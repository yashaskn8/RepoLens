import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import test from 'node:test';
import ts from 'typescript';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const source = readFileSync(join(root, 'src/app/changes/[id]/page.tsx'), 'utf8');
const start = source.indexOf('  useEffect(() => {\n    let cancelled = false;');
const end = source.indexOf('  const retryMissingArtifacts =', start);
assert.ok(start >= 0 && end > start, 'active change-detail status effect exists');
const effect = ts.transpileModule(source.slice(start, end), {
  compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
}).outputText;

class ApiError extends Error {
  constructor(status) {
    super('Untrusted server response text');
    this.status = status;
  }
}

async function flush() {
  await new Promise(resolve => setImmediate(resolve));
}

function mount({ responses, retryToken = 0 } = {}) {
  const state = {
    analysis: { id: 'previous' },
    diff: { changed_files: [{ file_path: 'secret.ts' }] },
    impacts: [{ title: 'secret' }],
    impactsLoaded: true,
    review: { summary: 'secret' },
    publication: { status: 'APPROVED' },
    selectedFile: 'secret.ts',
    missingArtifacts: ['review evidence'],
    confirmedPublish: true,
    analysisLoadError: null,
    loading: null,
    requests: 0,
    timers: [],
    artifactsRequested: 0,
  };
  const actionGeneration = { current: 5 };
  const publicationReadSequenceRef = { current: 7 };
  const retryPendingRef = { current: true };
  const sequence = [...responses];
  let cleanup;
  const dependencies = {
    useEffect: callback => { cleanup = callback(); },
    analysisId: 'analysis-1',
    artifactRetryToken: retryToken,
    actionGeneration,
    publicationReadSequenceRef,
    retryPendingRef,
    ApiError,
    setAnalysis: value => { state.analysis = value; },
    setDiff: value => { state.diff = value; },
    setImpacts: value => { state.impacts = value; },
    setImpactsLoaded: value => { state.impactsLoaded = value; },
    setReview: value => { state.review = value; },
    setPublication: value => { state.publication = value; },
    setSelectedFile: value => { state.selectedFile = value; },
    setMissingArtifacts: value => { state.missingArtifacts = value; },
    setConfirmedPublish: value => { state.confirmedPublish = value; },
    setAnalysisLoadError: value => { state.analysisLoadError = value; },
    setIsLoading: value => { state.loading = value; },
    withChangeDetailDeadline: request => request({}),
    fetchChangeAnalysis: async () => {
      state.requests++;
      const result = sequence.shift();
      if (result instanceof Error) throw result;
      return result;
    },
    fetchChangeAnalysisDiff: async () => { state.artifactsRequested++; return { changed_files: [] }; },
    fetchChangeAnalysisImpacts: async () => { state.artifactsRequested++; return []; },
    fetchChangeAnalysisReview: async () => { state.artifactsRequested++; return { findings: [] }; },
    fetchReviewPublication: async () => ({ status: 'PREVIEW_READY' }),
    setTimeout: callback => { state.timers.push(callback); return state.timers.length; },
    clearTimeout: () => {},
  };
  new Function(...Object.keys(dependencies), effect)(...Object.values(dependencies));
  return { state, actionGeneration, publicationReadSequenceRef, cleanup: () => cleanup?.() };
}

for (const status of [401, 403, 404]) {
  test(`HTTP ${status} stops polling and clears previously loaded sensitive evidence`, async () => {
    const ctx = mount({ responses: [new ApiError(status)], retryToken: 1 });
    await flush();
    const { state } = ctx;
    assert.equal(state.requests, 1);
    assert.equal(state.timers.length, 0, 'permanent failures must not poll forever');
    assert.equal(state.analysis, null);
    assert.equal(state.diff, null);
    assert.deepEqual(state.impacts, []);
    assert.equal(state.impactsLoaded, false);
    assert.equal(state.review, null);
    assert.equal(state.publication, null);
    assert.equal(state.selectedFile, null);
    assert.deepEqual(state.missingArtifacts, []);
    assert.equal(state.confirmedPublish, false);
    assert.equal(state.artifactsRequested, 0);
    assert.equal(state.loading, false);
    assert.equal(ctx.actionGeneration.current, 6);
    assert.equal(ctx.publicationReadSequenceRef.current, 8);
    assert.doesNotMatch(state.analysisLoadError, /Untrusted server response text/);
    ctx.cleanup();
  });
}

test('transient backend failure reports retry and clears warning after recovery', async () => {
  const ctx = mount({ responses: [new ApiError(503), { status: 'COMPLETED' }] });
  await flush();
  assert.match(ctx.state.analysisLoadError, /Retrying automatically/);
  assert.equal(ctx.state.timers.length, 1);
  assert.equal(ctx.state.artifactsRequested, 0);
  ctx.state.timers.shift()();
  await flush();
  assert.equal(ctx.state.analysis.status, 'COMPLETED');
  assert.equal(ctx.state.analysisLoadError, null);
  assert.equal(ctx.state.artifactsRequested, 3);
  assert.deepEqual(ctx.state.missingArtifacts, []);
  assert.equal(ctx.state.timers.length, 0);
  ctx.cleanup();
});

test('network error is retryable without retaining an invented clean result', async () => {
  const ctx = mount({ responses: [new Error('network timeout')] });
  await flush();
  assert.match(ctx.state.analysisLoadError, /Retrying automatically/);
  assert.equal(ctx.state.analysis, null);
  assert.equal(ctx.state.artifactsRequested, 0);
  assert.equal(ctx.state.timers.length, 1);
  ctx.cleanup();
});

test('status failures are visibly disclosed in the workspace', () => {
  assert.match(source, /\{analysisLoadError && \(/);
  assert.match(source, /role="alert"/);
  assert.match(source, /This analysis is unavailable or access was denied/);
});
