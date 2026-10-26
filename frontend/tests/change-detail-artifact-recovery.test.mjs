import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import test from 'node:test';
import ts from 'typescript';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const source = readFileSync(join(root, 'src/app/changes/[id]/page.tsx'), 'utf8');
const effectStart = source.indexOf('  useEffect(() => {\n    let cancelled = false;');
const retryStart = source.indexOf('  const retryMissingArtifacts =', effectStart);
const retryEnd = source.indexOf('  const handleGeneratePreview', retryStart);
assert.ok(effectStart >= 0 && retryStart > effectStart && retryEnd > retryStart);
const js = ts.transpileModule(source.slice(effectStart, retryStart), {
  compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
}).outputText;
const retryJs = ts.transpileModule(source.slice(retryStart, retryEnd), {
  compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
}).outputText;

async function load({ status = 'COMPLETED', failures = [], retryToken = 0 } = {}) {
  const state = { missing: null, loading: null, clearedAnalysis: false, artifactRequests: [] };
  const fetch = (name, value) => async () => {
    state.artifactRequests.push(name);
    if (failures.includes(name)) throw Error(name + ' unavailable');
    return value;
  };
  const noop = () => {};
  const retryPendingRef = { current: true };
  const dependencies = {
    useEffect: callback => { callback(); },
    analysisId: 'analysis-1',
    artifactRetryToken: retryToken,
    setAnalysis: value => { if (value === null) state.clearedAnalysis = true; else state.analysis = value; },
    setDiff: value => { state.diff = value; },
    setImpacts: value => { state.impacts = value; },
    setReview: value => { state.review = value; },
    setPublication: value => { state.publication = value; },
    setSelectedFile: noop,
    setMissingArtifacts: value => { state.missing = value; },
    setIsLoading: value => { state.loading = value; },
    retryPendingRef,
    fetchChangeAnalysis: async () => ({ status }),
    fetchChangeAnalysisDiff: fetch('diff', { changed_files: [] }),
    fetchChangeAnalysisImpacts: fetch('impacts', []),
    fetchChangeAnalysisReview: fetch('review', { findings: [] }),
    fetchReviewPublication: fetch('publication', { status: 'PREVIEW_READY' }),
    setTimeout: () => 0,
    clearTimeout: noop,
  };
  new Function(...Object.keys(dependencies), js)(...Object.values(dependencies));
  await new Promise(resolve => setImmediate(resolve));
  return { state, retryPendingRef };
}

test('failed required artifacts remain unknown and can be retried', async () => {
  const { state } = await load({ failures: ['diff', 'review', 'publication'] });
  assert.deepEqual(state.missing, ['structural diff', 'review evidence']);
  // Initial load clears stale evidence to null, which remains unverified (not empty).
  assert.equal(state.diff, null);
  assert.equal(state.review, null);
  assert.deepEqual(state.impacts, []);
  assert.equal(state.loading, false);
  assert.match(source, /Missing evidence does not mean zero findings/);
  assert.match(source, /onClick=\{retryMissingArtifacts\}/);
});

test('successful retry clears missing evidence without clearing existing analysis', async () => {
  const { state, retryPendingRef } = await load({ retryToken: 1, failures: ['publication'] });
  assert.deepEqual(state.missing, []);
  assert.equal(state.clearedAnalysis, false);
  assert.deepEqual(state.diff.changed_files, []);
  assert.equal(retryPendingRef.current, false);
});

test('failed analysis does not fetch nonexistent completed artifacts', async () => {
  const { state } = await load({ status: 'FAILED' });
  assert.deepEqual(state.artifactRequests, []);
  assert.equal(state.analysis.status, 'FAILED');
});

test('retry handler rejects duplicate requests and incomplete analyses', () => {
  const pending = { current: false };
  const tokens = [];
  const build = (analysis, missingArtifacts) => new Function(
    'analysis', 'missingArtifacts', 'retryPendingRef', 'setArtifactRetryToken',
    retryJs + '\nreturn retryMissingArtifacts;',
  )(analysis, missingArtifacts, pending, updater => tokens.push(updater(0)));
  build({ status: 'COMPLETED' }, ['structural diff'])();
  build({ status: 'COMPLETED' }, ['structural diff'])();
  assert.deepEqual(tokens, [1]);
  pending.current = false;
  build({ status: 'FAILED' }, ['structural diff'])();
  build({ status: 'COMPLETED' }, [])();
  assert.deepEqual(tokens, [1]);
});
