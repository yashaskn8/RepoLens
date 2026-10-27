import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import ts from 'typescript';

const source = readFileSync(new URL('../src/features/change-analysis/ChangeAnalysisWorkspace.tsx', import.meta.url), 'utf8');
const start = source.indexOf('  const loadCompletedAnalysisData = async');
const end = source.indexOf('  const retryCompletedArtifacts =', start);
assert.ok(start >= 0 && end > start, 'artifact loader must exist');
const compiled = ts.transpileModule(source.slice(start, end), {
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.None },
}).outputText;

function deferred() {
  let resolve;
  const promise = new Promise(done => { resolve = done; });
  return { promise, resolve };
}

function fixture() {
  const persistedPublication = deferred();
  const state = { publication: null, error: null, availability: {} };
  const analysisGenerationRef = { current: 1 };
  const artifactLoadSequenceRef = { current: 0 };
  const publicationActionSequenceRef = { current: 0 };
  const publicationPendingRef = { current: false };
  const load = new Function(
    'fetchChangeAnalysisImpacts', 'fetchChangeAnalysisReview', 'fetchChangeAnalysisReport',
    'fetchChangeAnalysisTelemetry', 'fetchChangeAnalysisDiff', 'fetchReviewPublication',
    'analysisGenerationRef', 'artifactLoadSequenceRef', 'publicationActionSequenceRef',
    'publicationPendingRef', 'setImpacts', 'setReviewFindings', 'setReport',
    'setTelemetry', 'setDiffDeltas', 'setPublication', 'setArtifactAvailability', 'setArtifactError',
    compiled + '\nreturn loadCompletedAnalysisData;',
  )(
    async () => [], async () => ({ findings: [] }), async () => ({ markdown_report: '# report' }),
    async () => ({}), async () => ({}), () => persistedPublication.promise,
    analysisGenerationRef, artifactLoadSequenceRef, publicationActionSequenceRef,
    publicationPendingRef, () => {}, () => {}, () => {}, () => {}, () => {},
    value => { state.publication = value; },
    updater => { state.availability = updater(state.availability); },
    value => { state.error = value; },
  );
  return { load, state, persistedPublication, publicationActionSequenceRef, publicationPendingRef };
}

test('persisted publication loads normally without an intervening operator action', async () => {
  const f = fixture();
  const loading = f.load('analysis-A', 1);
  f.persistedPublication.resolve({ preview_digest: 'persisted' });
  await loading;
  assert.equal(f.state.publication.preview_digest, 'persisted');
  assert.equal(f.state.error, null);
});

test('delayed persisted publication cannot overwrite a newer generated preview', async () => {
  const f = fixture();
  const loading = f.load('analysis-A', 1);
  f.publicationActionSequenceRef.current += 1;
  f.publicationPendingRef.current = true;
  f.state.publication = { preview_digest: 'new-preview' };
  f.publicationPendingRef.current = false;
  f.publicationActionSequenceRef.current += 1;
  f.persistedPublication.resolve({ preview_digest: 'old-preview' });
  await loading;
  assert.equal(f.state.publication.preview_digest, 'new-preview');
});

test('persisted publication cannot replace an in-flight operator action', async () => {
  const f = fixture();
  const loading = f.load('analysis-A', 1);
  f.publicationPendingRef.current = true;
  f.persistedPublication.resolve({ preview_digest: 'stale' });
  await loading;
  assert.equal(f.state.publication, null);
});

test('artifact loading started during approval cannot overwrite the approved result', async () => {
  const f = fixture();
  f.publicationPendingRef.current = true;
  f.publicationActionSequenceRef.current += 1;
  const loading = f.load('analysis-A', 1);
  f.state.publication = { preview_digest: 'approved', status: 'APPROVED' };
  f.publicationPendingRef.current = false;
  f.publicationActionSequenceRef.current += 1;
  f.persistedPublication.resolve({ preview_digest: 'unapproved', status: 'PREVIEW' });
  await loading;
  assert.equal(f.state.publication.status, 'APPROVED');
});

test('all three operator actions invalidate publication artifact loads', () => {
  for (const marker of ['setIsGeneratingPreview(true)', 'setIsApprovingPub(true)', 'setIsPublishingPub(true)']) {
    const i = source.indexOf(marker);
    assert.ok(i >= 0, 'missing publication operator action');
    assert.match(source.slice(Math.max(0, i - 100), i), /publicationActionSequenceRef\.current \+= 1/);
  }
});
