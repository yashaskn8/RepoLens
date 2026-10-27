import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import ts from 'typescript';

const source = readFileSync(new URL('../src/features/change-analysis/ChangeAnalysisWorkspace.tsx', import.meta.url), 'utf8');
const start = source.indexOf('  const loadCompletedAnalysisData = async');
const end = source.indexOf('  const retryCompletedArtifacts =', start);
assert.ok(start >= 0 && end > start);
const compiled = ts.transpileModule(source.slice(start, end), {
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.None },
}).outputText;

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}

function fixture() {
  const publication = deferred();
  const state = { report: null, publication: null, error: null };
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
    async () => [], async () => ({ findings: [] }),
    async () => ({ markdown_report: '# ready' }), async () => ({}), async () => ({}),
    () => publication.promise,
    analysisGenerationRef, artifactLoadSequenceRef, publicationActionSequenceRef, publicationPendingRef,
    () => {}, () => {}, value => { state.report = value; },
    () => {}, () => {}, value => { state.publication = value; }, () => {},
    value => { state.error = value; },
  );
  return { load, publication, state, analysisGenerationRef, publicationActionSequenceRef };
}

test('optional publication fetch cannot block mandatory report recovery', async () => {
  const f = fixture();
  const result = await Promise.race([
    f.load('analysis-A', 1).then(() => 'completed'),
    new Promise(resolve => setTimeout(() => resolve('blocked'), 100)),
  ]);
  assert.equal(result, 'completed', 'required artifacts must not wait for optional publication');
  assert.equal(f.state.report.markdown_report, '# ready');
  assert.equal(f.state.error, null);
  f.publication.resolve({ preview_digest: 'saved' });
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(f.state.publication.preview_digest, 'saved');
});

test('late optional publication from an obsolete generation is ignored', async () => {
  const f = fixture();
  await f.load('analysis-A', 1);
  f.analysisGenerationRef.current = 2;
  f.publication.resolve({ preview_digest: 'obsolete' });
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(f.state.publication, null);
});

test('optional publication failures do not invalidate available report evidence', async () => {
  const f = fixture();
  await f.load('analysis-A', 1);
  f.publication.reject(new Error('no preview exists'));
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(f.state.report.markdown_report, '# ready');
  assert.equal(f.state.error, null);
});
