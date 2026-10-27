import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import ts from 'typescript';

const source = readFileSync(new URL('../src/features/change-analysis/ChangeAnalysisWorkspace.tsx', import.meta.url), 'utf8');
const start = source.indexOf('  const loadCompletedAnalysisData = async');
const end = source.indexOf('  const retryCompletedArtifacts =', start);
assert.ok(start >= 0 && end > start, 'completed-analysis artifact loader must exist');
const compiled = ts.transpileModule(source.slice(start, end), {
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.None },
}).outputText;

function deferred() {
  let resolve;
  const promise = new Promise(done => { resolve = done; });
  return { promise, resolve };
}

function fixture() {
  const firstReport = deferred();
  const firstImpacts = deferred();
  let reportRequests = 0;
  let impactRequests = 0;
  const state = { report: null, impacts: null, error: null, availability: {} };
  const analysisGenerationRef = { current: 1 };
  const artifactLoadSequenceRef = { current: 0 };
  const publicationActionSequenceRef = { current: 0 };
  const publicationPendingRef = { current: false };
  const load = new Function(
    'fetchChangeAnalysisImpacts', 'fetchChangeAnalysisReview', 'fetchChangeAnalysisReport',
    'fetchChangeAnalysisTelemetry', 'fetchChangeAnalysisDiff', 'fetchReviewPublication',
    'analysisGenerationRef', 'artifactLoadSequenceRef',
    'publicationActionSequenceRef', 'publicationPendingRef',
    'setImpacts', 'setReviewFindings', 'setReport', 'setTelemetry', 'setDiffDeltas',
    'setPublication', 'setArtifactAvailability', 'setArtifactError',
    compiled + '\nreturn loadCompletedAnalysisData;',
  )(
    async () => ++impactRequests === 1 ? firstImpacts.promise : [{ id: 'new-impact' }],
    async () => ({ findings: [] }),
    async () => ++reportRequests === 1 ? firstReport.promise : { markdown_report: 'new-report' },
    async () => ({}),
    async () => ({}),
    async () => null,
    analysisGenerationRef, artifactLoadSequenceRef,
    publicationActionSequenceRef, publicationPendingRef,
    value => { state.impacts = value; },
    () => {},
    value => { state.report = value; },
    () => {}, () => {}, () => {},
    updater => { state.availability = updater(state.availability); },
    value => { state.error = value; },
  );
  return { state, load, firstReport, firstImpacts, analysisGenerationRef };
}

test('late older artifact load cannot replace a newer completed report or impacts', async () => {
  const f = fixture();
  const older = f.load('analysis-A', 1);
  const newer = f.load('analysis-A', 1);
  await newer;
  assert.equal(f.state.report.markdown_report, 'new-report');
  assert.deepEqual(f.state.impacts, [{ id: 'new-impact' }]);
  f.firstReport.resolve({ markdown_report: 'old-report' });
  f.firstImpacts.resolve([{ id: 'old-impact' }]);
  await older;
  assert.equal(f.state.report.markdown_report, 'new-report');
  assert.deepEqual(f.state.impacts, [{ id: 'new-impact' }]);
  assert.equal(f.state.error, null);
});

test('artifact responses from an invalidated analysis generation are ignored', async () => {
  const f = fixture();
  const pending = f.load('analysis-A', 1);
  f.analysisGenerationRef.current = 2;
  f.firstReport.resolve({ markdown_report: 'private-old-report' });
  f.firstImpacts.resolve([{ id: 'old-impact' }]);
  await pending;
  assert.equal(f.state.report, null);
  assert.equal(f.state.impacts, null);
  assert.deepEqual(f.state.availability, {});
});
