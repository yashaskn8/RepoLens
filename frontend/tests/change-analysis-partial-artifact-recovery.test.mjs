import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import ts from 'typescript';

const source = readFileSync(new URL('../src/features/change-analysis/ChangeAnalysisWorkspace.tsx', import.meta.url), 'utf8');
const start = source.indexOf('  const loadCompletedAnalysisData = async');
const end = source.indexOf('  const retryCompletedArtifacts =', start);
assert.ok(start >= 0 && end > start, 'completed-analysis loader must exist');
const compiled = ts.transpileModule(source.slice(start, end), {
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.None },
}).outputText;

function deferred() {
  let resolve;
  const promise = new Promise(done => { resolve = done; });
  return { promise, resolve };
}

function fixture({ telemetry, report } = {}) {
  const state = { report: null, impacts: null, telemetry: null, availability: {}, error: null };
  const generation = { current: 1 };
  const loadSequence = { current: 0 };
  const load = new Function(
    'fetchChangeAnalysisImpacts', 'fetchChangeAnalysisReview', 'fetchChangeAnalysisReport',
    'fetchChangeAnalysisTelemetry', 'fetchChangeAnalysisDiff', 'fetchReviewPublication',
    'analysisGenerationRef', 'artifactLoadSequenceRef', 'publicationActionSequenceRef',
    'publicationPendingRef', 'setImpacts', 'setReviewFindings', 'setReport',
    'setTelemetry', 'setDiffDeltas', 'setPublication', 'setArtifactAvailability', 'setArtifactError',
    compiled + '\nreturn loadCompletedAnalysisData;',
  )(
    async () => [{ id: 'impact-1' }], async () => ({ findings: [] }),
    report || (async () => ({ markdown_report: '# ready' })),
    telemetry || (async () => ({})),
    async () => ({}), async () => { throw new Error('no publication'); },
    generation, loadSequence, { current: 0 }, { current: false },
    value => { state.impacts = value; }, () => {},
    value => { state.report = value; }, value => { state.telemetry = value; },
    () => {}, () => {},
    updater => { state.availability = updater(state.availability); },
    value => { state.error = value; },
  );
  return { state, generation, load };
}

test('stalled telemetry cannot hide completed report and impacts', async () => {
  const stalled = deferred();
  const f = fixture({ telemetry: () => stalled.promise });
  const loading = f.load('analysis-A', 1);
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(f.state.report?.markdown_report, '# ready');
  assert.deepEqual(f.state.impacts, [{ id: 'impact-1' }]);
  assert.equal(f.state.availability.report, true);
  assert.equal(f.state.availability.impacts, true);
  assert.notEqual(f.state.availability.telemetry, true);
  // Release the simulated stalled request so the deadline timer is cleared.
  stalled.resolve({});
  await loading;
});

test('failed telemetry still reports missing evidence without hiding successful artifacts', async () => {
  const f = fixture({ telemetry: async () => { throw new Error('telemetry unavailable'); } });
  await f.load('analysis-A', 1);
  assert.equal(f.state.report?.markdown_report, '# ready');
  assert.match(f.state.error, /unavailable artifacts: telemetry/);
  assert.equal(f.state.availability.telemetry, undefined);
});

test('late artifact completion from an obsolete analysis cannot reveal old report', async () => {
  const pending = deferred();
  const f = fixture({ report: () => pending.promise });
  const loading = f.load('analysis-A', 1);
  f.generation.current = 2;
  pending.resolve({ markdown_report: 'private obsolete report' });
  await loading;
  assert.equal(f.state.report, null);
  assert.equal(f.state.availability.report, undefined);
});
