import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import ts from 'typescript';

const source = readFileSync(new URL('../src/features/change-analysis/ChangeAnalysisWorkspace.tsx', import.meta.url), 'utf8');
const apiSource = readFileSync(new URL('../src/lib/api.ts', import.meta.url), 'utf8');
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

function fixture({ telemetry = async () => ({ ready: true }) } = {}) {
  const state = { report: null, telemetry: null, error: null, availability: {} };
  const generation = { current: 1 };
  const timers = new Map();
  const signals = [];
  let nextTimer = 0;
  const load = new Function(
    'fetchChangeAnalysisImpacts', 'fetchChangeAnalysisReview', 'fetchChangeAnalysisReport',
    'fetchChangeAnalysisTelemetry', 'fetchChangeAnalysisDiff', 'fetchReviewPublication',
    'analysisGenerationRef', 'artifactLoadSequenceRef', 'publicationActionSequenceRef',
    'publicationPendingRef', 'setImpacts', 'setReviewFindings', 'setReport',
    'setTelemetry', 'setDiffDeltas', 'setPublication', 'setArtifactAvailability', 'setArtifactError',
    'setTimeout', 'clearTimeout',
    compiled + '\nreturn loadCompletedAnalysisData;',
  )(
    async () => [], async () => ({ findings: [] }), async () => ({ markdown_report: '# ready' }),
    (id, signal) => { signals.push(signal); return telemetry(id, signal); },
    async () => ({}), async () => { throw new Error('no optional publication'); },
    generation, { current: 0 }, { current: 0 }, { current: false },
    () => {}, () => {}, value => { state.report = value; },
    value => { state.telemetry = value; }, () => {}, () => {},
    updater => { state.availability = updater(state.availability); },
    value => { state.error = value; },
    (callback, delay) => {
      assert.equal(delay, 15_000);
      const id = ++nextTimer;
      timers.set(id, callback);
      return id;
    },
    id => timers.delete(id),
  );
  return {
    state, generation, signals, load,
    pendingTimers: () => timers.size,
    expire: () => {
      const pending = [...timers.values()];
      timers.clear();
      for (const callback of pending) callback();
    },
  };
}

const tick = () => new Promise(resolve => setImmediate(resolve));

test('stalled telemetry becomes a retryable error without hiding ready report', async () => {
  const stalled = deferred();
  let attempts = 0;
  const f = fixture({ telemetry: () => ++attempts === 1 ? stalled.promise : Promise.resolve({ ready: true }) });
  const first = f.load('analysis-A', 1);
  await tick();
  assert.equal(f.state.report?.markdown_report, '# ready');
  assert.equal(f.state.error, null);
  assert.equal(f.pendingTimers(), 1);

  f.expire();
  await first;
  assert.match(f.state.error, /unavailable artifacts: telemetry/);
  assert.equal(f.signals[0].aborted, true);
  assert.equal(f.state.availability.report, true);
  assert.equal(f.state.availability.telemetry, undefined);

  // A non-cooperative request may still settle later; it must not apply.
  stalled.resolve({ obsolete: true });
  await tick();
  assert.equal(f.state.telemetry, null);

  await f.load('analysis-A', 1);
  assert.deepEqual(f.state.telemetry, { ready: true });
  assert.equal(f.state.error, null);
  assert.equal(f.pendingTimers(), 0);
});

test('successful evidence requests clear their deadline timers', async () => {
  const f = fixture();
  await f.load('analysis-A', 1);
  assert.equal(f.state.error, null);
  assert.equal(f.state.availability.telemetry, true);
  assert.equal(f.pendingTimers(), 0);
  assert.equal(f.signals[0].aborted, false);
});

test('expired requests from obsolete analysis cannot report missing evidence', async () => {
  const stalled = deferred();
  const f = fixture({ telemetry: () => stalled.promise });
  const first = f.load('analysis-A', 1);
  await tick();
  f.generation.current = 2;
  f.expire();
  await first;
  assert.equal(f.state.error, null);
  assert.equal(f.state.telemetry, null);
  stalled.resolve({ obsolete: true });
  await tick();
  assert.equal(f.state.telemetry, null);
});

test('ordinary failed artifact requests clear timers and retain missing-evidence warning', async () => {
  const f = fixture({ telemetry: async () => { throw new Error('offline'); } });
  await f.load('analysis-A', 1);
  assert.match(f.state.error, /unavailable artifacts: telemetry/);
  assert.equal(f.pendingTimers(), 0);
  assert.equal(f.signals[0].aborted, false);
});

test('all five evidence endpoints forward cancellation to the network request', () => {
  for (const name of ['Diff', 'Impacts', 'Review', 'Report', 'Telemetry']) {
    const start = apiSource.indexOf('export async function fetchChangeAnalysis' + name + '(');
    const end = apiSource.indexOf('\n}', start);
    assert.ok(start >= 0 && end > start, 'missing API getter: ' + name);
    const getter = apiSource.slice(start, end);
    assert.match(getter, /signal\?: AbortSignal/);
    assert.match(getter, /cache: 'no-store',\s*signal,/);
    assert.match(source, new RegExp('withArtifactDeadline\\(\\(signal\\) => fetchChangeAnalysis' + name));
  }
});
