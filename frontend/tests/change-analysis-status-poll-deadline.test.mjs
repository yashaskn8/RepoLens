import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import ts from 'typescript';

const source = readFileSync(new URL('../src/features/change-analysis/ChangeAnalysisWorkspace.tsx', import.meta.url), 'utf8');
const apiSource = readFileSync(new URL('../src/lib/api.ts', import.meta.url), 'utf8');
const start = source.indexOf('  useEffect(() => {', source.indexOf('// Fetch one analysis identity'));
const end = source.indexOf('  const loadCompletedAnalysisData =', start);
assert.ok(start >= 0 && end > start, 'analysis status polling effect must exist');
const compiled = ts.transpileModule(source.slice(start, end), {
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.None },
}).outputText;

const tick = () => new Promise(resolve => setImmediate(resolve));
const deferred = () => {
  let resolve;
  const promise = new Promise(done => { resolve = done; });
  return { promise, resolve };
};

function fixture(fetchStatus) {
  const generation = { current: 1 };
  const state = { current: { id: 'analysis-A', status: 'PENDING' } };
  const calls = [];
  const timers = new Map();
  let nextTimer = 0;
  let cleanup;
  let loads = 0;
  let updates = 0;
  new Function(
    'useEffect', 'activeAnalysis', 'analysisGenerationRef', 'fetchChangeAnalysis',
    'setActiveAnalysis', 'loadCompletedAnalysisData', 'setTimeout', 'clearTimeout', 'console',
    compiled,
  )(
    callback => { cleanup = callback(); },
    state.current, generation,
    (id, signal) => { calls.push({ id, signal }); return fetchStatus(id, signal); },
    updater => { state.current = updater(state.current); updates += 1; },
    async () => { loads += 1; },
    (callback, delay) => { const id = ++nextTimer; timers.set(id, { callback, delay }); return id; },
    id => timers.delete(id),
    { error() {} },
  );
  return {
    calls, state, generation, cleanup,
    get loads() { return loads; },
    get updates() { return updates; },
    pending: delay => [...timers.values()].filter(timer => timer.delay === delay).length,
    fire: delay => {
      const item = [...timers.entries()].find(([, timer]) => timer.delay === delay);
      assert.ok(item, 'expected timer for ' + delay);
      timers.delete(item[0]);
      item[1].callback();
    },
  };
}

test('a stalled status request aborts and schedules a fresh poll', async () => {
  const stalled = deferred();
  let attempt = 0;
  const f = fixture(() => ++attempt === 1 ? stalled.promise : Promise.resolve({ id: 'analysis-A', status: 'COMPLETED' }));
  await tick();
  assert.equal(f.pending(15_000), 1);
  assert.equal(f.pending(2_000), 0);
  f.fire(15_000);
  await tick();
  assert.equal(f.calls[0].signal.aborted, true);
  assert.equal(f.pending(2_000), 1);
  f.fire(2_000);
  await tick();
  assert.equal(f.calls.length, 2);
  assert.equal(f.state.current.status, 'COMPLETED');
  assert.equal(f.loads, 1);
  assert.equal(f.pending(15_000), 0);
  assert.equal(f.pending(2_000), 0);
  stalled.resolve({ id: 'analysis-A', status: 'FAILED' });
  await tick();
  assert.equal(f.state.current.status, 'COMPLETED', 'late timed-out result must not overwrite current state');
  f.cleanup();
});

test('unmount aborts the in-flight request and ignores late responses', async () => {
  const stalled = deferred();
  const f = fixture(() => stalled.promise);
  await tick();
  f.cleanup();
  assert.equal(f.calls[0].signal.aborted, true);
  stalled.resolve({ id: 'analysis-A', status: 'COMPLETED' });
  await tick();
  assert.equal(f.updates, 0);
  assert.equal(f.loads, 0);
  assert.equal(f.pending(2_000), 0);
});

test('ordinary status network errors continue polling without concurrent requests', async () => {
  let attempt = 0;
  const f = fixture(() => ++attempt === 1 ? Promise.reject(new Error('offline')) : Promise.resolve({ id: 'analysis-A', status: 'FAILED' }));
  await tick();
  assert.equal(f.pending(15_000), 0);
  assert.equal(f.pending(2_000), 1);
  f.fire(2_000);
  await tick();
  assert.equal(f.calls.length, 2);
  assert.equal(f.state.current.status, 'FAILED');
  assert.equal(f.pending(2_000), 0);
  f.cleanup();
});

test('read-only analysis status getter forwards AbortSignal to apiFetch', () => {
  const start = apiSource.indexOf('export async function fetchChangeAnalysis(');
  const end = apiSource.indexOf('export async function fetchChangeAnalysisDiff(', start);
  assert.ok(start >= 0 && end > start);
  const getter = apiSource.slice(start, end);
  assert.match(getter, /signal\\?: AbortSignal/);
  assert.match(getter, /cache: 'no-store',\\s*signal,/);
  assert.match(source, /fetchChangeAnalysis\\(analysisId, controller.signal\\)/);
});
