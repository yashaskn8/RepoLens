import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const source = readFileSync(join(root, 'src/app/dashboard/page.tsx'), 'utf8');
const start = source.indexOf('  // Private dashboard summaries');
const end = source.indexOf('\n  return (', start);
assert.ok(start >= 0 && end > start, 'Dashboard account-scoped effect must exist');
const privateLogic = source.slice(start, end).replace(
  /const visibleChangeAnalyses = .*?;\n  const visibleRecentScans = .*?;\n  const displayLoading = .*?;/s,
  '',
);

function deferred() {
  let resolve;
  const promise = new Promise((yes) => { resolve = yes; });
  return { promise, resolve };
}

function mount(accountId, authLoading, responses) {
  const state = { changes: [], scans: [], loadedForAccount: null, loading: false };
  const generation = { current: 0 };
  const effects = [];
  const ctx = {
    accountId, authLoading, requestGeneration: generation,
    setChangeAnalyses: v => { state.changes = v; },
    setRecentScans: v => { state.scans = v; },
    setLoadedForAccount: v => { state.loadedForAccount = v; },
    setIsLoading: v => { state.loading = v; },
    listChangeAnalyses: () => responses.changes(),
    listScans: () => responses.scans(),
    useEffect: (callback, deps) => { effects.push({ callback, deps }); },
  };
  const render = new Function('ctx', [
    'const { accountId, authLoading, requestGeneration,',
    ' setChangeAnalyses, setRecentScans, setLoadedForAccount, setIsLoading,',
    ' listChangeAnalyses, listScans, useEffect } = ctx;',
    privateLogic,
  ].join('\n'));
  render(ctx);
  const cleanup = effects[0].callback();
  return { state, generation, cleanup };
}

async function settle() {
  for (let i = 0; i < 12; i += 1) await Promise.resolve();
}

test('signed-out dashboard never requests private tenant summaries', async () => {
  let calls = 0;
  const api = { changes: () => { calls += 1; return Promise.resolve([]); }, scans: () => { calls += 1; return Promise.resolve([]); } };
  const app = mount(null, false, api);
  await settle();
  assert.equal(calls, 0);
  assert.deepEqual(app.state.changes, []);
  assert.deepEqual(app.state.scans, []);
  app.cleanup();
});

test('account switch invalidates stale private API responses', async () => {
  const changes = deferred();
  const scans = deferred();
  const app = mount('tenant-A', false, { changes: () => changes.promise, scans: () => scans.promise });
  app.cleanup();
  changes.resolve([{ id: 'tenant-A-change' }]);
  scans.resolve([{ id: 'tenant-A-scan' }]);
  await settle();
  assert.deepEqual(app.state.changes, []);
  assert.deepEqual(app.state.scans, []);
  assert.equal(app.state.loadedForAccount, null);
});

test('successful authenticated response is associated with its account', async () => {
  const app = mount('tenant-B', false, {
    changes: () => Promise.resolve([{ id: 'tenant-B-change' }]),
    scans: () => Promise.resolve([{ id: 'tenant-B-scan' }]),
  });
  await settle();
  assert.equal(app.state.loadedForAccount, 'tenant-B');
  assert.deepEqual(app.state.changes, [{ id: 'tenant-B-change' }]);
  assert.deepEqual(app.state.scans, [{ id: 'tenant-B-scan' }]);
  app.cleanup();
});

test('private dashboard render uses account-masked summaries', () => {
  assert.match(source, /loadedForAccount === accountId \? changeAnalyses : \[\]/);
  assert.match(source, /loadedForAccount === accountId \? recentScans : \[\]/);
  assert.match(source, /value=\{visibleChangeAnalyses\.length\}/);
  assert.match(source, /value=\{visibleRecentScans\.reduce/);
  assert.match(source, /\{visibleChangeAnalyses\.map/);
  assert.match(source, /\{displayLoading \? \(/);
});
