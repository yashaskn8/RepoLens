import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import test from 'node:test';

// Exercise the actual component callback, not a rewritten pagination algorithm.
const root = dirname(dirname(fileURLToPath(import.meta.url)));
const source = readFileSync(join(root, 'src/app/findings/page.tsx'), 'utf8');
const startMarker = '  const loadOlderScans = useCallback(async () => {';
const start = source.indexOf(startMarker);
const end = source.indexOf('  }, [accountId', start);
assert.ok(start >= 0 && end > start, 'older-scan callback must exist');
const body = source.slice(start + startMarker.length, end).replaceAll('caught: unknown', 'caught');
const makeHandler = new Function(
  'olderPagePending', 'failedFindingsRetryPending', 'authLoading', 'accountId', 'loadedForAccount',
  'loading', 'loadingMore', 'hasOlderScans', 'requestGeneration',
  'setLoadingMore', 'loadScanFindingsPage', 'loadedScanCount', 'SCAN_PAGE_SIZE',
  'listScans', 'fetchScanFindings', 'isCurrentAccountResponse', 'user',
  'setFindings', 'setLoadedScanCount', 'setHasOlderScans', 'setFailedScanIds', 'setError',
  `return async function loadOlderScans() {${body}}`,
);

function fixture() {
  const olderPagePending = { current: false };
  const failedFindingsRetryPending = { current: false };
  const requestGeneration = { current: 1 };
  const calls = [];
  const deferred = [];
  const errors = [];
  let loadedCount = 25;
  let findings = [];
  const make = () => makeHandler(
    olderPagePending, failedFindingsRetryPending, false, 'tenant-A', 'tenant-A', false, false, true,
    requestGeneration, () => {},
    async (offset) => {
      calls.push(offset);
      return new Promise((resolve, reject) => deferred.push({ resolve, reject }));
    },
    loadedCount, 25, () => {}, () => {},
    (requested, current, generation, active) =>
      requested === current && generation === active,
    { id: 'tenant-A' },
    (updater) => { findings = updater(findings); },
    (updater) => { loadedCount = updater(loadedCount); },
    () => {},
    () => {},
    (updater) => { errors.push(typeof updater === 'function' ? updater(null) : updater); },
  );
  return { make, calls, deferred, errors, olderPagePending, requestGeneration,
    get loadedCount() { return loadedCount; }, get findings() { return findings; } };
}

test('two same-tick older-page clicks fetch one page and advance the offset once', async () => {
  const f = fixture();
  const load = f.make();
  const first = load();
  const second = load();
  assert.deepEqual(f.calls, [25]);
  f.deferred[0].resolve({ findings: [{ id: 'one' }], scanCount: 25, hasOlderScans: true, failedScanIds: [], failedCount: 0 });
  await Promise.all([first, second]);
  assert.equal(f.loadedCount, 50);
  assert.deepEqual(f.findings, [{ id: 'one' }]);
  assert.equal(f.olderPagePending.current, false);
});

test('a failed page request releases the lock for a subsequent retry', async () => {
  const f = fixture();
  const load = f.make();
  const first = load();
  f.deferred[0].reject(new Error('network unavailable'));
  await first;
  assert.equal(f.olderPagePending.current, false);
  assert.match(f.errors[0], /network unavailable/);
  const retry = load();
  assert.deepEqual(f.calls, [25, 25]);
  f.deferred[1].resolve({ findings: [], scanCount: 0, hasOlderScans: false, failedScanIds: [], failedCount: 0 });
  await retry;
});

test('stale page completion cannot unlock a newer account-generation request', async () => {
  const f = fixture();
  const old = f.make()();
  f.requestGeneration.current += 1;
  f.olderPagePending.current = false; // account change or explicit refresh
  const loadNew = f.make();
  const newer = loadNew();
  f.deferred[0].resolve({ findings: [], scanCount: 25, hasOlderScans: true, failedScanIds: [], failedCount: 0 });
  await old;
  assert.equal(f.olderPagePending.current, true);
  await loadNew(); // must not fetch the same newer page again
  assert.deepEqual(f.calls, [25, 25]);
  f.deferred[1].resolve({ findings: [], scanCount: 25, hasOlderScans: true, failedScanIds: [], failedCount: 0 });
  await newer;
  assert.equal(f.olderPagePending.current, false);
});

test('account reset and refresh invalidate the older-page lock', () => {
  assert.match(source, /const generation = \+\+requestGeneration\.current;\s+olderPagePending\.current = false/);
  assert.match(source, /requestGeneration\.current \+= 1;\s+olderPagePending\.current = false/);
});
