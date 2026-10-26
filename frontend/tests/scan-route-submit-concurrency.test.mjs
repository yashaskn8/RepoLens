import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import test from 'node:test';

// Extract and execute the actual active /scan route callback, without rendering React.
const root = dirname(dirname(fileURLToPath(import.meta.url)));
const source = readFileSync(join(root, 'src/app/scan/page.tsx'), 'utf8');
const start = source.indexOf('  const handleStartScan = async (e: React.FormEvent) => {');
const end = source.indexOf('\n  const isScanning', start);
assert.ok(start >= 0 && end > start, 'active scan submit callback must exist');
const body = source.slice(start, end)
  .replaceAll('e: React.FormEvent', 'e')
  .replaceAll('err: unknown', 'err');
const makeHandler = new Function(
  'repoUrl', 'isAuthenticated', 'scanRequestGeneration', 'setError', 'setIsSubmitting',
  'startScan', 'branch', 'setActiveScan', 'setRecentScans', 'window', 'Event',
  'isAuthLoading', 'isHydrated', 'isScanning', 'scanSubmissionPendingRef',
  `${body}; return handleStartScan;`,
);

function fixture({ authenticated = true, authLoading = false, hydrated = true, scanning = false } = {}) {
  const scanRequestGeneration = { current: 0 };
  const scanSubmissionPendingRef = { current: false };
  const requests = [];
  const deferred = [];
  const errors = [];
  const submitting = [];
  const active = [];
  const events = [];
  let recent = [];
  const make = () => makeHandler(
    'https://github.com/fastapi/fastapi', authenticated, scanRequestGeneration,
    (error) => errors.push(error), (busy) => submitting.push(busy),
    (request) => {
      requests.push(request);
      return new Promise((resolve, reject) => deferred.push({ resolve, reject }));
    },
    'main', (scan) => active.push(scan),
    (updater) => { recent = updater(recent); },
    { dispatchEvent: (event) => events.push(event.type) },
    class Event { constructor(type) { this.type = type; } },
    authLoading, hydrated, scanning, scanSubmissionPendingRef,
  );
  const submit = (handler = make()) => handler({ preventDefault() {} });
  return { make, submit, requests, deferred, errors, submitting, active, events,
    scanRequestGeneration, scanSubmissionPendingRef, get recent() { return recent; } };
}

test('same-render duplicate clicks enqueue one scan only', async () => {
  const f = fixture();
  const handler = f.make();
  const first = f.submit(handler);
  const second = f.submit(handler);
  assert.equal(f.requests.length, 1);
  assert.equal(f.scanRequestGeneration.current, 1);
  f.deferred[0].resolve({ id: 'scan-1', status: 'PENDING' });
  await Promise.all([first, second]);
  assert.deepEqual(f.active.at(-1), { id: 'scan-1', status: 'PENDING' });
  assert.equal(f.scanSubmissionPendingRef.current, true);
});

test('pending scan remains locked even before a React rerender', async () => {
  const f = fixture();
  const handler = f.make();
  const first = f.submit(handler);
  f.deferred[0].resolve({ id: 'scan-1', status: 'RUNNING' });
  await first;
  await f.submit(handler);
  assert.equal(f.requests.length, 1);
});

test('terminal result unlocks another scan submission', async () => {
  const f = fixture();
  const handler = f.make();
  const first = f.submit(handler);
  f.deferred[0].resolve({ id: 'scan-1', status: 'COMPLETED' });
  await first;
  assert.equal(f.scanSubmissionPendingRef.current, false);
  const second = f.submit(handler);
  assert.equal(f.requests.length, 2);
  f.deferred[1].resolve({ id: 'scan-2', status: 'PENDING' });
  await second;
  assert.match(source, /if \(!isScanning\) scanSubmissionPendingRef\.current = false/);
});

test('failed initiation unlocks retry and reports the error', async () => {
  const f = fixture();
  const handler = f.make();
  const first = f.submit(handler);
  f.deferred[0].reject(new Error('network down'));
  await first;
  assert.equal(f.scanSubmissionPendingRef.current, false);
  assert.equal(f.errors.at(-1), 'network down');
  const retry = f.submit(handler);
  assert.equal(f.requests.length, 2);
  f.deferred[1].resolve({ id: 'scan-2', status: 'PENDING' });
  await retry;
});

test('logged-out submission opens sign-in rather than starting scan', async () => {
  const f = fixture({ authenticated: false });
  await f.submit();
  assert.deepEqual(f.events, ['repolens:open-auth']);
  assert.equal(f.requests.length, 0);
});

test('auth restoration, hydration and running scan all prevent starts', async () => {
  for (const options of [{ authLoading: true }, { hydrated: false }, { scanning: true }]) {
    const f = fixture(options);
    await f.submit();
    assert.equal(f.requests.length, 0);
  }
});

test('stale request from old account cannot release newer account lock', async () => {
  const f = fixture();
  const old = f.submit();
  // Auth effect invalidates the old generation and releases its lock.
  f.scanRequestGeneration.current += 1;
  f.scanSubmissionPendingRef.current = false;
  const newer = f.submit();
  assert.equal(f.requests.length, 2);
  f.deferred[0].resolve({ id: 'old-tenant-scan', status: 'PENDING' });
  await old;
  assert.equal(f.scanSubmissionPendingRef.current, true);
  assert.equal(f.active.length, 0);
  f.deferred[1].resolve({ id: 'new-tenant-scan', status: 'PENDING' });
  await newer;
  assert.equal(f.active.at(-1).id, 'new-tenant-scan');
  assert.match(source, /scanRequestGeneration\.current \+= 1;\s+scanSubmissionPendingRef\.current = false/);
});
