import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import test from 'node:test';

// Exercise the committed workspace submit callback rather than a copy of its logic.
const root = dirname(dirname(fileURLToPath(import.meta.url)));
const source = readFileSync(join(root, 'src/features/scan/RepositoryScanWorkspace.tsx'), 'utf8');
const start = source.indexOf('  const handleStartScan = async (e: React.FormEvent) => {');
const end = source.indexOf('\n  const isScanRunning', start);
assert.ok(start >= 0 && end > start, 'scan submit callback must exist');
const body = source.slice(start, end)
  .replaceAll('e: React.FormEvent', 'e')
  .replaceAll('err: unknown', 'err');
const makeHandler = new Function(
  'repoUrl', 'branch', 'scanGenerationRef', 'scanSubmissionPendingRef', 'isScanRunning',
  'setErrorMsg', 'setIsSubmitting', 'setActiveScan', 'setFindings',
  'setFindingsLoaded', 'setArtifactError', 'setTelemetry', 'startScan',
  `${body}; return handleStartScan;`,
);

function fixture({ repoUrl = 'https://github.com/fastapi/fastapi', branch = 'main', running = false } = {}) {
  const scanGenerationRef = { current: 0 };
  const scanSubmissionPendingRef = { current: false };
  const requests = [];
  const deferred = [];
  const errors = [];
  const submitting = [];
  const active = [];
  const noop = () => {};
  const handler = makeHandler(
    repoUrl, branch, scanGenerationRef, scanSubmissionPendingRef, running,
    (message) => errors.push(message), (busy) => submitting.push(busy),
    (scan) => active.push(scan), noop, noop, noop, noop,
    (request) => {
      requests.push(request);
      return new Promise((resolve, reject) => deferred.push({ resolve, reject }));
    },
  );
  const submit = () => handler({ preventDefault() {} });
  return { submit, requests, deferred, errors, submitting, active, scanGenerationRef, scanSubmissionPendingRef };
}

test('two rapid submissions create exactly one scan and preserve its response', async () => {
  const f = fixture();
  const first = f.submit();
  const second = f.submit();
  assert.equal(f.requests.length, 1);
  assert.deepEqual(f.requests[0], { repository_url: 'https://github.com/fastapi/fastapi', branch: 'main' });
  assert.equal(f.scanGenerationRef.current, 1);
  assert.equal(f.scanSubmissionPendingRef.current, true);
  f.deferred[0].resolve({ id: 'scan-1', status: 'PENDING' });
  await Promise.all([first, second]);
  assert.equal(f.scanSubmissionPendingRef.current, true);
  assert.deepEqual(f.active.at(-1), { id: 'scan-1', status: 'PENDING' });
});

test('failed scan initiation releases the guard and allows retry', async () => {
  const f = fixture();
  const first = f.submit();
  f.deferred[0].reject(new Error('service unavailable'));
  await first;
  assert.equal(f.scanSubmissionPendingRef.current, false);
  assert.match(f.errors.at(-1), /service unavailable/);
  const retry = f.submit();
  assert.equal(f.requests.length, 2);
  f.deferred[1].resolve({ id: 'scan-2', status: 'PENDING' });
  await retry;
  assert.deepEqual(f.active.at(-1), { id: 'scan-2', status: 'PENDING' });
  assert.deepEqual(f.submitting, [true, false, true, false]);
});

test('a running scan cannot be replaced by another submission', async () => {
  const f = fixture({ running: true });
  await f.submit();
  assert.equal(f.requests.length, 0);
  assert.equal(f.scanGenerationRef.current, 0);
});

test('empty repository URL does not acquire the submission lock', async () => {
  const f = fixture({ repoUrl: '  ' });
  await f.submit();
  assert.equal(f.requests.length, 0);
  assert.equal(f.scanSubmissionPendingRef.current, false);
});

test('empty branch retains the existing main fallback', async () => {
  const f = fixture({ branch: '  ' });
  const started = f.submit();
  assert.equal(f.requests[0].branch, 'main');
  f.deferred[0].resolve({ id: 'scan-3', status: 'COMPLETED' });
  await started;
});

test('resolved pending scan remains guarded before the next React render', async () => {
  const f = fixture();
  const first = f.submit();
  f.deferred[0].resolve({ id: 'scan-1', status: 'PENDING' });
  await first;
  assert.equal(f.scanSubmissionPendingRef.current, true);
  await f.submit();
  assert.equal(f.requests.length, 1, 'same-render callback must not start a second scan');
});

test('terminal scan state releases the guard and permits a new scan', async () => {
  // The real effect observes the terminal state after React commits the update.
  assert.match(source, /if \(!isScanRunning\) scanSubmissionPendingRef\.current = false/);
  const f = fixture();
  const first = f.submit();
  f.deferred[0].resolve({ id: 'scan-1', status: 'COMPLETED' });
  await first;
  assert.equal(f.scanSubmissionPendingRef.current, false);
  const second = f.submit();
  assert.equal(f.requests.length, 2);
  f.deferred[1].resolve({ id: 'scan-2', status: 'COMPLETED' });
  await second;
});
