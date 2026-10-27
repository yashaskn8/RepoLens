import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const source = readFileSync(new URL('../src/app/changes/[id]/page.tsx', import.meta.url), 'utf8');
const helperStart = source.indexOf('function withChangeDetailDeadline<T>(');
const helperEnd = source.indexOf('\ninterface ChangeDetailPageProps', helperStart);
assert.ok(helperStart >= 0 && helperEnd > helperStart, 'deadline helper exists');
const helperSource = source.slice(helperStart, helperEnd)
  .replace('function withChangeDetailDeadline<T>(request: (signal: AbortSignal) => Promise<T>): Promise<T> {',
    'function withChangeDetailDeadline(request) {')
  .replace('let timer: ReturnType<typeof setTimeout> | undefined;', 'let timer;')
  .replace('new Promise<never>', 'new Promise');

function makeDeadlineHarness() {
  const timers = new Map();
  let nextTimer = 0;
  const signals = [];
  class FakeAbortController {
    signal = { aborted: false };
    constructor() { signals.push(this.signal); }
    abort() { this.signal.aborted = true; }
  }
  const schedule = (callback) => { const id = ++nextTimer; timers.set(id, callback); return id; };
  const clear = (id) => timers.delete(id);
  const load = new Function('AbortController', 'setTimeout', 'clearTimeout',
    helperSource + '\nreturn withChangeDetailDeadline;');
  return { run: load(FakeAbortController, schedule, clear), timers, signals };
}

test('hung read times out, aborts and releases its deadline', async () => {
  const h = makeDeadlineHarness();
  const pending = h.run(() => new Promise(() => {}));
  assert.equal(h.timers.size, 1);
  [...h.timers.values()][0]();
  await assert.rejects(pending, /timed out/);
  assert.equal(h.signals[0].aborted, true);
  assert.equal(h.timers.size, 0);
});

test('successful read clears its deadline without aborting', async () => {
  const h = makeDeadlineHarness();
  assert.equal(await h.run(async () => 'ready'), 'ready');
  assert.equal(h.signals[0].aborted, false);
  assert.equal(h.timers.size, 0);
});

const loadStart = source.indexOf('          const publicationReadSequence = publicationReadSequenceRef.current;');
const loadEnd = source.indexOf('          if (cancelled) return;', loadStart);
assert.ok(loadStart >= 0 && loadEnd > loadStart, 'independent publication loader exists');
const loaderSource = source.slice(loadStart, loadEnd);
const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
const loadArtifacts = new AsyncFunction(
  'withChangeDetailDeadline', 'fetchReviewPublication', 'analysisId', 'publicationReadSequenceRef',
  'fetchChangeAnalysisDiff', 'fetchChangeAnalysisImpacts', 'fetchChangeAnalysisReview',
  'setPublication', 'cancelled',
  loaderSource + '\nreturn { diffRes, impactsRes, reviewRes };',
);

test('a stalled optional publication read does not block required evidence', async () => {
  const publications = [];
  const result = await loadArtifacts(
    (request) => request({}), () => new Promise(() => {}), 'analysis-1', { current: 0 },
    async () => ({ changed_files: [] }), async () => [], async () => ({ findings: [] }),
    (value) => publications.push(value), false,
  );
  assert.deepEqual(result.diffRes.status, 'fulfilled');
  assert.deepEqual(result.impactsRes.status, 'fulfilled');
  assert.deepEqual(result.reviewRes.status, 'fulfilled');
  assert.deepEqual(publications, []);
});

test('obsolete optional publication responses cannot overwrite operator actions', async () => {
  let resolvePublication;
  const deferred = new Promise((resolve) => { resolvePublication = resolve; });
  const sequence = { current: 0 };
  const publications = [];
  await loadArtifacts(
    (request) => request({}), () => deferred, 'analysis-1', sequence,
    async () => ({}), async () => [], async () => ({}),
    (value) => publications.push(value), false,
  );
  sequence.current += 1; // Operator started a newer preview/approval.
  resolvePublication({ status: 'APPROVED' });
  await Promise.resolve();
  await Promise.resolve();
  assert.deepEqual(publications, []);
});

test('successful publication is acknowledged before bounded reconciliation', () => {
  const actionStart = source.indexOf('  const handleApproveAndPublish = async () => {');
  const actionEnd = source.indexOf('  const currentFileDiff =', actionStart);
  const action = source.slice(actionStart, actionEnd);
  assert.ok(action.includes('setPublication((current) => current?.publication_id === res.publication_id'));
  assert.ok(action.indexOf('setPublication((current) => current?.publication_id === res.publication_id') <
    action.indexOf('await withChangeDetailDeadline((signal) => fetchReviewPublication'));
  assert.match(action, /current\.status === 'PUBLISHED' && updatedPub\.status !== 'PUBLISHED'/);
  assert.match(action, /Verify the current status before another publication attempt/);
});
