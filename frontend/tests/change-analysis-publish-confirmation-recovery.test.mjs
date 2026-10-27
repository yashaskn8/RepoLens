import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const source = readFileSync(new URL('../src/features/change-analysis/ChangeAnalysisWorkspace.tsx', import.meta.url), 'utf8');
const start = source.indexOf('  const handlePublishReview = async');
const end = source.indexOf('  const handleCopyDigest =', start);
assert.ok(start >= 0 && end > start, 'publication handler must exist');
const handler = source.slice(start, end)
  .replaceAll('catch (err: unknown)', 'catch (err)')
  .replaceAll('new Promise<never>', 'new Promise')
  .replace(/let refreshTimer: ReturnType<typeof setTimeout> \| undefined;/, 'let refreshTimer;');

const deferred = () => {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
};
const tick = () => new Promise(resolve => setImmediate(resolve));

function fixture() {
  const timers = new Map();
  let nextTimer = 0;
  const writes = { errors: [], confirmations: [], busy: [], publications: [] };
  const current = { publication_id: 'pub-1', status: 'APPROVED', preview_digest: 'digest-A' };
  const context = {
    activeAnalysis: { id: 'analysis-A' },
    publication: current,
    analysisGenerationRef: { current: 1 },
    publicationPendingRef: { current: false },
    publicationActionSequenceRef: { current: 0 },
    publishReviewPublication: async () => ({ publication_id: 'pub-1', status: 'PUBLISHED', github_review_id: 42 }),
    fetchReviewPublication: async () => ({ ...current, status: 'PUBLISHED', github_review_id: 42 }),
    setPublication: update => {
      const next = typeof update === 'function' ? update(context.publication) : update;
      context.publication = next;
      writes.publications.push(next);
    },
    setPubError: value => writes.errors.push(value),
    setShowPublishConfirm: value => writes.confirmations.push(value),
    setIsPublishingPub: value => writes.busy.push(value),
    setTimeout: (callback, delay) => {
      assert.equal(delay, 15_000);
      const id = ++nextTimer;
      timers.set(id, callback);
      return id;
    },
    clearTimeout: id => timers.delete(id),
  };
  const run = new Function('context', 'with (context) { ' + handler + '\nreturn handlePublishReview; }')(context);
  return {
    run, context, writes,
    pending: () => timers.size,
    expire: () => { for (const [id, callback] of [...timers]) { timers.delete(id); callback(); } },
  };
}

test('successful publish response is shown without waiting for stalled status GET', async () => {
  const f = fixture();
  const stalled = deferred();
  f.context.fetchReviewPublication = (_id, signal) => {
    f.context.refreshSignal = signal;
    return stalled.promise;
  };
  const running = f.run();
  await tick();
  assert.equal(f.context.publication.status, 'PUBLISHED');
  assert.equal(f.context.publication.github_review_id, 42);
  assert.deepEqual(f.writes.confirmations, [false]);
  assert.equal(f.pending(), 1);
  f.expire();
  await running;
  assert.equal(f.context.refreshSignal.aborted, true);
  assert.match(f.writes.errors.at(-1), /do not repeat publication/i);
  assert.equal(f.context.publication.status, 'PUBLISHED');
  assert.equal(f.context.publicationPendingRef.current, false);
  stalled.resolve({ status: 'APPROVED' });
  await tick();
  assert.equal(f.context.publication.status, 'PUBLISHED');
});

test('successful status refresh replaces interim publish response and clears timer', async () => {
  const f = fixture();
  await f.run();
  assert.equal(f.context.publication.status, 'PUBLISHED');
  assert.equal(f.pending(), 0);
  assert.deepEqual(f.writes.errors, [null]);
  assert.equal(f.context.publicationPendingRef.current, false);
});

test('failed publication POST is not misrepresented as a successful publication', async () => {
  const f = fixture();
  let refreshes = 0;
  f.context.publishReviewPublication = async () => { throw new Error('publish rejected'); };
  f.context.fetchReviewPublication = async () => { refreshes++; };
  await f.run();
  assert.equal(refreshes, 0);
  assert.equal(f.context.publication.status, 'APPROVED');
  assert.equal(f.writes.errors.at(-1), 'publish rejected');
  assert.equal(f.context.publicationPendingRef.current, false);
});

test('obsolete publish response cannot update a newer analysis', async () => {
  const f = fixture();
  const pending = deferred();
  f.context.publishReviewPublication = () => pending.promise;
  const running = f.run();
  f.context.analysisGenerationRef.current += 1;
  pending.resolve({ publication_id: 'pub-1', status: 'PUBLISHED' });
  await running;
  assert.equal(f.writes.publications.length, 0);
  assert.equal(f.writes.confirmations.length, 0);
});
