import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const source = readFileSync(new URL('../src/features/change-analysis/ChangeAnalysisWorkspace.tsx', import.meta.url), 'utf8');
const start = source.indexOf('  const retryCompletedArtifacts = async');
const end = source.indexOf('  const handleStartAnalysis =', start);
assert.ok(start >= 0 && end > start, 'artifact retry handler must exist');
const handlerSource = source.slice(start, end);

function deferred() {
  let resolve;
  const promise = new Promise(done => { resolve = done; });
  return { promise, resolve };
}

function fixture() {
  const generation = { current: 1 };
  const pending = { current: false };
  const requests = [];
  const busyStates = [];
  const makeRetry = (analysis) => new Function(
    'activeAnalysis', 'isRetryingArtifacts', 'analysisGenerationRef',
    'artifactRetryPendingRef', 'setIsRetryingArtifacts', 'loadCompletedAnalysisData',
    handlerSource + '\nreturn retryCompletedArtifacts;',
  )(
    analysis, false, generation, pending,
    value => busyStates.push(value),
    (id, gen) => {
      const response = deferred();
      requests.push({ id, gen, ...response });
      return response.promise;
    },
  );
  return { generation, pending, requests, busyStates, makeRetry };
}

test('synchronous repeated retry clicks start only one artifact request', async () => {
  const f = fixture();
  const retry = f.makeRetry({ id: 'analysis-A', status: 'COMPLETED' });
  const first = retry();
  const second = retry();
  assert.equal(f.requests.length, 1, 'state-only guards do not prevent double submission before rerender');
  f.requests[0].resolve();
  await Promise.all([first, second]);
  assert.equal(f.pending.current, false);
  const third = retry();
  assert.equal(f.requests.length, 2, 'the lock must release after completion');
  f.requests[1].resolve();
  await third;
});

test('unfinished analyses cannot manually retry completed artifacts', async () => {
  const f = fixture();
  await f.makeRetry({ id: 'analysis-A', status: 'ANALYZING' })();
  assert.equal(f.requests.length, 0);
});

test('obsolete retry completion cannot unlock a newer analysis retry', async () => {
  const f = fixture();
  const oldRetry = f.makeRetry({ id: 'analysis-A', status: 'COMPLETED' });
  const old = oldRetry();
  f.generation.current += 1;
  f.pending.current = false; // new analysis resets the synchronous lock
  const newRetry = f.makeRetry({ id: 'analysis-B', status: 'COMPLETED' });
  const current = newRetry();
  assert.equal(f.requests.length, 2);
  f.requests[0].resolve();
  await old;
  assert.equal(f.pending.current, true, 'obsolete response must not unlock the new request');
  await newRetry();
  assert.equal(f.requests.length, 2);
  f.requests[1].resolve();
  await current;
  assert.equal(f.pending.current, false);
});
