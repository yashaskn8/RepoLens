import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import test from 'node:test';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const source = readFileSync(join(root, 'src/features/remediation/RemediationLifecycle.tsx'), 'utf8');

// Execute the real recovery effect and request handlers, not an independent
// approximation of their state transitions.
const recovery = source.slice(
  source.indexOf('  // Restore previously completed research'),
  source.indexOf('  // Step 1: Request Research'),
).replaceAll('fetchJobResult<ResearchResult>', 'fetchJobResult')
 .replaceAll('fetchJobResult<FixPlan>', 'fetchJobResult');
const handlers = source.slice(
  source.indexOf('  const handleRequestResearch = async () => {'),
  source.indexOf('  // Step 3: Request Safe Patch Generation'),
).replaceAll('catch (err: unknown)', 'catch (err)');

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}

function mount({ jobs, research, plan } = {}) {
  const state = { research: null, plan: null, error: null, loadingStep: null };
  const refs = {
    researchActionRef: { current: false },
    planActionRef: { current: false },
    actionInFlightRef: { current: false },
  };
  const ctx = {
    ...refs, finding: { id: 'finding-1' },
    setResearch: value => { state.research = value; },
    setPlan: value => { state.plan = value; },
    setError: value => { state.error = value; },
    setLoadingStep: value => { state.loadingStep = value; },
    findLatestRemediationJobs: () => jobs ?? Promise.resolve({ research: null, plan: null }),
    fetchJobResult: id => Promise.resolve({ from: 'persisted', id }),
    listJobs: async () => ({ items: [], next_cursor: null }),
    requestFindingResearch: () => research ?? Promise.resolve({ from: 'new-research' }),
    requestFixPlan: () => plan ?? Promise.resolve({ from: 'new-plan' }),
    useEffect: callback => { callback(); },
  };
  const factory = new Function('ctx', [
    'const { finding, researchActionRef, planActionRef, actionInFlightRef,',
    ' setResearch, setPlan, setError, setLoadingStep,',
    ' findLatestRemediationJobs, fetchJobResult, listJobs,',
    ' requestFindingResearch, requestFixPlan, useEffect } = ctx;',
    recovery, handlers,
    'return { handleRequestResearch, handleRequestPlan };',
  ].join('\n'));
  return { state, refs, ...factory(ctx) };
}

async function settle() {
  for (let i = 0; i < 12; i += 1) await Promise.resolve();
}

test('late persisted research cannot replace an in-flight newer research request', async () => {
  const oldJobs = deferred();
  const newResearch = deferred();
  const app = mount({ jobs: oldJobs.promise, research: newResearch.promise });
  const pending = app.handleRequestResearch();
  oldJobs.resolve({ research: { id: 'old-research', state: 'SUCCEEDED' }, plan: null });
  await settle();
  assert.equal(app.refs.researchActionRef.current, true);
  assert.equal(app.state.research, null);
  assert.equal(app.state.loadingStep, 'research');
  newResearch.resolve({ from: 'new-research' });
  await pending;
  assert.deepEqual(app.state.research, { from: 'new-research' });
});

test('late persisted plan cannot replace an in-flight newer plan request', async () => {
  const oldJobs = deferred();
  const newPlan = deferred();
  const app = mount({ jobs: oldJobs.promise, plan: newPlan.promise });
  const pending = app.handleRequestPlan();
  oldJobs.resolve({ research: null, plan: { id: 'old-plan', state: 'SUCCEEDED' } });
  await settle();
  assert.equal(app.refs.planActionRef.current, true);
  assert.equal(app.state.plan, null);
  newPlan.resolve({ from: 'new-plan' });
  await pending;
  assert.deepEqual(app.state.plan, { from: 'new-plan' });
});

test('recovery errors do not overwrite successful newer research', async () => {
  const oldJobs = deferred();
  const app = mount({ jobs: oldJobs.promise });
  await app.handleRequestResearch();
  oldJobs.reject(Error('old history unavailable'));
  await settle();
  assert.equal(app.state.error, null);
  assert.deepEqual(app.state.research, { from: 'new-research' });
});

test('unrelated persisted plan can still recover while new research runs', async () => {
  const oldJobs = deferred();
  const newResearch = deferred();
  const app = mount({ jobs: oldJobs.promise, research: newResearch.promise });
  const pending = app.handleRequestResearch();
  oldJobs.resolve({ research: { id: 'old-research', state: 'SUCCEEDED' }, plan: { id: 'saved-plan', state: 'SUCCEEDED' } });
  await settle();
  assert.equal(app.state.research, null);
  assert.deepEqual(app.state.plan, { from: 'persisted', id: 'saved-plan' });
  newResearch.resolve({ from: 'new-research' });
  await pending;
});
