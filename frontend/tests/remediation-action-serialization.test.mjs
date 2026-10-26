import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const source = readFileSync(join(root, 'src/features/remediation/RemediationLifecycle.tsx'), 'utf8');
const names = ['handleRequestResearch', 'handleRequestPlan', 'handleRequestPatch', 'handleApprove'];
const handlers = names.map((name) => {
  const start = source.indexOf('const ' + name + ' = async () => {');
  assert.ok(start >= 0, 'Missing handler ' + name);
  const end = source.indexOf('\n  };', start);
  assert.ok(end > start, 'Missing handler end ' + name);
  return source.slice(start, end + 6).replaceAll('catch (err: unknown)', 'catch (err)');
}).join('\n');

function deferred() {
  let resolve;
  const promise = new Promise((yes) => { resolve = yes; });
  return { promise, resolve };
}

function mount(api = {}) {
  const state = { patchId: 'parent', patchStatus: 'VERIFIED', loadingStep: null, error: null };
  const proposal = { id: 'new-patch', unified_diff: 'diff', files_modified: [] };
  const ctx = {
    state, finding: { id: 'finding-A' },
    actionInFlightRef: { current: false }, localPatchActionRef: { current: false },
    researchActionRef: { current: false }, planActionRef: { current: false },
    setError: (value) => { state.error = value; },
    setLoadingStep: (value) => { state.loadingStep = value; },
    setPatchStatus: (value) => { state.patchStatus = value; },
    setResearch() {}, setPlan() {}, setWorkflowResult() {},
    setRevisionNumber() {}, setDiff() {}, setFilesModified() {},
    setDelivery() {}, setDeliveryPreview() {},
    requestFindingResearch: async () => ({}),
    requestFixPlan: async () => ({}),
    requestPatchGeneration: async () => ({ proposal, machine_verdict: 'PASSED' }),
    approvePatch: async () => ({ status: 'APPROVED' }),
    ...api,
  };
  const factory = new Function('ctx', [
    'const { finding, actionInFlightRef, localPatchActionRef, researchActionRef, planActionRef,',
    ' setError, setLoadingStep, setPatchStatus, setResearch, setPlan, setWorkflowResult,',
    ' setRevisionNumber, setDiff, setFilesModified, setDelivery, setDeliveryPreview,',
    ' requestFindingResearch, requestFixPlan, requestPatchGeneration, approvePatch } = ctx;',
    "let patchId = 'parent';",
    'const setPatchId = (id) => { patchId = id; ctx.state.patchId = id; };',
    handlers,
    'return { ' + names.join(', ') + ' };',
  ].join('\n'));
  return { state, ...factory(ctx) };
}

test('approval in flight cannot authorize a newly regenerated patch', async () => {
  const approval = deferred();
  let generations = 0;
  const app = mount({
    approvePatch: () => approval.promise,
    requestPatchGeneration: async () => {
      generations += 1;
      return { proposal: { id: 'new-patch', unified_diff: 'diff', files_modified: [] }, machine_verdict: 'PASSED' };
    },
  });
  const pending = app.handleApprove();
  await app.handleRequestPatch();
  assert.equal(generations, 0);
  approval.resolve({ status: 'APPROVED' });
  await pending;
  assert.equal(app.state.patchId, 'parent');
  await app.handleRequestPatch();
  assert.equal(generations, 1);
  assert.equal(app.state.patchStatus, 'VERIFIED');
});

test('regeneration in flight cannot approve the previous patch', async () => {
  const generation = deferred();
  let approvals = 0;
  const app = mount({
    requestPatchGeneration: () => generation.promise,
    approvePatch: async () => { approvals += 1; return { status: 'APPROVED' }; },
  });
  const pending = app.handleRequestPatch();
  await app.handleApprove();
  assert.equal(approvals, 0);
  generation.resolve({ proposal: { id: 'new-patch', unified_diff: 'diff', files_modified: [] }, machine_verdict: 'PASSED' });
  await pending;
  assert.equal(app.state.patchId, 'new-patch');
  assert.equal(app.state.patchStatus, 'VERIFIED');
  await app.handleApprove();
  assert.equal(approvals, 1);
});

test('planning and research cannot overlap and lose the busy indicator', async () => {
  const plan = deferred();
  let researches = 0;
  const app = mount({
    requestFixPlan: () => plan.promise,
    requestFindingResearch: async () => { researches += 1; return {}; },
  });
  const pending = app.handleRequestPlan();
  await app.handleRequestResearch();
  assert.equal(researches, 0);
  assert.equal(app.state.loadingStep, 'plan');
  plan.resolve({});
  await pending;
  await app.handleRequestResearch();
  assert.equal(researches, 1);
});

test('failed approval releases the lock so a retry works', async () => {
  let calls = 0;
  const app = mount({
    approvePatch: async () => {
      calls += 1;
      if (calls === 1) throw Error('network unavailable');
      return { status: 'APPROVED' };
    },
  });
  await app.handleApprove();
  assert.equal(app.state.error, 'network unavailable');
  await app.handleApprove();
  assert.equal(calls, 2);
  assert.equal(app.state.patchStatus, 'APPROVED');
});

test('request panels disable new actions while another lifecycle action runs', () => {
  for (const name of ['ResearchPanel', 'FixPlanPanel', 'PatchCandidatePanel']) {
    assert.match(source, new RegExp('<' + name + '[\\s\\S]*?disabled=\\{loadingStep !== null\\}'));
  }
  for (const file of ['ResearchPanel.tsx', 'FixPlanPanel.tsx', 'PatchCandidatePanel.tsx']) {
    const panel = readFileSync(join(root, 'src/features/remediation', file), 'utf8');
    assert.match(panel, /disabled=\{isLoading \|\| disabled\}/);
  }
});
