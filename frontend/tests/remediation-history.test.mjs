import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { runInNewContext } from 'node:vm';
import ts from 'typescript';
const root = dirname(dirname(fileURLToPath(import.meta.url)));
const source = readFileSync(join(root, 'src/lib/remediationHistory.ts'), 'utf8');
const js = ts.transpileModule(source, { compilerOptions: {
  module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022,
}}).outputText;
const exports = {};
runInNewContext(js, { exports, Set, Error });
const { findLatestRemediationJobs } = exports;
const job = (kind, state, resourceId='finding-a') => ({
  id: `${kind}-${state}`, work_kind: kind, resource_type: 'FINDING',
  resource_id: resourceId, state,
});
test('finds latest relevant research and plan across cursor pages', async () => {
  let calls = 0;
  const found = await findLatestRemediationJobs('finding-a', async (cursor) => {
    calls += 1;
    if (!cursor) return { items: [job('RESEARCH', 'SUCCEEDED')], next_cursor: 'older' };
    return { items: [job('FIX_PLAN', 'SUCCEEDED')], next_cursor: null };
  });
  assert.equal(calls, 2);
  assert.equal(found.research.state, 'SUCCEEDED');
  assert.equal(found.plan.state, 'SUCCEEDED');
});
test('latest failed job is retained as failed, never replaced by stale success', async () => {
  const found = await findLatestRemediationJobs('finding-a', async () => ({
    items: [job('RESEARCH', 'FAILED'), job('RESEARCH', 'SUCCEEDED'), job('FIX_PLAN', 'PENDING')],
    next_cursor: null,
  }));
  assert.equal(found.research.state, 'FAILED');
  assert.equal(found.plan.state, 'PENDING');
});
test('job discovery never includes a different tenant or finding', async () => {
  const found = await findLatestRemediationJobs('finding-a', async () => ({
    items: [job('RESEARCH', 'SUCCEEDED', 'finding-b')],
    next_cursor: null,
  }));
  assert.equal(found.research, null);
});
test('pagination cursor loops are rejected rather than hiding older jobs', async () => {
  await assert.rejects(findLatestRemediationJobs('finding-a', async () => ({
    items: [], next_cursor: 'stuck',
  })), /Inconsistent persisted remediation job pagination/);
});
test('remediation UI retrieves only successful job results without rerunning provider work', () => {
  const ui = readFileSync(join(root, 'src/features/remediation/RemediationLifecycle.tsx'), 'utf8');
  assert.match(ui, /latest\.research\?\.state === 'SUCCEEDED'/);
  assert.match(ui, /latest\.plan\?\.state === 'SUCCEEDED'/);
  assert.match(ui, /fetchJobResult<ResearchResult>/);
  assert.match(ui, /fetchJobResult<FixPlan>/);
});
