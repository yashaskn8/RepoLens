import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { runInNewContext } from 'node:vm';
import ts from 'typescript';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const source = readFileSync(join(root, 'src/lib/api.ts'), 'utf8');
const match = source.match(/export async function revisePatch\([\s\S]*?\n\}/);
assert.ok(match);
const js = ts.transpileModule(match[0], {
  compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
}).outputText;

function simulate({ response, job, child, errorCode = 'REVISION_QUEUED' }) {
  const exports = {};
  const calls = [];
  class ApiError extends Error {
    constructor(message, status, code) { super(message); this.status = status; this.errorCode = code; }
  }
  const apiFetch = async (url) => {
    calls.push(['api', url]);
    return response;
  };
  const fetchJob = async (id) => { calls.push(['job', id]); return job; };
  const fetchPatch = async (id) => { calls.push(['patch', id]); return child; };
  const apiErrorFromResponse = async () => new ApiError('Revision queued', 503, errorCode);
  runInNewContext(js, {
    exports, apiFetch, fetchJob, fetchPatch, apiErrorFromResponse, ApiError,
    REMEDIATION_POLL_ATTEMPTS: 1, REMEDIATION_POLL_INTERVAL_MS: 1,
    TERMINAL_JOB_STATES: new Set(['SUCCEEDED', 'FAILED', 'CANCELLED', 'TIMED_OUT']),
    setTimeout, Promise, Error, JSON,
  });
  return { revisePatch: exports.revisePatch, calls };
}
const accepted = () => ({
  ok: false, status: 503,
  headers: { get: () => '/api/v1/jobs/11111111-1111-1111-1111-111111111111' },
});
test('queued revision resolves to verified parent-bound child patch', async () => {
  const child = { id: 'child-id', parent_patch_id: 'parent-id' };
  const app = simulate({
    response: accepted(),
    job: { state: 'SUCCEEDED', outcome_detail: { patch_id: 'child-id' } },
    child,
  });
  const result = await app.revisePatch('parent-id', { user_feedback: 'Safer fix' });
  assert.equal(result.id, 'child-id');
  assert.deepEqual(app.calls.map((x) => x[0]), ['api', 'job', 'patch']);
});
test('queued revision refuses child with wrong parent', async () => {
  const app = simulate({
    response: accepted(),
    job: { state: 'SUCCEEDED', outcome_detail: { patch_id: 'child-id' } },
    child: { id: 'child-id', parent_patch_id: 'other-parent' },
  });
  await assert.rejects(
    app.revisePatch('parent-id', { user_feedback: 'Fix' }),
    /does not match the requested patch/,
  );
});
test('failed queued revision is not returned as an approved patch', async () => {
  const app = simulate({
    response: accepted(),
    job: { state: 'FAILED', failures: [{ message: 'Revision failed verification' }] },
  });
  await assert.rejects(
    app.revisePatch('parent-id', { user_feedback: 'Fix' }),
    /Revision failed verification/,
  );
});
test('unrecognized 503 never enters revision polling', async () => {
  const app = simulate({
    response: accepted(),
    errorCode: 'NEW_JOBS_PAUSED',
  });
  await assert.rejects(
    app.revisePatch('parent-id', { user_feedback: 'Fix' }),
    /Revision queued/,
  );
  assert.deepEqual(app.calls.map((x) => x[0]), ['api']);
});
