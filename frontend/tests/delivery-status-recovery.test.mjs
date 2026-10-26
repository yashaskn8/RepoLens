import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import test from 'node:test';
const root = dirname(dirname(fileURLToPath(import.meta.url)));
const source = readFileSync(join(root, 'src/features/remediation/RemediationLifecycle.tsx'), 'utf8');
test('accepted delivery is polled rather than treated as an immediate PR', () => {
  assert.match(source, /await fetchDelivery\(delivery\.id\)/);
  assert.match(source, /next\.patch_id !== patchId/);
  assert.match(source, /\['PR_CREATED', 'FAILED', 'BLOCKED'\]\.includes\(next\.status\)/);
  assert.match(source, /attempts < 120/);
});
test('pending delivery cannot be resubmitted and cancelled polling is cleaned up', () => {
  assert.match(source, /delivery !== null && !\['FAILED', 'BLOCKED'\]\.includes\(delivery\.status\)/);
  assert.match(source, /clearTimeout\(timer\)/);
  assert.match(source, /Delivery in progress/);
});
