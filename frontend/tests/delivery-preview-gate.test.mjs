import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import test from 'node:test';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const ui = readFileSync(join(root, 'src/features/remediation/RemediationLifecycle.tsx'), 'utf8');
const modal = readFileSync(join(root, 'src/features/remediation/DeliveryPreviewModal.tsx'), 'utf8');
const api = readFileSync(join(root, 'src/lib/api.ts'), 'utf8');

test('delivery cannot start without authenticated operator and eligible preview', () => {
  assert.match(ui, /!user\?\.id \|\| !isOperator \|\| !deliveryPreview\?\.eligible/);
  assert.match(ui, /!deliveryPreview\?\.eligible \|\|/);
  assert.match(modal, /disabled=\{isDelivering \|\| !deliveryPreview\?\.eligible/);
});
test('delivery preview errors never silently enable publishing', () => {
  assert.doesNotMatch(ui, /fetchDeliveryPreview\(patchId\)\.catch\(\(\) => null\)/);
  assert.match(ui, /Delivery preview is unavailable/);
  assert.doesNotMatch(modal, /base_branch \|\| 'main'/);
});
test('frontend approval and delivery actors are not invented', () => {
  assert.match(ui, /approvePatch\(patchId, \{\}\)/);
  assert.match(ui, /requested_by: user\.id/);
  assert.doesNotMatch(ui, /'lead-engineer'/);
  assert.doesNotMatch(modal, /Requested By \(User Identifier\)/);
  assert.match(api, /payload: PatchReviewRequest = \{\}/);
});
