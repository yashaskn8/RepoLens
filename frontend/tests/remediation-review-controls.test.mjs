import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import test from 'node:test';
const root = dirname(dirname(fileURLToPath(import.meta.url)));
const lifecycle = readFileSync(join(root, 'src/features/remediation/RemediationLifecycle.tsx'), 'utf8');
const controls = readFileSync(join(root, 'src/features/remediation/HumanReviewControls.tsx'), 'utf8');

test('human review is permitted only once proposal is verification-ready', () => {
  assert.match(controls, /patchStatus === 'VERIFIED' \|\| patchStatus === 'NEEDS_REVIEW'/);
  assert.match(controls, /disabled=\{!reviewReady \|\| busy\}/);
  assert.match(lifecycle, /Not yet verified/);
});
test('UI does not request second human revision or submit conflicting actions', () => {
  assert.match(lifecycle, /canRevise=\{revisionNumber < 1\}/);
  assert.match(lifecycle, /setRevisionNumber\(saved\.revision_number \?\? 0\)/);
  assert.match(lifecycle, /setRevisionNumber\(updated\.revision_number \?\? 1\)/);
  assert.match(controls, /disabled=\{!reviewReady \|\| !canRevise \|\| busy\}/);
  assert.match(controls, /disabled=\{!revisionFeedback\.trim\(\) \|\| busy\}/);
  assert.match(controls, /disabled=\{!rejectReason\.trim\(\) \|\| busy\}/);
});
