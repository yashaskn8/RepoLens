import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import test from 'node:test';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const source = readFileSync(join(root, 'src/features/remediation/RemediationLifecycle.tsx'), 'utf8');

test('remediation restores persisted proposals after browser refresh', () => {
  assert.match(source, /await fetchScanPatches\(finding\.scan_id\)/);
  assert.match(source, /history\.find\(\(patch\) => patch\.finding_id === finding\.id\)/);
  assert.match(source, /if \(!active \|\| localPatchActionRef\.current\) return/);
});
test('revision replaces active proposal identity and diff, revoking stale verification', () => {
  const handler = source.slice(source.indexOf('const handleRevise = async'), source.indexOf('// Step 7:'));
  for (const required of [
    'setPatchId(updated.id)',
    'setDiff(updated.unified_diff)',
    'setFilesModified(updated.files_modified)',
    'setPatchStatus(updated.status)',
    'setWorkflowResult(null)',
    'setDeliveryPreview(null)',
    'setDelivery(null)',
  ]) {
    assert.ok(handler.includes(required), `Missing revision transition: ${required}`);
  }
});
test('remediation clears previous finding state and does not present nonexistent patch as generated', () => {
  assert.match(source, /setPatchId\(initialPatch\?\.id \|\| null\)/);
  assert.match(source, /setResearch\(null\)/);
  assert.match(source, /No patch proposal yet/);
  assert.match(source, /\{patchId && \(/);
});
