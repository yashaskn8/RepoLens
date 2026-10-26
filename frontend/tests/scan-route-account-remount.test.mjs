import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import test from 'node:test';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const source = readFileSync(join(root, 'src/app/scan/page.tsx'), 'utf8');
const keyMatch = source.match(/const workspaceKey = ([^;]+);/);
assert.ok(keyMatch, 'scan workspace must derive an account-scoped key');
const workspaceKey = new Function('isLoading', 'user', `return (${keyMatch[1]});`);

test('scan workspace identity changes between accounts and logout', () => {
  const first = workspaceKey(false, { id: 'account-A' });
  const second = workspaceKey(false, { id: 'account-B' });
  const signedOut = workspaceKey(false, null);
  assert.notEqual(first, second);
  assert.notEqual(first, signedOut);
  assert.notEqual(second, signedOut);
});

test('session restoration cannot reuse the previous account workspace', () => {
  const first = workspaceKey(false, { id: 'account-A' });
  const restoring = workspaceKey(true, { id: 'account-A' });
  assert.notEqual(first, restoring);
  assert.equal(restoring, workspaceKey(true, null));
});

test('the rendered scan workspace is keyed and wrapped by the auth boundary', () => {
  assert.match(source, /function AccountBoundScanWorkspace\(\)/);
  assert.match(source, /<ScanWorkspaceContent key=\{workspaceKey\} \/>/);
  assert.match(source, /<AccountBoundScanWorkspace \/>/);
  assert.doesNotMatch(source, /<ScanWorkspaceContent \/>/);
});

test('account transition invalidates requests and clears tenant-scoped scan state', () => {
  assert.match(source, /scanRequestGeneration\.current \+= 1;\s+scanSubmissionPendingRef\.current = false/);
  assert.match(source, /setActiveScan\(null\);\s+setRecentScans\(\[\]\);/);
});
