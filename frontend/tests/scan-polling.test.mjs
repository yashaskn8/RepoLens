import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { runInNewContext } from 'node:vm';
import ts from 'typescript';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const content = readFileSync(join(root, 'src/lib/scanPolling.ts'), 'utf8');
const code = ts.transpileModule(content, {
  compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
}).outputText;
const exports = {};
runInNewContext(code, { exports });
const { reconcilePolledScan } = exports;

test('a response from the previously selected scan cannot replace the active scan', () => {
  const current = { id: 'new-scan', status: 'RUNNING' };
  const stale = { id: 'old-scan', status: 'COMPLETED' };
  assert.equal(reconcilePolledScan(current, stale, 'old-scan'), current);
});

test('late running responses cannot regress completed or failed results', () => {
  for (const status of ['COMPLETED', 'FAILED']) {
    const current = { id: 'scan', status };
    const stale = { id: 'scan', status: 'RUNNING' };
    assert.equal(reconcilePolledScan(current, stale, 'scan'), current);
  }
});

test('current scan accepts real progress and terminal transitions', () => {
  const current = { id: 'scan', status: 'PENDING' };
  const running = { id: 'scan', status: 'RUNNING' };
  const completed = { id: 'scan', status: 'COMPLETED' };
  assert.equal(reconcilePolledScan(current, running, 'scan'), running);
  assert.equal(reconcilePolledScan(running, completed, 'scan'), completed);
});

test('scan page polls sequentially rather than overlapping intervals', () => {
  const page = readFileSync(join(root, 'src/app/scan/page.tsx'), 'utf8');
  assert.doesNotMatch(page, /setInterval\(async \(\) =>/);
  assert.match(page, /nextPoll = setTimeout\(poll,/);
  assert.match(page, /if \(cancelled\) return;/);
  assert.match(page, /reconcilePolledScan\(current, updated, scanId\)/);
});

test('logout and account changes clear the prior tenant scan before loading history', () => {
  const page = readFileSync(join(root, 'src/app/scan/page.tsx'), 'utf8');
  const start = page.indexOf('// Server state is tenant-scoped.');
  const end = page.indexOf('// Sequential, cancel-safe polling', start);
  const section = page.slice(start, end);
  const effect = section.match(/useEffect\(\(\) => \{([\s\S]*?)\}, \[accountId, isAuthLoading\]\);/);
  assert.ok(effect, 'auth-scoped scan effect must track account identity');
  const runEffect = new Function(
    'isAuthLoading', 'accountId', 'scanRequestGeneration', 'setActiveScan',
    'setRecentScans', 'setError', 'setIsSubmitting', 'listScans', effect[1],
  );

  for (const nextAccount of [null, 'other-account']) {
    let activeScan = { id: 'previous-tenant-scan', status: 'COMPLETED' };
    let recentScans = [activeScan];
    let error = 'previous tenant error';
    let isSubmitting = true;
    const generation = { current: 7 };
    runEffect(
      false, nextAccount, generation,
      (value) => { activeScan = value; },
      (value) => { recentScans = value; },
      (value) => { error = value; },
      (value) => { isSubmitting = value; },
      () => new Promise(() => {}),
    );
    assert.equal(activeScan, null);
    assert.deepEqual(recentScans, []);
    assert.equal(error, null);
    assert.equal(isSubmitting, false);
    assert.equal(generation.current, 8);
  }
});

test('late scan submissions cannot restore results after account change', () => {
  const page = readFileSync(join(root, 'src/app/scan/page.tsx'), 'utf8');
  const submit = page.slice(page.indexOf('const handleStartScan'), page.indexOf('const isScanning'));
  assert.match(submit, /const generation = \+\+scanRequestGeneration\.current/);
  assert.match(submit, /if \(generation !== scanRequestGeneration\.current\) return;/);
  assert.match(submit, /if \(generation === scanRequestGeneration\.current\) setIsSubmitting\(false\);/);
});
