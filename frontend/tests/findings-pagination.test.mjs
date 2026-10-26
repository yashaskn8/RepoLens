import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { runInNewContext } from 'node:vm';
import ts from 'typescript';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const source = readFileSync(join(root, 'src/lib/findingsPagination.ts'), 'utf8');
const compiled = ts.transpileModule(source, {
  compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
}).outputText;
const exports = {};
runInNewContext(compiled, { exports, Promise, Number, Error, Array });
const { loadScanFindingsPage } = exports;

test('findings page discovers older scans without hiding the pagination boundary', async () => {
  const scans = Array.from({ length: 5 }, (_, i) => ({ id: `scan-${i}` }));
  const calls = [];
  const list = async (limit, offset) => {
    calls.push([limit, offset]);
    return scans.slice(offset, offset + limit);
  };
  const findings = async (id) => [{ id: `finding-${id}` }];
  const first = await loadScanFindingsPage(0, 3, list, findings);
  assert.equal(first.findings.length, 3);
  assert.equal(first.hasOlderScans, true);
  const second = await loadScanFindingsPage(first.scanCount, 3, list, findings);
  assert.equal(second.findings.length, 2);
  assert.equal(second.hasOlderScans, false);
  assert.deepEqual(calls, [[3, 0], [3, 3]]);
});

test('partial findings failures are counted, not represented as clean', async () => {
  const page = await loadScanFindingsPage(
    0, 2,
    async () => [{ id: 'ok' }, { id: 'broken' }],
    async (id) => { if (id === 'broken') throw new Error('unavailable'); return [{ id: 'verified' }]; },
  );
  assert.equal(page.failedCount, 1);
  assert.equal(page.findings.length, 1);
  assert.equal(page.hasOlderScans, true);
});

test('invalid server pagination is rejected', async () => {
  await assert.rejects(
    loadScanFindingsPage(0, 2, async () => [{ id: 'a' }, { id: 'b' }, { id: 'c' }], async () => []),
    /Invalid scan pagination response/,
  );
});
