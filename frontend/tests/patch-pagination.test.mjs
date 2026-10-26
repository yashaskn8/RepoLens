import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { runInNewContext } from 'node:vm';
import ts from 'typescript';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const source = readFileSync(join(root, 'src/lib/api.ts'), 'utf8');
const matches = source.match(/export async function fetchScanPatches\(scanId: string\): Promise<PatchResponse\[\]> \{[\s\S]*?\n\}/);
assert.ok(matches);
const js = ts.transpileModule(matches[0], {
  compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
}).outputText;
function makeFetcher(pages) {
  const calls = [];
  const exports = {};
  class ApiError extends Error {}
  const apiFetch = async (url) => {
    calls.push(url);
    const offset = Number(new URL('https://api.example.test' + url).searchParams.get('offset'));
    const index = Math.floor(offset / 500);
    return { ok: true, json: async () => pages[index] || [] };
  };
  runInNewContext(js, { exports, apiFetch, apiErrorFromResponse: () => Error('error'), ApiError, URLSearchParams, encodeURIComponent, Set, String, Array });
  return { fetchScanPatches: exports.fetchScanPatches, calls };
}

test('scan patch history loads all pages, retaining older findings after refresh', async () => {
  const firstPage = Array.from({ length: 500 }, (_, i) => ({ id: `patch-${i}` }));
  const secondPage = [{ id: 'patch-500', finding_id: 'older-finding' }];
  const { fetchScanPatches, calls } = makeFetcher([firstPage, secondPage]);
  const result = await fetchScanPatches('scan-1');
  assert.equal(result.length, 501);
  assert.equal(result.at(-1).finding_id, 'older-finding');
  assert.equal(calls.length, 2);
  assert.ok(calls[1].includes('offset=500'));
});
test('duplicate persisted patches across pagination boundaries fail closed', async () => {
  const firstPage = Array.from({ length: 500 }, (_, i) => ({ id: `patch-${i}` }));
  const { fetchScanPatches } = makeFetcher([firstPage, [{ id: 'patch-499' }]]);
  await assert.rejects(fetchScanPatches('scan-1'), /Inconsistent patch history pagination/);
});
test('invalid patch page cannot be represented as an empty history', async () => {
  const { fetchScanPatches } = makeFetcher([Array.from({ length: 501 }, (_, i) => ({ id: `p${i}` }))]);
  await assert.rejects(fetchScanPatches('scan-1'), /Invalid patch history pagination/);
});
