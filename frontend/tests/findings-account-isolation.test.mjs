import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { runInNewContext } from 'node:vm';
import ts from 'typescript';
const root = dirname(dirname(fileURLToPath(import.meta.url)));
const source = readFileSync(join(root, 'src/lib/accountRequest.ts'), 'utf8');
const compiled = ts.transpileModule(source, {compilerOptions:{
  module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022,
}}).outputText;
const exports = {};
runInNewContext(compiled, {exports, Boolean});
const {isCurrentAccountResponse} = exports;

test('tenant switch and logout invalidate old asynchronous findings responses', () => {
  assert.equal(isCurrentAccountResponse('tenant-A','tenant-A',5,5),true);
  assert.equal(isCurrentAccountResponse('tenant-A','tenant-B',5,5),false);
  assert.equal(isCurrentAccountResponse('tenant-A',null,5,5),false);
  assert.equal(isCurrentAccountResponse(null,null,5,5),false);
});
test('a refreshed request invalidates earlier findings and older-scan pages', () => {
  assert.equal(isCurrentAccountResponse('tenant-A','tenant-A',5,6),false);
});
test('findings page guards both loaded pages and clears tenant-scoped state', () => {
  const page=readFileSync(join(root,'src/app/findings/page.tsx'),'utf8');
  assert.match(page,/const \{ user, isLoading: authLoading \} = useAuth\(\)/);
  assert.match(page,/requestGeneration\.current \+= 1/);
  assert.match(page,/setFindings\(\[\]\)/);
  assert.match(page,/isCurrentAccountResponse\(/);
  assert.match(page,/loadedForAccount === accountId/);
});
