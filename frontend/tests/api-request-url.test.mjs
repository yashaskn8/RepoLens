import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { runInNewContext } from 'node:vm';
import ts from 'typescript';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const content = readFileSync(join(root, 'src/lib/apiRequestUrl.ts'), 'utf8');
const code = ts.transpileModule(content, {
  compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
}).outputText;
const exports = {};
runInNewContext(code, { exports, Error, RegExp, String });
const { buildApiRequestUrl } = exports;

test('application-relative API paths keep the configured origin', () => {
  assert.equal(
    buildApiRequestUrl('http://localhost:8000', '/api/v1/auth/me'),
    'http://localhost:8000/api/v1/auth/me',
  );
  assert.equal(
    buildApiRequestUrl('https://api.example.com', '/health'),
    'https://api.example.com/health',
  );
});
test('absolute and protocol-relative URLs cannot receive a CSRF header', () => {
  for (const input of [
    'https://attacker.example/collect',
    'http://localhost:8000/api/v1/auth/me',
    '//attacker.example/collect',
    'javascript:alert(1)',
    'api/v1/auth/me',
    '/\\attacker.example',
    '/api/v1/auth/me\nX-Evil: true',
  ]) {
    assert.throws(() => buildApiRequestUrl('https://api.example.com', input),
      /application-relative API request paths/);
  }
});
test('shared API wrapper must call the guarded request URL builder', () => {
  const api = readFileSync(join(root, 'src/lib/api.ts'), 'utf8');
  assert.match(api, /const url = buildApiRequestUrl\(getApiBaseUrl\(\), input\);/);
  assert.doesNotMatch(api, /input\.startsWith\('http'\)/);
});
