import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { runInNewContext } from 'node:vm';
import ts from 'typescript';

// Compile only the actual exported function, so these checks exercise the
// frontend source without loading its browser-only and API dependencies.
const root = dirname(dirname(fileURLToPath(import.meta.url)));
const source = readFileSync(join(root, 'src/lib/api.ts'), 'utf8');
const parsed = ts.createSourceFile('api.ts', source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
const declaration = parsed.statements.find(
  (statement) => ts.isFunctionDeclaration(statement) && statement.name?.text === 'getApiBaseUrl',
);
assert.ok(declaration, 'getApiBaseUrl must remain defined');
const compiled = ts.transpileModule(declaration.getText(parsed), {
  compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
}).outputText;

function resolveApiBaseUrl({ host, configured, environment = 'development' }) {
  const exports = {};
  const sandbox = {
    exports,
    URL,
    process: {
      env: {
        NODE_ENV: environment,
        ...(configured === undefined ? {} : { NEXT_PUBLIC_API_BASE_URL: configured }),
      },
    },
    ...(host === undefined
      ? {}
      : { window: { location: { hostname: host, protocol: 'http:' } } }),
  };
  runInNewContext(compiled, sandbox);
  return exports.getApiBaseUrl();
}

test('development aligns a configured localhost API with a 127.0.0.1 frontend', () => {
  assert.equal(
    resolveApiBaseUrl({ host: '127.0.0.1', configured: 'http://localhost:8000' }),
    'http://127.0.0.1:8000',
  );
});

test('development aligns configured 127.0.0.1 API with a localhost frontend', () => {
  assert.equal(
    resolveApiBaseUrl({ host: 'localhost', configured: 'http://127.0.0.1:8000' }),
    'http://localhost:8000',
  );
});

test('development preserves a configured loopback API path', () => {
  assert.equal(
    resolveApiBaseUrl({ host: '127.0.0.1', configured: 'http://localhost:8000/gateway' }),
    'http://127.0.0.1:8000/gateway',
  );
});

test('remote development API origins and lookalike hosts remain unchanged', () => {
  for (const configured of [
    'https://api.dev.example.com',
    'http://localhost.attacker.example:8000',
  ]) {
    assert.equal(resolveApiBaseUrl({ host: '127.0.0.1', configured }), configured);
  }
});

test('default development API follows the browser hostname', () => {
  assert.equal(resolveApiBaseUrl({ host: '127.0.0.1' }), 'http://127.0.0.1:8000');
  assert.equal(resolveApiBaseUrl({ host: 'localhost' }), 'http://localhost:8000');
  assert.equal(resolveApiBaseUrl({}), 'http://localhost:8000');
});

test('production API security validation is unchanged', () => {
  assert.equal(
    resolveApiBaseUrl({ environment: 'production', configured: 'https://api.example.com' }),
    'https://api.example.com',
  );
  assert.throws(
    () => resolveApiBaseUrl({ environment: 'production', configured: 'http://localhost:8000' }),
    /credential-free HTTPS origin/,
  );
});
