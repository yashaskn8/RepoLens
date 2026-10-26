import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { runInNewContext } from 'node:vm';
import ts from 'typescript';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const source = readFileSync(join(root, 'src/app/remediation/page.tsx'), 'utf8');

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}

function mount({ account = 'account-A', authLoading = false } = {}) {
  let userId = account;
  let loadingAuth = authLoading;
  const requests = [];
  const states = [];
  const effects = [];
  let hookIndex = 0;
  let pendingEffects = [];
  const same = (a, b) => a && b && a.length === b.length && a.every((value, i) => value === b[i]);
  const jsx = (type, props, key) => ({ type, props: props || {}, key });
  const lifecycle = () => null;
  const stub = () => null;
  const react = {
    useState(initial) {
      const index = hookIndex++;
      if (!(index in states)) states[index] = initial;
      return [states[index], (value) => { states[index] = typeof value === 'function' ? value(states[index]) : value; }];
    },
    useRef(initial) {
      const index = hookIndex++;
      if (!(index in states)) states[index] = { current: initial };
      return states[index];
    },
    useCallback(callback, deps) {
      const index = hookIndex++;
      if (!states[index] || !same(states[index].deps, deps)) states[index] = { callback, deps };
      return states[index].callback;
    },
    useEffect(effect, deps) {
      const index = hookIndex++;
      if (!effects[index] || !same(effects[index].deps, deps)) {
        pendingEffects = pendingEffects.filter((pending) => pending.index !== index);
        pendingEffects.push({ index, effect, deps });
      }
    },
  };
  const modules = {
    react,
    'react/jsx-runtime': { jsx, jsxs: jsx },
    'next/navigation': { useRouter: () => ({ push() {} }), useSearchParams: () => ({ get: () => 'finding-1' }) },
    '@/context/AuthContext': { useAuth: () => ({ user: userId ? { id: userId } : null, isLoading: loadingAuth }) },
    '@/components/layout/AppShell': { AppShell: stub },
    '@/components/ui/Alert': { Alert: stub },
    '@/components/ui/Button': { Button: stub },
    '@/components/ui/EmptyState': { EmptyState: stub },
    '@/components/ui/Skeleton': { CardSkeleton: stub },
    '@/features/remediation/RemediationLifecycle': { RemediationLifecycle: lifecycle },
    '@/lib/api': {
      fetchFinding(id) {
        const request = { account: userId, id, ...deferred() };
        requests.push(request);
        return request.promise;
      },
    },
  };
  const code = ts.transpileModule(source + '\nexport { RemediationWorkspaceContent };', {
    compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022, jsx: ts.JsxEmit.ReactJSX },
  }).outputText;
  const exports = {};
  runInNewContext(code, {
    exports,
    require(name) { if (!(name in modules)) throw Error('Unexpected dependency: ' + name); return modules[name]; },
    Error,
  });
  function render({ flushEffects = true } = {}) {
    hookIndex = 0;
    const tree = exports.RemediationWorkspaceContent();
    if (flushEffects) {
      for (const effect of pendingEffects) {
        effects[effect.index]?.cleanup?.();
        effects[effect.index] = { deps: effect.deps, cleanup: effect.effect() };
      }
      pendingEffects = [];
    }
    return tree;
  }
  return {
    render, requests, lifecycle,
    setAccount(id) { userId = id; },
    setAuthLoading(value) { loadingAuth = value; },
  };
}

const settle = async () => { await Promise.resolve(); await Promise.resolve(); };

test('logout immediately removes another account remediation controls, even before effects', async () => {
  const app = mount();
  app.render();
  app.requests[0].resolve({ id: 'finding-1', title: 'Private finding' });
  await settle();
  assert.equal(app.render().type, app.lifecycle);

  app.setAccount(null);
  assert.notEqual(app.render({ flushEffects: false }).type, app.lifecycle);
  app.render();
  assert.equal(app.requests.length, 1, 'logged-out workspace must not fetch private findings');
});

test('switching accounts refetches the same finding and keys its lifecycle to the account', async () => {
  const app = mount();
  app.render();
  app.requests[0].resolve({ id: 'finding-1', title: 'Account A finding' });
  await settle();
  const original = app.render();
  assert.equal(original.type, app.lifecycle);

  app.setAccount('account-B');
  assert.notEqual(app.render({ flushEffects: false }).type, app.lifecycle);
  app.render();
  assert.equal(app.requests.length, 2);
  assert.equal(app.requests[1].account, 'account-B');
  app.requests[1].resolve({ id: 'finding-1', title: 'Account B finding' });
  await settle();
  const updated = app.render();
  assert.equal(updated.type, app.lifecycle);
  assert.equal(updated.props.finding.title, 'Account B finding');
  assert.notEqual(updated.key, original.key);
});

test('a previous account pending response cannot publish a remediation workspace', async () => {
  const app = mount();
  app.render();
  app.setAccount('account-B');
  app.render();
  assert.equal(app.requests.length, 2);
  app.requests[0].resolve({ id: 'finding-1', title: 'Account A finding' });
  await settle();
  assert.notEqual(app.render().type, app.lifecycle);
  app.requests[1].resolve({ id: 'finding-1', title: 'Account B finding' });
  await settle();
  assert.equal(app.render().props.finding.title, 'Account B finding');
});

test('authentication initialization does not request or display tenant data', async () => {
  const app = mount({ account: null, authLoading: true });
  assert.notEqual(app.render().type, app.lifecycle);
  assert.equal(app.requests.length, 0);
  app.setAuthLoading(false);
  app.render();
  assert.equal(app.requests.length, 0);
  app.setAccount('account-A');
  app.render();
  assert.equal(app.requests.length, 1);
  app.requests[0].resolve({ id: 'finding-1', title: 'Account A finding' });
  await settle();
  assert.equal(app.render().type, app.lifecycle);
});
