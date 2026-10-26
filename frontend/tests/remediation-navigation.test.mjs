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
  const promise = new Promise((res, rej) => { resolve = res; reject = rej; });
  return { promise, resolve, reject };
}

function mount() {
  let findingId = 'first';
  const requests = new Map();
  const states = [];
  const effects = [];
  let hookIndex = 0;
  let pendingEffects = [];
  const jsx = (type, props) => ({ type, props });
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
      if (!states[index] || !same(states[index].deps, deps)) states[index] = { deps, callback };
      return states[index].callback;
    },
    useEffect(effect, deps) {
      const index = hookIndex++;
      if (!effects[index] || !same(effects[index].deps, deps)) {
        pendingEffects.push({ index, effect, deps });
      }
    },
  };
  function same(a, b) { return a && b && a.length === b.length && a.every((v, i) => v === b[i]); }
  const modules = {
    react,
    'react/jsx-runtime': { jsx, jsxs: jsx },
    'next/navigation': { useRouter: () => ({ push() {} }), useSearchParams: () => ({ get: () => findingId }) },
    '@/components/layout/AppShell': { AppShell: stub },
    '@/components/ui/Alert': { Alert: stub },
    '@/components/ui/Button': { Button: stub },
    '@/components/ui/EmptyState': { EmptyState: stub },
    '@/components/ui/Skeleton': { CardSkeleton: stub },
    '@/features/remediation/RemediationLifecycle': { RemediationLifecycle: lifecycle },
    '@/lib/api': { fetchFinding(id) { const d = deferred(); requests.set(id, d); return d.promise; } },
  };
  const code = ts.transpileModule(source + '\nexport { RemediationWorkspaceContent };', {
    compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022, jsx: ts.JsxEmit.ReactJSX },
  }).outputText;
  const exports = {};
  runInNewContext(code, { exports, require(name) { if (!(name in modules)) throw Error(name); return modules[name]; }, Error });
  const render = ({ flushEffects = true } = {}) => {
    hookIndex = 0;
    const element = exports.RemediationWorkspaceContent();
    if (flushEffects) {
      for (const next of pendingEffects) {
        effects[next.index]?.cleanup?.();
        effects[next.index] = { deps: next.deps, cleanup: next.effect() };
      }
      pendingEffects = [];
    }
    return element;
  };
  return { requests, render, setId(id) { findingId = id; }, lifecycle };
}

const settle = async () => { await Promise.resolve(); await Promise.resolve(); };

test('older finding response cannot replace a newer remediation route', async () => {
  const app = mount();
  app.render();
  app.setId('second');
  app.render();
  app.requests.get('second').resolve({ id: 'second', title: 'Second finding' });
  await settle();
  assert.equal(app.render().props.finding.id, 'second');
  app.requests.get('first').resolve({ id: 'first', title: 'First finding' });
  await settle();
  assert.equal(app.render().props.finding.id, 'second');
});

test('changing route never renders the previous finding while new request is pending', async () => {
  const app = mount();
  app.render();
  app.requests.get('first').resolve({ id: 'first', title: 'First finding' });
  await settle();
  assert.equal(app.render().props.finding.id, 'first');
  app.setId('second');
  const element = app.render({ flushEffects: false });
  assert.notEqual(element.type, app.lifecycle);
});

test('late failure from an old finding does not hide the current finding', async () => {
  const app = mount();
  app.render();
  app.setId('second');
  app.render();
  app.requests.get('second').resolve({ id: 'second', title: 'Second finding' });
  await settle();
  app.requests.get('first').reject(new Error('Old finding is unavailable'));
  await settle();
  assert.equal(app.render().props.finding.id, 'second');
});

test('retry after a failed finding fetch restores only the requested finding', async () => {
  const app = mount();
  app.render();
  app.requests.get('first').reject(new Error('Temporary outage'));
  await settle();
  const errorView = app.render();
  assert.equal(errorView.type, 'div');
  const retry = errorView.props.children[1];
  retry.props.onClick();
  app.requests.get('first').resolve({ id: 'first', title: 'Recovered finding' });
  await settle();
  assert.equal(app.render().props.finding.id, 'first');
});
