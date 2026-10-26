import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import ts from 'typescript';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const source = readFileSync(join(root, 'src/app/change-analysis/page.tsx'), 'utf8');
const effectStart = source.indexOf('// Recent analyses and in-flight submissions');
const handlerStart = source.indexOf('  const handleSubmit = async', effectStart);
const jsxStart = source.indexOf('  return (', handlerStart);
assert.ok(effectStart >= 0 && handlerStart > effectStart && jsxStart > handlerStart);

const effectSource = source.slice(effectStart, handlerStart);
const effectBody = effectSource.match(/useEffect\\(\\(\\) => \\{([\\s\\S]*?)\\}, \\[accountId, authLoading\\]\\);/);
assert.ok(effectBody, 'private history must reload on account and session changes');

function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
async function flush() {
  await Promise.resolve();
  await Promise.resolve();
  await Promise.resolve();
}

function historyFixture(accountId, authLoading = false) {
  const request = deferred();
  const state = { history: ['old-private-result'], loaded: 'old-tenant', loading: false, error: 'old error', submitting: true };
  const listGeneration = { current: 0 };
  const submitGeneration = { current: 0 };
  const submitPending = { current: true };
  const activeAccountRef = { current: authLoading ? null : accountId };
  const run = new Function(
    'accountId', 'authLoading', 'listGeneration', 'submitGeneration', 'submitPending',
    'setRecentAnalyses', 'setLoadedForAccount', 'setError', 'setIsSubmitting',
    'setIsLoadingRecent', 'listChangeAnalyses', 'isCurrentAccountResponse', 'activeAccountRef',
    effectBody[1],
  );
  const cleanup = run(
    accountId, authLoading, listGeneration, submitGeneration, submitPending,
    value => { state.history = value; }, value => { state.loaded = value; },
    value => { state.error = value; }, value => { state.submitting = value; },
    value => { state.loading = value; }, () => request.promise,
    (requested, active, generation, current) => Boolean(requested && requested === active && generation === current),
    activeAccountRef,
  );
  return { state, request, cleanup, listGeneration, submitGeneration, submitPending, activeAccountRef };
}

test('logout clears history and does not fetch private analyses', () => {
  const run = historyFixture(null);
  assert.deepEqual(run.state.history, []);
  assert.equal(run.state.loaded, null);
  assert.equal(run.state.loading, false);
  assert.equal(run.submitPending.current, false);
});

test('old tenant history cannot be restored after account change', async () => {
  const run = historyFixture('tenant-A');
  assert.deepEqual(run.state.history, []);
  run.activeAccountRef.current = 'tenant-B';
  run.cleanup();
  run.request.resolve([{ id: 'tenant-A-private' }]);
  await flush();
  assert.deepEqual(run.state.history, []);
  assert.equal(run.state.loaded, null);
});

test('current tenant history is published only after its request completes', async () => {
  const run = historyFixture('tenant-B');
  assert.equal(run.state.loading, true);
  run.request.resolve([{ id: 'tenant-B-private' }]);
  await flush();
  assert.deepEqual(run.state.history, [{ id: 'tenant-B-private' }]);
  assert.equal(run.state.loaded, 'tenant-B');
  assert.equal(run.state.loading, false);
});

test('failed old-account request cannot replace current-account history', async () => {
  const run = historyFixture('tenant-A');
  run.activeAccountRef.current = 'tenant-B';
  run.cleanup();
  run.request.reject(new Error('old-account failure'));
  await flush();
  assert.equal(run.state.error, null);
  assert.equal(run.state.loaded, null);
});

const submitJs = ts.transpileModule(source.slice(handlerStart, jsxStart), {
  compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
}).outputText;
function submitFixture() {
  const request = deferred();
  const state = { account: 'tenant-A', errors: [], submitting: false, navigations: [], calls: 0 };
  const activeAccountRef = { current: state.account };
  const submitGeneration = { current: 0 };
  const submitPending = { current: false };
  const handleSubmit = new Function(
    'accountId', 'authLoading', 'submitGeneration', 'submitPending', 'activeAccountRef',
    'setError', 'setIsSubmitting', 'mode', 'prUrl', 'repoUrl', 'baseRef', 'headRef',
    'startChangeAnalysisFromPR', 'startChangeAnalysis', 'isCurrentAccountResponse', 'router', 'getErrorMessage',
    submitJs + '\\nreturn handleSubmit;',
  )(
    state.account, false, submitGeneration, submitPending, activeAccountRef,
    value => { state.errors.push(value); }, value => { state.submitting = value; },
    'pr', 'https://github.com/org/repo/pull/1', '', '', '',
    () => { state.calls++; return request.promise; },
    () => { throw new Error('wrong mode'); },
    (requested, active, generation, current) => Boolean(requested && requested === active && generation === current),
    { push: path => state.navigations.push(path) },
    error => error.message,
  );
  return { state, request, activeAccountRef, submitGeneration, submitPending, handleSubmit };
}

test('submission result from previous account never navigates to private analysis', async () => {
  const run = submitFixture();
  const pending = run.handleSubmit({ preventDefault() {} });
  run.activeAccountRef.current = 'tenant-B';
  run.submitGeneration.current++;
  run.request.resolve({ id: 'tenant-A-private' });
  await pending;
  assert.deepEqual(run.state.navigations, []);
  assert.equal(run.state.calls, 1);
});

test('duplicate submissions are blocked before React re-renders', async () => {
  const run = submitFixture();
  const first = run.handleSubmit({ preventDefault() {} });
  await run.handleSubmit({ preventDefault() {} });
  assert.equal(run.state.calls, 1);
  run.request.resolve({ id: 'current-analysis' });
  await first;
  assert.deepEqual(run.state.navigations, ['/changes/current-analysis']);
  assert.equal(run.submitPending.current, false);
});

test('UI never displays prior account history while a new account loads', () => {
  assert.match(source, /loadedForAccount === accountId/);
  assert.match(source, /visibleRecentAnalyses\\.map/);
  assert.match(source, /displayRecentLoading/);
  assert.match(source, /disabled=\\{authLoading \\|\\| !accountId \\|\\| isSubmitting\\}/);
});
