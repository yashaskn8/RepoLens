import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { runInNewContext } from 'node:vm';
import ts from 'typescript';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const helperSource = readFileSync(join(root, 'src/lib/findingsPagination.ts'), 'utf8');
const pageSource = readFileSync(join(root, 'src/app/findings/page.tsx'), 'utf8');

function transpile(source) {
  return ts.transpileModule(source, {
    compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
  }).outputText;
}

const exports = {};
runInNewContext(transpile(helperSource), { exports, Promise, Number, Error, Array });
const { loadScanFindingsPage } = exports;

const start = pageSource.indexOf('  const retryFailedFindings = useCallback(async () => {');
const endMarker = '  }, [accountId, user?.id, authLoading, loadedForAccount, loading, loadingMore, failedScanIds]);';
const end = pageSource.indexOf(endMarker, start);
assert.ok(start >= 0 && end > start, 'findings recovery callback must be present');
const callback = pageSource.slice(start, end + endMarker.length);

function makeRetry({ failedIds = ['missing'], fetch = async () => [], findings = [], account = 'alice', loadingMore = false } = {}) {
  const context = {
    Promise, Set, Array,
    failedFindingsRetryPending: { current: false },
    olderPagePending: { current: false },
    requestGeneration: { current: 1 },
    accountId: account,
    loadedForAccount: account,
    user: { id: account },
    authLoading: false,
    loading: false,
    loadingMore,
    failedScanIds: failedIds,
    findings,
    retrying: false,
    fetchScanFindings: fetch,
    isCurrentAccountResponse: (expected, actual, generation, current) =>
      expected === actual && generation === current,
    useCallback: (fn) => fn,
  };
  context.setRetryingFailedFindings = (value) => { context.retrying = value; };
  context.setFindings = (update) => { context.findings = update(context.findings); };
  context.setFailedScanIds = (update) => { context.failedScanIds = update(context.failedScanIds); };
  runInNewContext(transpile(callback + '\nglobalThis.retry = retryFailedFindings;'), context);
  return context;
}

test('failed scan IDs survive a partially successful page, in scan order', async () => {
  const page = await loadScanFindingsPage(
    0, 3,
    async () => [{ id: 'ok' }, { id: 'failed-a' }, { id: 'failed-b' }],
    async (id) => { if (id.startsWith('failed')) throw Error('offline'); return [{ id: 'f1' }]; },
  );
  assert.deepEqual(Array.from(page.failedScanIds), ['failed-a', 'failed-b']);
  assert.equal(page.failedCount, 2);
  assert.equal(page.scanCount, 3);
  assert.equal(page.findings.length, 1);
});

test('retry merges recovered evidence without duplicating existing findings', async () => {
  const ctx = makeRetry({
    failedIds: ['scan-a', 'scan-b'],
    findings: [{ id: 'existing' }],
    fetch: async (id) => [{ id: id === 'scan-a' ? 'existing' : 'recovered' }],
  });
  await ctx.retry();
  assert.deepEqual(ctx.findings.map((finding) => finding.id), ['existing', 'recovered']);
  assert.deepEqual(Array.from(ctx.failedScanIds), []);
  assert.equal(ctx.retrying, false);
});

test('retry retains only scan IDs that still fail', async () => {
  const ctx = makeRetry({
    failedIds: ['a', 'b'],
    fetch: async (id) => { if (id === 'b') throw Error('offline'); return [{ id: 'ok' }]; },
  });
  await ctx.retry();
  assert.deepEqual(Array.from(ctx.failedScanIds), ['b']);
  assert.equal(ctx.findings.length, 1);
});

test('same-render retry clicks issue only one request', async () => {
  let release;
  let calls = 0;
  const ctx = makeRetry({
    fetch: () => { calls++; return new Promise((resolve) => { release = resolve; }); },
  });
  const first = ctx.retry();
  const second = ctx.retry();
  assert.equal(calls, 1);
  release([{ id: 'recovered' }]);
  await Promise.all([first, second]);
  assert.equal(ctx.findings.length, 1);
});

test('obsolete account response cannot insert findings or mutate missing IDs', async () => {
  let release;
  const ctx = makeRetry({
    fetch: () => new Promise((resolve) => { release = resolve; }),
  });
  const pending = ctx.retry();
  ctx.requestGeneration.current++;
  ctx.user.id = 'bob';
  release([{ id: 'private-finding' }]);
  await pending;
  assert.equal(ctx.findings.length, 0);
  assert.deepEqual(Array.from(ctx.failedScanIds), ['missing']);
});

test('retry does not overlap older-scan pagination', async () => {
  let calls = 0;
  const ctx = makeRetry({ loadingMore: true, fetch: async () => { calls++; return []; } });
  await ctx.retry();
  assert.equal(calls, 0);
});
