import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import ts from 'typescript';

const source = readFileSync(new URL('../src/features/change-analysis/ChangeAnalysisWorkspace.tsx', import.meta.url), 'utf8');
const apiSource = readFileSync(new URL('../src/lib/api.ts', import.meta.url), 'utf8');
const statusSource = readFileSync(new URL('../src/features/change-analysis/ChangeAnalysisStatus.tsx', import.meta.url), 'utf8');
const start = source.indexOf('  const handleDownloadMarkdown = async () => {');
const end = source.indexOf('  const handleCopyMarkdown = async () => {', start);
assert.ok(start >= 0 && end > start, 'report download handler must exist');
const compiled = ts.transpileModule(source.slice(start, end), {
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.None },
}).outputText;

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((done, fail) => { resolve = done; reject = fail; });
  return { promise, resolve, reject };
}

function fixture({ download = async () => '# report', click = () => {} } = {}) {
  const state = { downloading: false, error: null, clicks: 0, appended: 0, removed: 0, revoked: 0, blobs: [] };
  const generation = { current: 1 };
  const pending = { current: false };
  const abort = { current: null };
  const calls = [];
  const timers = new Map();
  let nextTimer = 0;
  const handler = new Function(
    'activeAnalysis', 'analysisGenerationRef', 'downloadPendingRef', 'downloadAbortRef',
    'setIsDownloading', 'setDownloadError', 'downloadChangeAnalysisMarkdown',
    'Blob', 'URL', 'document', 'setTimeout', 'clearTimeout',
    compiled + '\nreturn handleDownloadMarkdown;',
  )(
    { id: 'analysis-A', status: 'COMPLETED' }, generation, pending, abort,
    value => { state.downloading = value; }, value => { state.error = value; },
    (id, signal) => { calls.push({ id, signal }); return download(id, signal); },
    class { constructor(parts, options) { state.blobs.push({ parts, options }); } },
    { createObjectURL: () => 'blob:test', revokeObjectURL: () => { state.revoked++; } },
    { createElement: () => ({ click() { state.clicks++; click(); } }),
      body: { appendChild() { state.appended++; }, removeChild() { state.removed++; } } },
    (callback, delay) => {
      assert.equal(delay, 15_000);
      const id = ++nextTimer;
      timers.set(id, callback);
      return id;
    },
    id => timers.delete(id),
  );
  return {
    state, generation, pending, abort, calls, handler,
    timers: () => timers.size,
    expire: () => { for (const callback of [...timers.values()]) callback(); },
  };
}

test('hung report download times out, aborts, reports failure and unlocks retry', async () => {
  const stalled = deferred();
  const f = fixture({ download: () => stalled.promise });
  const first = f.handler();
  assert.equal(f.pending.current, true);
  assert.equal(f.state.downloading, true);
  assert.equal(f.timers(), 1);
  f.expire();
  await first;
  assert.equal(f.calls[0].signal.aborted, true);
  assert.match(f.state.error, /download failed or timed out/i);
  assert.equal(f.pending.current, false);
  assert.equal(f.state.downloading, false);
  assert.equal(f.timers(), 0);
  stalled.resolve('# too late');
  await Promise.resolve();
  assert.equal(f.state.clicks, 0);
});

test('synchronous duplicate clicks start only one download and success cleans up', async () => {
  const slow = deferred();
  const f = fixture({ download: () => slow.promise });
  const first = f.handler();
  await f.handler();
  assert.equal(f.calls.length, 1);
  slow.resolve('# ready');
  await first;
  assert.equal(f.state.clicks, 1);
  assert.equal(f.state.appended, 1);
  assert.equal(f.state.removed, 1);
  assert.equal(f.state.revoked, 1);
  assert.equal(f.state.blobs[0].parts[0], '# ready');
  assert.equal(f.state.error, null);
  assert.equal(f.timers(), 0);
  await f.handler();
  assert.equal(f.calls.length, 2, 'successful completion unlocks subsequent download');
});

test('network error reports retryable failure and releases the lock', async () => {
  let attempts = 0;
  const f = fixture({ download: async () => {
    if (++attempts === 1) throw new Error('offline');
    return '# recovered';
  } });
  await f.handler();
  assert.match(f.state.error, /download failed or timed out/i);
  assert.equal(f.pending.current, false);
  assert.equal(f.timers(), 0);
  await f.handler();
  assert.equal(f.state.error, null);
  assert.equal(f.state.clicks, 1);
});

test('obsolete successful download cannot click or release a newer lock', async () => {
  const slow = deferred();
  const f = fixture({ download: () => slow.promise });
  const first = f.handler();
  f.generation.current = 2;
  f.pending.current = true;
  slow.resolve('# previous account');
  await first;
  assert.equal(f.state.clicks, 0);
  assert.equal(f.pending.current, true);
  assert.equal(f.timers(), 0);
});

test('obsolete failure cannot display an error in a newer analysis', async () => {
  const slow = deferred();
  const f = fixture({ download: () => slow.promise });
  const first = f.handler();
  f.generation.current = 2;
  f.pending.current = true;
  slow.reject(new Error('old request failed'));
  await first;
  assert.equal(f.state.error, null);
  assert.equal(f.pending.current, true);
});

test('browser download failure still removes link and revokes blob URL', async () => {
  const f = fixture({ click: () => { throw new Error('download denied'); } });
  await f.handler();
  assert.equal(f.state.appended, 1);
  assert.equal(f.state.removed, 1);
  assert.equal(f.state.revoked, 1);
  assert.match(f.state.error, /download failed or timed out/i);
});

test('Markdown API forwards cancellation and workspace renders retryable feedback', () => {
  const apiStart = apiSource.indexOf('export async function downloadChangeAnalysisMarkdown(');
  const apiEnd = apiSource.indexOf('\n}', apiStart);
  assert.ok(apiStart >= 0 && apiEnd > apiStart);
  const getter = apiSource.slice(apiStart, apiEnd);
  assert.match(getter, /signal\?: AbortSignal/);
  assert.match(getter, /cache: 'no-store',\s*signal,/);
  assert.match(source, /downloadChangeAnalysisMarkdown\(analysisId, controller.signal\)/);
  assert.match(source, /title="Report download unavailable"/);
  assert.match(source, /isDownloading=\{isDownloading\}/);
  assert.match(statusSource, /disabled=\{isDownloading\}/);
});
