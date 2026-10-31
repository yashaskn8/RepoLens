import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import ts from 'typescript';

// Run the actual typed download callback, rather than trying to evaluate TS as JS.
const source = readFileSync(new URL('../src/features/change-analysis/ChangeAnalysisWorkspace.tsx', import.meta.url), 'utf8');
const start = source.indexOf('  const handleDownloadMarkdown = async');
const end = source.indexOf('  const handleCopyMarkdown =', start);
assert.ok(start >= 0 && end > start, 'report download handler must exist');
const handlerSource = ts.transpileModule(source.slice(start, end), {
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.None },
}).outputText;

function deferred() {
  let resolve;
  const promise = new Promise(done => { resolve = done; });
  return { promise, resolve };
}

function fixture() {
  const pending = deferred();
  const generation = { current: 1 };
  const lock = { current: false };
  const abort = { current: null };
  const events = [];
  const timeouts = new Map();
  let nextTimeout = 0;
  const url = {
    createObjectURL() { events.push('create'); return 'blob:test'; },
    revokeObjectURL() { events.push('revoke'); },
  };
  const document = {
    body: { appendChild() {}, removeChild() {} },
    createElement() { return { click() { events.push('click'); } }; },
  };
  const handleDownloadMarkdown = new Function(
    'activeAnalysis', 'analysisGenerationRef', 'downloadPendingRef', 'downloadAbortRef',
    'downloadChangeAnalysisMarkdown', 'setIsDownloading', 'setDownloadError',
    'Blob', 'URL', 'document', 'setTimeout', 'clearTimeout', 'AbortController',
    handlerSource + '\nreturn handleDownloadMarkdown;',
  )(
    { id: 'analysis-A', status: 'COMPLETED' }, generation, lock, abort,
    () => pending.promise, () => {}, () => {},
    class Blob {}, url, document,
    (callback) => { const id = ++nextTimeout; timeouts.set(id, callback); return id; },
    id => timeouts.delete(id), AbortController,
  );
  return { pending, generation, lock, abort, events, handleDownloadMarkdown, timeouts };
}

test('obsolete analysis response cannot download the prior analysis report', async () => {
  const f = fixture();
  const download = f.handleDownloadMarkdown();
  f.generation.current += 1;
  f.pending.resolve('# Confidential report from old analysis');
  await download;
  assert.deepEqual(f.events, []);
  assert.equal(f.timeouts.size, 0);
});

test('current analysis can still download its report', async () => {
  const f = fixture();
  const download = f.handleDownloadMarkdown();
  f.pending.resolve('# Current report');
  await download;
  assert.deepEqual(f.events, ['create', 'click', 'revoke']);
  assert.equal(f.lock.current, false);
  assert.equal(f.timeouts.size, 0);
});

test('workspace unmount invalidates pending generation-guarded callbacks and aborts download', () => {
  assert.match(source, /useEffect\(\(\) => \(\) => \{[\s\S]*analysisGenerationRef\.current \+= 1;[\s\S]*downloadAbortRef\.current\?\.abort\(\);[\s\S]*\}, \[\]\)/);
});
