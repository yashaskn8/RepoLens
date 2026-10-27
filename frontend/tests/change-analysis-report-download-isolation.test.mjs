import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const source = readFileSync(new URL('../src/features/change-analysis/ChangeAnalysisWorkspace.tsx', import.meta.url), 'utf8');
const start = source.indexOf('  const handleDownloadMarkdown = async');
const end = source.indexOf('  const handleCopyMarkdown =', start);
assert.ok(start >= 0 && end > start, 'report download handler must exist');
const handlerSource = source.slice(start, end);

function deferred() {
  let resolve;
  const promise = new Promise(done => { resolve = done; });
  return { promise, resolve };
}

function fixture() {
  const pending = deferred();
  const generation = { current: 1 };
  const events = [];
  const url = {
    createObjectURL() { events.push('create'); return 'blob:test'; },
    revokeObjectURL() { events.push('revoke'); },
  };
  const document = {
    body: { appendChild() {}, removeChild() {} },
    createElement() { return { click() { events.push('click'); } }; },
  };
  const handleDownloadMarkdown = new Function(
    'activeAnalysis', 'analysisGenerationRef', 'downloadChangeAnalysisMarkdown',
    'Blob', 'URL', 'document', 'console',
    handlerSource + '\nreturn handleDownloadMarkdown;',
  )(
    { id: 'analysis-A' }, generation, () => pending.promise,
    class Blob {}, url, document, { error() {} },
  );
  return { pending, generation, events, handleDownloadMarkdown };
}

test('obsolete analysis response cannot download the prior analysis report', async () => {
  const f = fixture();
  const download = f.handleDownloadMarkdown();
  f.generation.current += 1;
  f.pending.resolve('# Confidential report from old analysis');
  await download;
  assert.deepEqual(f.events, []);
});

test('current analysis can still download its report', async () => {
  const f = fixture();
  const download = f.handleDownloadMarkdown();
  f.pending.resolve('# Current report');
  await download;
  assert.deepEqual(f.events, ['create', 'click', 'revoke']);
});

test('workspace unmount invalidates pending generation-guarded callbacks', () => {
  assert.match(source, /useEffect\(\(\) => \(\) => \{ analysisGenerationRef\.current \+= 1; \}, \[\]\)/);
});
