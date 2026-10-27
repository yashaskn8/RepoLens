import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import ts from 'typescript';

const workspace = readFileSync(new URL('../src/features/change-analysis/ChangeAnalysisWorkspace.tsx', import.meta.url), 'utf8');
const panel = readFileSync(new URL('../src/features/review/ReviewReportPanel.tsx', import.meta.url), 'utf8');
const start = workspace.indexOf('  const handleCopyMarkdown =');
const end = workspace.indexOf('  const handleGeneratePreview =', start);
assert.ok(start >= 0 && end > start, 'report copy handler must exist');
const compiled = ts.transpileModule(workspace.slice(start, end), {
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.None },
}).outputText;

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}

function fixture(writeText) {
  const state = { copied: false, error: null };
  const generation = { current: 1 };
  const copySequence = { current: 0 };
  const timers = [];
  const handler = new Function(
    'report', 'analysisGenerationRef', 'copySequenceRef',
    'setCopiedReport', 'setCopyError', 'navigator', 'setTimeout',
    compiled + '\nreturn handleCopyMarkdown;',
  )(
    { markdown_report: '# verified report' }, generation, copySequence,
    value => { state.copied = value; }, value => { state.error = value; },
    { clipboard: { writeText } }, callback => timers.push(callback),
  );
  return { handler, state, generation, timers };
}

test('copy success appears only after the clipboard confirms the write', async () => {
  const pending = deferred();
  const f = fixture(() => pending.promise);
  const action = f.handler();
  assert.equal(f.state.copied, false);
  pending.resolve();
  await action;
  assert.equal(f.state.copied, true);
  assert.equal(f.state.error, null);
  f.timers[0]();
  assert.equal(f.state.copied, false);
});

test('clipboard rejection is reported instead of falsely claiming success', async () => {
  const f = fixture(async () => { throw new Error('permission denied'); });
  await f.handler();
  assert.equal(f.state.copied, false);
  assert.match(f.state.error, /Could not copy/);
  assert.match(panel, /Clipboard unavailable/);
});

test('obsolete analysis cannot show a delayed clipboard success', async () => {
  const pending = deferred();
  const f = fixture(() => pending.promise);
  const action = f.handler();
  f.generation.current += 1;
  pending.resolve();
  await action;
  assert.equal(f.state.copied, false);
});

test('a previous copy timer cannot clear a newer success indication', async () => {
  const f = fixture(async () => {});
  await f.handler();
  const firstTimer = f.timers[0];
  await f.handler();
  firstTimer();
  assert.equal(f.state.copied, true);
  f.timers[1]();
  assert.equal(f.state.copied, false);
});
