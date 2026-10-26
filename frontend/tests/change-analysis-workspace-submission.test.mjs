import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import test from 'node:test';
import ts from 'typescript';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const source = readFileSync(join(root, 'src/features/change-analysis/ChangeAnalysisWorkspace.tsx'), 'utf8');
const helper = readFileSync(join(root, 'src/lib/exactChangeCommits.ts'), 'utf8');
const start = source.indexOf('  const handleStartAnalysis =');
const end = source.indexOf('  const handleDownloadMarkdown =', start);
assert.ok(start > 0 && end > start);
const js = ts.transpileModule(source.slice(start, end), {
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.None },
}).outputText;
const helperJs = ts.transpileModule(helper.replace('export interface ExactChangeCommits', 'interface ExactChangeCommits').replace('export function parseExactChangeCommits', 'function parseExactChangeCommits'), {
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.None },
}).outputText;
const parseExactChangeCommits = new Function(helperJs + '\nreturn parseExactChangeCommits;')();

function makeHarness({ mode = 'EXACT', base = 'a'.repeat(40), head = 'B'.repeat(40), submit } = {}) {
  const calls = [];
  const errors = [];
  const pending = { current: false };
  const noop = () => {};
  const deps = {
    submitPendingRef: pending,
    analysisGenerationRef: { current: 0 },
    inputMode: mode,
    baseSha: base,
    headSha: head,
    repoUrl: 'https://github.com/example/repo',
    prUrl: 'https://github.com/example/repo/pull/1',
    baseRef: 'main',
    headRef: 'feature',
    parseExactChangeCommits,
    setErrorMsg: message => errors.push(message),
    setArtifactError: noop,
    setIsRetryingArtifacts: noop,
    setArtifactAvailability: noop,
    setIsSubmitting: noop,
    setActiveAnalysis: noop,
    setReport: noop,
    setImpacts: noop,
    setReviewFindings: noop,
    setTelemetry: noop,
    setPublication: noop,
    setPubError: noop,
    setDiffDeltas: noop,
    startChangeAnalysis: async payload => {
      calls.push(payload);
      return submit ? submit(payload) : { id: 'new-analysis' };
    },
    startChangeAnalysisFromPR: async payload => {
      calls.push(payload);
      return submit ? submit(payload) : { id: 'new-analysis' };
    },
  };
  const handler = new Function(...Object.keys(deps), js + '\nreturn handleStartAnalysis;')(...Object.values(deps));
  return { calls, errors, pending, handler: () => handler({ preventDefault() {} }) };
}

test('branch names are rejected before sending exact analysis requests', async () => {
  const h = makeHarness({ base: 'main', head: 'feature' });
  await h.handler();
  assert.equal(h.calls.length, 0);
  assert.match(h.errors.at(-1), /40-character hexadecimal/);
});

test('identical commits are rejected without consuming a request', async () => {
  const h = makeHarness({ base: 'A'.repeat(40), head: 'a'.repeat(40) });
  await h.handler();
  assert.equal(h.calls.length, 0);
  assert.match(h.errors.at(-1), /different/);
});

test('valid exact SHAs are normalized and branch labels remain metadata', async () => {
  const h = makeHarness();
  await h.handler();
  assert.equal(h.calls.length, 1);
  assert.equal(h.calls[0].base_commit_sha, 'a'.repeat(40));
  assert.equal(h.calls[0].head_commit_sha, 'b'.repeat(40));
  assert.equal(h.calls[0].base_ref, 'main');
});

test('a second submission cannot start while the first is unresolved', async () => {
  let release;
  const h = makeHarness({ submit: () => new Promise(resolve => { release = resolve; }) });
  const first = h.handler();
  const second = h.handler();
  assert.equal(h.calls.length, 1);
  assert.equal(h.pending.current, true);
  release({ id: 'new-analysis' });
  await Promise.all([first, second]);
  assert.equal(h.pending.current, false);
});

test('a rejected request releases the synchronous guard for retry', async () => {
  let attempts = 0;
  const h = makeHarness({ submit: () => {
    attempts += 1;
    if (attempts === 1) throw Error('Temporary failure');
    return { id: 'recovered' };
  } });
  await h.handler();
  assert.match(h.errors.at(-1), /Temporary failure/);
  await h.handler();
  assert.equal(h.calls.length, 2);
  assert.equal(h.pending.current, false);
});

test('mode selector remains disabled during an in-flight submission', () => {
  const input = readFileSync(join(root, 'src/features/change-analysis/ChangeAnalysisInput.tsx'), 'utf8');
  assert.match(input, /const isBusy = isSubmitting \\|\\| isRunning/);
  assert.equal((input.match(/disabled=\\{isBusy\\}/g) || []).length >= 2, true);
  assert.doesNotMatch(input, /disabled=\\{isRunning\\}/);
});
