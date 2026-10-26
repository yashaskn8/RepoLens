import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import ts from 'typescript';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const helperSource = readFileSync(join(root, 'src/lib/exactChangeCommits.ts'), 'utf8');
const compiled = ts.transpileModule(helperSource, {
  compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
}).outputText;
const exports = {};
new Function('exports', compiled)(exports);
const { parseExactChangeCommits } = exports;
const shaA = 'A'.repeat(40);
const shaB = 'b'.repeat(40);

test('exact commit pair is normalized and sent as immutable SHAs', () => {
  assert.deepEqual(parseExactChangeCommits(`  ${shaA} `, shaB), {
    baseSha: 'a'.repeat(40), headSha: shaB,
  });
});

test('branch names, partial hashes, nonhex characters and empty inputs are rejected', () => {
  for (const value of ['main', 'feature/auth', 'f'.repeat(39), 'g'.repeat(40), '']) {
    assert.throws(() => parseExactChangeCommits(value, shaB), /Base commit/);
    assert.throws(() => parseExactChangeCommits(shaA, value), /Head commit/);
  }
});

test('same revision cannot be compared, even with mixed SHA casing', () => {
  assert.throws(() => parseExactChangeCommits(shaA, 'a'.repeat(40)), /must be different/);
});

const page = readFileSync(join(root, 'src/app/change-analysis/page.tsx'), 'utf8');
test('UI accurately requests exact SHAs rather than advertising unsupported branch resolution', () => {
  assert.match(page, /Compare Exact Commits/);
  assert.match(page, /Base commit SHA \(40 hexadecimal characters\)/);
  assert.match(page, /Head commit SHA \(40 hexadecimal characters\)/);
  assert.doesNotMatch(page, /Compare Branches \/ Commits/);
  assert.match(page, /const \[baseRef, setBaseRef\] = useState\(''\)/);
  assert.match(page, /const \[headRef, setHeadRef\] = useState\(''\)/);
});

const handlerStart = page.indexOf('  const handleSubmit = async');
const handlerEnd = page.indexOf('  return (', handlerStart);
assert.ok(handlerStart >= 0 && handlerEnd > handlerStart);
const handlerJs = ts.transpileModule(page.slice(handlerStart, handlerEnd), {
  compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
}).outputText;

function fixture(mode, baseRef, headRef) {
  const calls = [];
  const errors = [];
  const submitPending = { current: false };
  const submitGeneration = { current: 0 };
  const activeAccountRef = { current: 'account-A' };
  const handleSubmit = new Function(
    'accountId', 'authLoading', 'submitPending', 'submitGeneration', 'activeAccountRef',
    'setError', 'setIsSubmitting', 'mode', 'baseRef', 'headRef', 'repoUrl', 'prUrl',
    'startChangeAnalysis', 'startChangeAnalysisFromPR', 'isCurrentAccountResponse',
    'router', 'getErrorMessage', 'parseExactChangeCommits',
    handlerJs + '\nreturn handleSubmit;',
  )(
    'account-A', false, submitPending, submitGeneration, activeAccountRef,
    value => errors.push(value), () => {}, mode, baseRef, headRef,
    'https://github.com/org/repo', 'https://github.com/org/repo/pull/1',
    async payload => { calls.push(['exact', payload]); return { id: 'analysis-1' }; },
    async payload => { calls.push(['pr', payload]); return { id: 'analysis-1' }; },
    (requested, active, generation, current) => requested === active && generation === current,
    { push() {} }, err => err.message, parseExactChangeCommits,
  );
  return { calls, errors, handleSubmit };
}

test('invalid branch input is rejected before any API call or pending submission', async () => {
  const run = fixture('commits', 'main', 'feature/auth');
  await run.handleSubmit({ preventDefault() {} });
  assert.equal(run.calls.length, 0);
  assert.match(run.errors.at(-1), /Base commit/);
});

test('exact mode sends normalized SHA payload, never branch names', async () => {
  const run = fixture('commits', shaA, shaB);
  await run.handleSubmit({ preventDefault() {} });
  assert.deepEqual(run.calls, [['exact', {
    repository_url: 'https://github.com/org/repo',
    base_commit_sha: 'a'.repeat(40),
    head_commit_sha: shaB,
  }]]);
});

test('PR URL mode remains functional without exact SHA inputs', async () => {
  const run = fixture('pr', '', '');
  await run.handleSubmit({ preventDefault() {} });
  assert.deepEqual(run.calls, [['pr', { pr_url: 'https://github.com/org/repo/pull/1' }]]);
});
