import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const source = readFileSync(new URL('../src/features/change-analysis/ChangeAnalysisWorkspace.tsx', import.meta.url), 'utf8');
const panel = readFileSync(new URL('../src/features/review/ReviewPublicationPanel.tsx', import.meta.url), 'utf8');
const start = source.indexOf('  const handleCopyDigest =');
const end = source.indexOf('  const isRunning =', start);
assert.ok(start >= 0 && end > start, 'publication digest copy handler must exist');
const handlerSource = source.slice(start, end);

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((done, fail) => { resolve = done; reject = fail; });
  return { promise, resolve, reject };
}

function fixture() {
  const generation = { current: 1 };
  const sequence = { current: 0 };
  const copied = [];
  const errors = [];
  const clipboard = [];
  const timers = [];
  const makeCopy = digest => new Function(
    'publication', 'navigator', 'analysisGenerationRef', 'copyDigestSequenceRef',
    'setCopiedDigest', 'setCopyDigestError', 'setTimeout',
    handlerSource + '\\nreturn handleCopyDigest;',
  )(
    { preview_digest: digest },
    { clipboard: { writeText: value => {
      const pending = deferred();
      clipboard.push({ value, ...pending });
      return pending.promise;
    } } },
    generation, sequence, value => copied.push(value), value => errors.push(value),
    (callback, delay) => { assert.equal(delay, 2000); timers.push(callback); },
  );
  return { generation, sequence, copied, errors, clipboard, timers, makeCopy };
}

test('digest copy does not show success until clipboard confirms', async () => {
  const f = fixture();
  const task = f.makeCopy('digest-A')();
  assert.deepEqual(f.copied, [false]);
  assert.equal(f.clipboard[0].value, 'digest-A');
  f.clipboard[0].resolve();
  await task;
  assert.deepEqual(f.copied, [false, true]);
  assert.equal(f.timers.length, 1);
});

test('denied clipboard permission reports failure rather than false success', async () => {
  const f = fixture();
  const task = f.makeCopy('digest-A')();
  f.clipboard[0].reject(new Error('permission denied'));
  await task;
  assert.equal(f.copied.includes(true), false);
  assert.match(f.errors.at(-1), /clipboard|copy/i);
  assert.match(panel, /copyDigestError/);
});

test('obsolete analysis or replaced digest cannot claim copy success', async () => {
  const f = fixture();
  const old = f.makeCopy('digest-A')();
  f.generation.current += 1;
  f.clipboard[0].resolve();
  await old;
  assert.equal(f.copied.includes(true), false);

  const newer = f.makeCopy('digest-B')();
  f.sequence.current += 1; // publication digest changed before clipboard settled
  f.clipboard[1].resolve();
  await newer;
  assert.equal(f.copied.includes(true), false);
  assert.match(source, /\\[publication\\?\\.preview_digest\\]/);
});

test('earlier copy timer cannot reset a newer digest copy indicator', async () => {
  const f = fixture();
  const first = f.makeCopy('digest-A')();
  f.clipboard[0].resolve();
  await first;
  const second = f.makeCopy('digest-A')();
  f.clipboard[1].resolve();
  await second;
  f.timers[0]();
  assert.equal(f.copied.at(-1), true);
  f.timers[1]();
  assert.equal(f.copied.at(-1), false);
});
