import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import ts from 'typescript';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const source = readFileSync(join(root, 'src/app/scans/[id]/page.tsx'), 'utf8');
const effectStart = source.indexOf('  useEffect(() => {', source.indexOf('function ScanDetailWorkspace('));
const effectEnd = source.indexOf('  }, [scanId, findingsRetryKey]);', effectStart);
assert.ok(effectStart > 0 && effectEnd > effectStart, 'retry key must restart scan artifact loading');

const effectBody = source.slice(effectStart + '  useEffect(() => {'.length, effectEnd);
const effectJs = ts.transpileModule('function runEffect() {' + effectBody + '}', {
  compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
}).outputText;
const effect = new Function(
  'scanId', 'fetchScan', 'fetchScanFindings', 'fetchScanTelemetry',
  'setScan', 'setFindings', 'setTelemetry', 'setFindingsLoaded',
  'setChainbrainAiNotes', 'setChainbrainAiBusy', 'setIsLoading', 'setTimeout', 'clearTimeout',
  effectJs + '\nreturn runEffect();',
);

async function flush() {
  for (let i = 0; i < 10; i++) await Promise.resolve();
}

test('completed scan retries missing findings but never treats them as zero', async () => {
  let findingsCalls = 0;
  let loaded = false;
  let findings = ['old-result'];
  const timers = [];
  const cleanup = effect(
    'scan-1',
    async () => ({ id: 'scan-1', status: 'COMPLETED' }),
    async () => { findingsCalls++; throw new Error('findings unavailable'); },
    async () => ({ status: 'COMPLETED' }),
    () => {}, value => { findings = value; }, () => {},
    value => { loaded = value; }, () => {}, () => {}, () => {},
    callback => { timers.push(callback); return timers.length; }, () => {},
  );
  await flush();
  assert.equal(loaded, false);
  assert.deepEqual(findings, []);
  for (let retry = 0; retry < 3; retry++) {
    assert.equal(timers.length, retry + 1);
    await timers[retry]();
    await flush();
  }
  assert.equal(findingsCalls, 4);
  assert.equal(timers.length, 3, 'bounded retries must stop after four attempts');
  assert.equal(loaded, false);
  cleanup();
});

test('successful manual retry can recover findings after previous exhaustion', async () => {
  let loaded = false;
  let findings = [];
  const cleanup = effect(
    'scan-1',
    async () => ({ id: 'scan-1', status: 'COMPLETED' }),
    async () => [{ id: 'recovered-finding' }],
    async () => ({}),
    () => {}, value => { findings = value; }, () => {},
    value => { loaded = value; }, () => {}, () => {}, () => {},
    () => { throw new Error('unexpected retry'); }, () => {},
  );
  await flush();
  assert.equal(loaded, true);
  assert.deepEqual(findings, [{ id: 'recovered-finding' }]);
  cleanup();
});

test('summary hides misleading zero counts until findings are actually loaded', () => {
  assert.match(source, /findingsLoaded && scan\?\.status === 'COMPLETED' \? \(/);
  assert.match(source, /Findings not verified — severity counts unknown/);
});

test('completed scan provides an explicit retry that restarts the loading effect', () => {
  assert.match(source, /actionLabel=\{scan\?\.status === 'COMPLETED' \? 'Retry loading findings'/);
  assert.match(source, /setFindingsRetryKey\(\(current\) => current \+ 1\)/);
  assert.match(source, /\[scanId, findingsRetryKey\]/);
});
