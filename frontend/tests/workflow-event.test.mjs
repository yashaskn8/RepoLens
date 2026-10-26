import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { runInNewContext } from 'node:vm';
import ts from 'typescript';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const source = readFileSync(join(root, 'src/lib/workflowEvent.ts'), 'utf8');
const compiled = ts.transpileModule(source, {
  compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
}).outputText;
const exports = {};
runInNewContext(compiled, { exports, Number, Array });
const { isNewWorkflowEvent } = exports;

test('new persisted stream events are accepted', () => {
  assert.equal(isNewWorkflowEvent({ id: 42, event_type: 'SCAN_COMPLETED' }, 41), true);
});
test('duplicate or out-of-order terminal events cannot close a reconnected stream', () => {
  assert.equal(isNewWorkflowEvent({ id: 41, event_type: 'SCAN_FAILED' }, 41), false);
  assert.equal(isNewWorkflowEvent({ id: 2, event_type: 'SCAN_COMPLETED' }, 41), false);
});
test('malformed IDs and event payloads are rejected', () => {
  for (const candidate of [
    null, [], 'event', { id: -1, event_type: 'SCAN_COMPLETED' },
    { id: NaN, event_type: 'SCAN_FAILED' },
    { id: Infinity, event_type: 'SCAN_FAILED' },
    { id: 1.5, event_type: 'SCAN_FAILED' },
    { id: '42', event_type: 'SCAN_FAILED' },
    { id: 42, event_type: null },
  ]) {
    assert.equal(isNewWorkflowEvent(candidate, 0), false);
  }
});
test('hook verifies event freshness before applying terminal state', () => {
  const hook = readFileSync(join(root, 'src/lib/useWorkflowStream.ts'), 'utf8');
  assert.match(hook, /isNewWorkflowEvent\(parsed, lastEventIdRef\.current\)/);
  assert.match(hook, /eventSourceRef\.current !== es/);
});
