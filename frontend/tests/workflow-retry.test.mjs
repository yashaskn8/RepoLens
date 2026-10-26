import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { runInNewContext } from 'node:vm';
import ts from 'typescript';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const content = readFileSync(join(root, 'src/lib/workflowRetry.ts'), 'utf8');
const code = ts.transpileModule(content, {
  compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
}).outputText;
const exports = {};
runInNewContext(code, { exports });
const { WorkflowRetryBudget } = exports;

test('repeated successful socket opens without progress exhaust the retry budget', () => {
  const budget = new WorkflowRetryBudget(10);
  for (let attempts = 1; attempts <= 10; attempts += 1) {
    const delay = budget.nextDelayMs();
    assert.ok(delay >= 2000 && delay <= 10000);
    // The browser may fire onopen between every onerror; that is not progress.
  }
  assert.equal(budget.nextDelayMs(), null);
  assert.equal(budget.nextDelayMs(), null);
});

test('a genuinely new workflow event resets the retry budget', () => {
  const budget = new WorkflowRetryBudget(2);
  assert.equal(budget.nextDelayMs(), 2000);
  assert.equal(budget.nextDelayMs(), 4000);
  assert.equal(budget.nextDelayMs(), null);
  budget.recordProgress();
  assert.equal(budget.nextDelayMs(), 2000);
});

test('workflow hook does not reset retries merely on EventSource open', () => {
  const hook = readFileSync(join(root, 'src/lib/useWorkflowStream.ts'), 'utf8');
  const onOpen = hook.match(/es\.onopen = \(\) => \{[\s\S]*?\n      \};/);
  assert.ok(onOpen, 'EventSource onopen handler must exist');
  assert.doesNotMatch(onOpen[0], /recordProgress\(|retryCount\s*=\s*0/);
  assert.match(hook, /lastEventIdRef\.current = parsed\.id;[\s\S]{0,180}retryBudget\.recordProgress\(\)/);
});

test('reject invalid retry limits', () => {
  assert.throws(() => new WorkflowRetryBudget(0), /positive integer/);
});
