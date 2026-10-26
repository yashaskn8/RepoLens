import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import test from 'node:test';
import ts from 'typescript';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const source = readFileSync(join(root, 'src/lib/useWorkflowStream.ts'), 'utf8');
const start = source.indexOf('function handleEvent(');
const end = source.indexOf('function connect()', start);
assert.ok(start >= 0 && end > start, 'SSE event handler must exist');
const handlerJs = ts.transpileModule(source.slice(start, end), {
  compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
}).outputText;

function fixture() {
  const active = { closed: false, close() { this.closed = true; } };
  const obsolete = { closed: false, close() { this.closed = true; } };
  const eventSourceRef = { current: active };
  const terminalReceivedRef = { current: false };
  const lastEventIdRef = { current: 0 };
  const retryTimeoutRef = { current: null };
  const state = { events: [], status: 'connected', progress: 0 };
  const handleEvent = new Function(
    'eventSourceRef', 'terminalReceivedRef', 'lastEventIdRef', 'retryTimeoutRef',
    'isNewWorkflowEvent', 'retryBudget', 'setEvents', 'setStatus', 'clearTimeout', 'isMounted',
    handlerJs + '\nreturn handleEvent;',
  )(
    eventSourceRef, terminalReceivedRef, lastEventIdRef, retryTimeoutRef,
    (event, lastId) => Number.isSafeInteger(event.id) && event.id > lastId,
    { recordProgress: () => { state.progress += 1; } },
    update => { state.events = update(state.events); },
    status => { state.status = status; },
    () => {}, true,
  );
  return { active, obsolete, state, handleEvent, lastEventIdRef, terminalReceivedRef };
}

test('obsolete SSE terminal message cannot close active socket', () => {
  const run = fixture();
  run.handleEvent({ data: JSON.stringify({ id: 99, event_type: 'SCAN_COMPLETED' }) }, run.obsolete);
  assert.equal(run.active.closed, false);
  assert.equal(run.terminalReceivedRef.current, false);
  assert.equal(run.state.status, 'connected');
  assert.deepEqual(run.state.events, []);
});

test('obsolete SSE events cannot advance cursor or reset retry budget', () => {
  const run = fixture();
  run.handleEvent({ data: JSON.stringify({ id: 101, event_type: 'SCAN_STARTED' }) }, run.obsolete);
  assert.equal(run.lastEventIdRef.current, 0);
  assert.equal(run.state.progress, 0);
  run.handleEvent({ data: JSON.stringify({ id: 1, event_type: 'SCAN_STARTED' }) }, run.active);
  assert.equal(run.lastEventIdRef.current, 1);
  assert.equal(run.state.progress, 1);
});

test('active SSE terminal message still records completion and closes its socket', () => {
  const run = fixture();
  run.handleEvent({ data: JSON.stringify({ id: 3, event_type: 'SCAN_COMPLETED' }) }, run.active);
  assert.equal(run.terminalReceivedRef.current, true);
  assert.equal(run.active.closed, true);
  assert.equal(run.state.status, 'completed');
  assert.equal(run.state.events.length, 1);
});

test('both default and named EventSource callbacks are bound to their socket', () => {
  assert.match(source, /const handleActiveEvent = \(event: MessageEvent\) => handleEvent\(event, es\)/);
  assert.match(source, /es\.onmessage = handleActiveEvent/);
  assert.match(source, /es\.addEventListener\(eventType, handleActiveEvent as EventListener\)/);
});
