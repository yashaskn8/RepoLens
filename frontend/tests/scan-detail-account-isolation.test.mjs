import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import test from 'node:test';
import ts from 'typescript';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const source = readFileSync(join(root, 'src/app/scans/[id]/page.tsx'), 'utf8');
const start = source.indexOf('export default function ScanDetailPage(');
const end = source.indexOf('function ScanDetailWorkspace(', start);
assert.ok(start >= 0 && end > start, 'scan detail must separate auth gate from stateful workspace');
const wrapperSource = source.slice(start, end).replace('export default function', 'function');
const transpiled = ts.transpileModule(wrapperSource, {
  compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022, jsx: ts.JsxEmit.React },
}).outputText;

function render(auth, scanId = 'scan-one') {
  const ScanDetailWorkspace = function ScanDetailWorkspace() {};
  const AppShell = function AppShell() {};
  const EmptyState = function EmptyState() {};
  const ShieldAlert = function ShieldAlert() {};
  const React = { createElement: (type, props, ...children) => ({
    type, props: { ...props, children },
  }) };
  const useAuth = () => auth;
  const use = (params) => params;
  const component = new Function(
    'React', 'use', 'useAuth', 'AppShell', 'EmptyState', 'ShieldAlert', 'ScanDetailWorkspace',
    transpiled + '\nreturn ScanDetailPage;',
  )(React, use, useAuth, AppShell, EmptyState, ShieldAlert, ScanDetailWorkspace);
  return { view: component({ params: { id: scanId } }), AppShell, EmptyState, ScanDetailWorkspace };
}

test('signed-out scan detail does not mount private workspace or start SSE', () => {
  const { view, AppShell, EmptyState } = render({ user: null, isLoading: false });
  assert.equal(view.type, AppShell);
  assert.equal(view.props.children[0].type, EmptyState);
  assert.match(view.props.children[0].props.title, /Sign in/);
});

test('session restoration does not mount private scan workspace', () => {
  const { view, AppShell } = render({ user: { id: 'tenant-A' }, isLoading: true });
  assert.equal(view.type, AppShell);
});

test('account switching remounts the scan and clears previous tenant state', () => {
  const first = render({ user: { id: 'tenant-A' }, isLoading: false });
  const next = render({ user: { id: 'tenant-B' }, isLoading: false });
  assert.equal(first.view.type, first.ScanDetailWorkspace);
  assert.equal(next.view.type, next.ScanDetailWorkspace);
  assert.notEqual(first.view.props.key, next.view.props.key);
  assert.equal(next.view.props.scanId, 'scan-one');
});

test('navigating between scans remounts the private workspace', () => {
  const auth = { user: { id: 'tenant-A' }, isLoading: false };
  const first = render(auth, 'scan-one');
  const next = render(auth, 'scan-two');
  assert.notEqual(first.view.props.key, next.view.props.key);
});

test('same account and scan preserve identity for polling continuity', () => {
  const auth = { user: { id: 'tenant-A' }, isLoading: false };
  assert.equal(render(auth, 'scan-one').view.props.key, render(auth, 'scan-one').view.props.key);
});

test('scan polling, private AI explanations and workflow SSE live inside keyed workspace', () => {
  const workspace = source.slice(end);
  assert.match(workspace, /useWorkflowStream\(scanId, true\)/);
  assert.match(workspace, /fetchScan\(scanId\)/);
  assert.match(workspace, /explainChainBrainSignal\(scan\.id, index\)/);
  assert.match(workspace, /cancelled = true/);
  assert.match(source.slice(start, end), /<ScanDetailWorkspace key=\{\`\$\{accountId\}:\$\{scanId\}\`\}/);
});
