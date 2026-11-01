import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import test from 'node:test';
import ts from 'typescript';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const source = readFileSync(join(root, 'src/app/changes/[id]/page.tsx'), 'utf8');
const start = source.indexOf('export default function ChangeDetailPage(');
const end = source.indexOf('function ChangeDetailWorkspace(', start);
assert.ok(start >= 0 && end > start, 'private PR workspace must have a separate account gate');
const wrapper = source.slice(start, end).replace('export default function', 'function');
const js = ts.transpileModule(wrapper, {
  compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022, jsx: ts.JsxEmit.React },
}).outputText;

function render(auth, analysisId = 'analysis-one') {
  const ChangeDetailWorkspace = function ChangeDetailWorkspace() {};
  const AppShell = function AppShell() {};
  const EmptyState = function EmptyState() {};
  const Lock = function Lock() {};
  const React = { createElement: (type, props, ...children) => ({
    type, props: { ...props, children },
  }) };
  const component = new Function(
    'React', 'use', 'useAuth', 'AppShell', 'EmptyState', 'Lock', 'ChangeDetailWorkspace',
    js + '\nreturn ChangeDetailPage;',
  )(React, value => value, () => auth, AppShell, EmptyState, Lock, ChangeDetailWorkspace);
  return { view: component({ params: { id: analysisId } }), AppShell, ChangeDetailWorkspace };
}

test('signed-out or restoring sessions never mount private PR review controls', () => {
  for (const auth of [
    { user: null, isLoading: false },
    { user: { id: 'tenant-A' }, isLoading: true },
  ]) {
    const { view, AppShell } = render(auth);
    assert.equal(view.type, AppShell);
  }
});

test('switching tenants resets PR diff and publication confirmation state', () => {
  const first = render({ user: { id: 'tenant-A' }, isLoading: false });
  const next = render({ user: { id: 'tenant-B' }, isLoading: false });
  assert.equal(first.view.type, first.ChangeDetailWorkspace);
  assert.equal(next.view.type, next.ChangeDetailWorkspace);
  assert.notEqual(first.view.props.key, next.view.props.key);
});

test('switching analysis IDs remounts private publication state', () => {
  const auth = { user: { id: 'tenant-A' }, isLoading: false };
  assert.notEqual(render(auth, 'analysis-one').view.props.key, render(auth, 'analysis-two').view.props.key);
  assert.equal(render(auth, 'analysis-one').view.props.key, render(auth, 'analysis-one').view.props.key);
});

test('pending review actions are invalidated on unmount before subsequent write', () => {
  const workspace = source.slice(end);
  assert.match(workspace, /useEffect\(\(\) => \(\) => \{ actionGeneration\.current \+= 1; \}, \[\]\)/);
  assert.match(workspace, /await approveReviewPublication\(analysisId, digest\);\s*if \(generation !== actionGeneration\.current\) return;/);
  assert.match(workspace, /publishingRef\.current = true/);
  assert.match(workspace, /!confirmedPublish \|\| publishingRef\.current/);
  assert.match(workspace, /if \(generation === actionGeneration\.current\) setPublication\(pub\)/);
});

test('unavailable PR risk cannot appear as LOW or a success badge', () => {
  const workspace = source.slice(end);
  assert.doesNotMatch(workspace, /analysis\?\.risk_level \|\| 'LOW'/);
  assert.match(workspace, /analysis\?\.risk_level === 'LOW'\s*\? 'success'\s*: 'warning'/);
  assert.match(workspace, /: 'Not assessed'/);
});

const actionSource = source.slice(
  source.indexOf('  const handleGeneratePreview ='),
  source.indexOf('  const currentFileDiff'),
);
const actionJs = ts.transpileModule(actionSource, {
  compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
}).outputText;

function makeActions({ confirmed = true, operator = true } = {}) {
  const actionGeneration = { current: 0 };
  const publishingRef = { current: false };
  const publicationReadSequenceRef = { current: 0 };
  const recorded = { approvals: 0, publishes: 0, previews: [], messages: [] };
  let resolveApproval;
  let resolvePreview;
  const approveReviewPublication = () => {
    recorded.approvals += 1;
    return new Promise(resolve => { resolveApproval = resolve; });
  };
  const generateReviewPublicationPreview = () => new Promise(resolve => { resolvePreview = resolve; });
  const publishReviewPublication = async () => {
    recorded.publishes += 1;
    return { github_review_id: '100' };
  };
  const actions = new Function(
    'actionGeneration', 'publishingRef', 'publicationReadSequenceRef', 'publication', 'isOperator', 'confirmedPublish',
    'setIsPublishing', 'setPublishMessage', 'approveReviewPublication', 'publishReviewPublication',
    'fetchReviewPublication', 'setPublication', 'generateReviewPublicationPreview',
    'getErrorMessage', 'analysisId', 'setConfirmedPublish', 'withChangeDetailDeadline',
    actionJs + '\nreturn {handleGeneratePreview,handleApproveAndPublish};',
  )(
    actionGeneration, publishingRef, publicationReadSequenceRef, { preview_digest: 'approved-digest' }, operator, confirmed,
    () => {}, message => recorded.messages.push(message),
    approveReviewPublication, publishReviewPublication, async () => ({ preview_digest: 'new' }),
    preview => recorded.previews.push(preview), generateReviewPublicationPreview,
    () => 'failed', 'analysis-one', () => {}, async (callback) => callback(),
  );
  return {
    actions, actionGeneration, recorded,
    resolveApproval: () => resolveApproval(),
    resolvePreview: value => resolvePreview(value),
  };
}

test('publication requires operator role and explicit human confirmation even on direct handler calls', async () => {
  for (const opts of [{ confirmed: false }, { operator: false }]) {
    const { actions, recorded } = makeActions(opts);
    await actions.handleApproveAndPublish();
    assert.equal(recorded.approvals, 0);
    assert.equal(recorded.publishes, 0);
  }
});

test('account switch during approval prevents a subsequent GitHub publish call', async () => {
  const run = makeActions();
  const pending = run.actions.handleApproveAndPublish();
  assert.equal(run.recorded.approvals, 1);
  run.actionGeneration.current += 1; // keyed workspace unmounted on account switch
  run.resolveApproval();
  await pending;
  assert.equal(run.recorded.publishes, 0);
});

test('double-click cannot submit two approval and publication requests', async () => {
  const run = makeActions();
  const first = run.actions.handleApproveAndPublish();
  await run.actions.handleApproveAndPublish();
  assert.equal(run.recorded.approvals, 1);
  run.resolveApproval();
  await first;
  assert.equal(run.recorded.publishes, 1);
});

test('late preview response cannot restore old tenant publication state', async () => {
  const run = makeActions();
  const pending = run.actions.handleGeneratePreview();
  run.actionGeneration.current += 1;
  run.resolvePreview({ preview_digest: 'stale-preview' });
  await pending;
  assert.deepEqual(run.recorded.previews, []);
});
