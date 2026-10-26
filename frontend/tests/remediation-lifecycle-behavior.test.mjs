import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { runInNewContext } from 'node:vm';
import ts from 'typescript';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const source = readFileSync(join(root, 'src/features/remediation/RemediationLifecycle.tsx'), 'utf8');
const compiled = ts.transpileModule(source, {
  compilerOptions: {
    module: ts.ModuleKind.CommonJS,
    target: ts.ScriptTarget.ES2022,
    jsx: ts.JsxEmit.ReactJSX,
    esModuleInterop: true,
  },
}).outputText;

function mount() {
  const state = [];
  const effects = [];
  let hookIndex = 0;
  const pending = [];
  const same = (a, b) => a && b && a.length === b.length && a.every((v, i) => v === b[i]);
  const components = new Map();
  for (const key of ['ResearchPanel', 'FixPlanPanel', 'PatchCandidatePanel', 'HumanReviewControls', 'DeliveryPreviewModal', 'Alert']) {
    components.set(key, function Stub() {});
  }
  const jsx = (type, props) => ({ type, props: props || {} });
  const react = {
    useState(initial) {
      const index = hookIndex++;
      if (!(index in state)) state[index] = initial;
      return [state[index], (value) => { state[index] = typeof value === 'function' ? value(state[index]) : value; }];
    },
    useRef(initial) {
      const index = hookIndex++;
      if (!(index in state)) state[index] = { current: initial };
      return state[index];
    },
    useEffect(effect, deps) {
      const index = hookIndex++;
      if (!effects[index] || !same(effects[index].deps, deps)) pending.push({ index, effect, deps });
    },
  };
  const reviseCalls = [];
  const approveCalls = [];
  const child = {
    id: 'child-patch', finding_id: 'finding-A', scan_id: 'scan-A',
    status: 'VERIFIED', revision_number: 1,
    unified_diff: '--- a/new.py\n+++ b/new.py\n@@ -1 +1 @@\n-old\n+child\n',
    files_modified: ['new.py'],
  };
  const api = {
    async revisePatch(id, payload) { reviseCalls.push([id, payload]); return child; },
    async approvePatch(id) { approveCalls.push(id); return { ...child, status: 'APPROVED' }; },
    async fetchScanPatches() { return []; },
    async listJobs() { return { items: [], next_cursor: null }; },
    async fetchJobResult() { throw Error('unexpected job result fetch'); },
  };
  const modules = {
    react,
    'react/jsx-runtime': { jsx, jsxs: jsx, Fragment: 'fragment' },
    '@/types/domain': {},
    '@/lib/api': api,
    '@/context/AuthContext': { useAuth: () => ({ user: { id: 'operator-id' }, isOperator: true }) },
    '@/lib/remediationHistory': { findLatestRemediationJobs: async () => ({ research: null, plan: null }) },
    '@/features/remediation/ResearchPanel': { ResearchPanel: components.get('ResearchPanel') },
    './ResearchPanel': { ResearchPanel: components.get('ResearchPanel') },
    './FixPlanPanel': { FixPlanPanel: components.get('FixPlanPanel') },
    './PatchCandidatePanel': { PatchCandidatePanel: components.get('PatchCandidatePanel') },
    './HumanReviewControls': { HumanReviewControls: components.get('HumanReviewControls') },
    './DeliveryPreviewModal': { DeliveryPreviewModal: components.get('DeliveryPreviewModal') },
    '@/components/ui/Alert': { Alert: components.get('Alert') },
  };
  const exports = {};
  runInNewContext(compiled, {
    exports, require(name) {
      if (!(name in modules)) throw Error(`Unexpected dependency: ${name}`);
      return modules[name];
    }, Error, Promise,
  });
  const finding = {
    id: 'finding-A', scan_id: 'scan-A',
    title: 'Code issue', description: 'Confirmed evidence', severity: 'HIGH',
  };
  const initialPatch = {
    id: 'parent-patch', finding_id: 'finding-A', scan_id: 'scan-A',
    status: 'VERIFIED', revision_number: 0,
    unified_diff: '--- a/old.py\n+++ b/old.py\n@@ -1 +1 @@\n-old\n+parent\n',
    files_modified: ['old.py'],
  };
  function render() {
    hookIndex = 0;
    const tree = exports.RemediationLifecycle({ finding, initialPatch });
    for (const effect of pending.splice(0)) {
      effects[effect.index]?.cleanup?.();
      effects[effect.index] = { deps: effect.deps, cleanup: effect.effect() };
    }
    return tree;
  }
  function find(tree, componentName) {
    const target = components.get(componentName);
    if (!tree || typeof tree !== 'object') return null;
    if (tree.type === target) return tree.props;
    const children = tree.props?.children;
    for (const child of Array.isArray(children) ? children : [children]) {
      const result = find(child, componentName);
      if (result) return result;
    }
    return null;
  }
  return { render, find, reviseCalls, approveCalls };
}

test('human revision switches every following action to the revised patch identity', async () => {
  const app = mount();
  app.render();
  let review = app.find(app.render(), 'HumanReviewControls');
  assert.equal(review.canRevise, true);
  review.onRevisionFeedbackChange('Use safer validation');
  review = app.find(app.render(), 'HumanReviewControls');
  await review.onRevise();
  const tree = app.render();
  const candidate = app.find(tree, 'PatchCandidatePanel');
  review = app.find(tree, 'HumanReviewControls');
  assert.equal(app.reviseCalls.length, 1);
  assert.equal(app.reviseCalls[0][0], 'parent-patch');
  assert.match(candidate.diff, /\+child/);
  assert.deepEqual(Array.from(candidate.filesModified), ['new.py']);
  assert.equal(review.canRevise, false);
  await review.onApprove();
  assert.deepEqual(app.approveCalls, ['child-patch']);
});
