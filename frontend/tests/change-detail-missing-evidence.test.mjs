import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const ts = require('typescript');
const source = readFileSync(new URL('../src/app/changes/[id]/page.tsx', import.meta.url), 'utf8');
const ast = ts.createSourceFile('page.tsx', source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);

function conditionForEmptyState(title) {
  let condition;
  function visit(node) {
    if (ts.isConditionalExpression(node) && node.whenTrue.getText(ast).includes(`title="${title}"`)) {
      condition ??= node.condition.getText(ast);
    }
    ts.forEachChild(node, visit);
  }
  visit(ast);
  return condition;
}

test('PR detail page parses as TSX', () => {
  assert.deepEqual(ast.parseDiagnostics.map((diagnostic) => diagnostic.messageText), []);
});

test('missing structural diff never renders a zero-breaking-changes conclusion', () => {
  assert.equal(conditionForEmptyState('Structural diff unavailable'), 'diff === null');
  assert.equal(conditionForEmptyState('Zero breaking changes detected'), 'breakingChangesCount === 0');
  assert.match(source, /diff === null \? \([\s\S]*?title="Structural diff unavailable"[\s\S]*?\) : breakingChangesCount === 0 \? \(/);
});

test('downstream impact failure is distinct from a verified empty result', () => {
  assert.equal(conditionForEmptyState('Downstream impact evidence unavailable'), '!impactsLoaded');
  assert.equal(conditionForEmptyState('No downstream callers affected'), 'impacts.length === 0');
  assert.match(source, /!impactsLoaded \? \([\s\S]*?title="Downstream impact evidence unavailable"[\s\S]*?\) : impacts.length === 0 \? \(/);
});

test('successful impact retrieval is tracked and required for risk assessment', () => {
  assert.match(source, /setImpactsLoaded\(false\)/);
  assert.match(source, /if \(impactsRes.status === 'fulfilled'\) \{\s*setImpacts\(impactsRes.value \|\| \[\]\);\s*setImpactsLoaded\(true\)/);
  assert.match(source, /const assessmentAvailable = analysis\?\.status === 'COMPLETED' && diff !== null && impactsLoaded && review !== null/);
});

test('unavailable evidence counts and unassessed risk are not reported as zero or safe', () => {
  assert.match(source, /Breaking Changes: \{diff === null \? 'unavailable' : breakingChangesCount\}/);
  assert.match(source, /Downstream Callers: \{impactsLoaded \? impacts.length : 'unavailable'\}/);
  assert.match(source, /Review Findings \(\{review === null \? 'unavailable'/);
  assert.match(source, /analysis.risk_level !== 'NONE'/);
  assert.doesNotMatch(source, /All public routes and schemas maintain backward compatibility/);
  assert.doesNotMatch(source, /do not propagate to downstream consumers/);
});
