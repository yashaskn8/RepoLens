import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import ts from 'typescript';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const source = readFileSync(join(root, 'src/lib/changeRiskPresentation.ts'), 'utf8');
const compiled = ts.transpileModule(source, {
  compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
}).outputText;
const exports = {};
new Function('exports', compiled)(exports);
const { describeChangeRisk } = exports;

test('all confirmed risk levels retain their matching severity', () => {
  for (const level of ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']) {
    const result = describeChangeRisk(level);
    assert.equal(result.variant, level.toLowerCase());
    assert.equal(result.label, level + ' RISK');
  }
});

test('NONE never inherits the LOW risk badge', () => {
  assert.deepEqual(describeChangeRisk('NONE'), {
    variant: 'default', label: 'NO RISK LEVEL ASSIGNED',
  });
});

test('unrecognized or unavailable assessments cannot be misrepresented as low risk', () => {
  assert.deepEqual(describeChangeRisk('UNKNOWN'), {
    variant: 'default', label: 'RISK UNKNOWN',
  });
  assert.equal(describeChangeRisk(null), null);
  assert.equal(describeChangeRisk(undefined), null);
});

test('change-analysis history uses risk presentation helper for all badges', () => {
  const page = readFileSync(join(root, 'src/app/change-analysis/page.tsx'), 'utf8');
  assert.match(page, /describeChangeRisk\(analysis\.risk_level\)\?\.variant/);
  assert.match(page, /describeChangeRisk\(analysis\.risk_level\)\?\.label/);
});
