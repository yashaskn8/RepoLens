import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import test from 'node:test';
const source = readFileSync(join(dirname(dirname(fileURLToPath(import.meta.url))), 'src/features/findings/FindingCard.tsx'), 'utf8');

test('finding impact is persisted text, not an invented generic consequence', () => {
  assert.match(source, /finding\.description\?\.trim\(\)/);
  assert.match(source, /No impact explanation was recorded/);
  assert.doesNotMatch(source, /Can lead to unauthorized access|Exposes sensitive data|Insecure configuration, missing input/);
});

test('finding remediation is persisted guidance, not a title heuristic', () => {
  assert.match(source, /finding\.mitigation_guidance\?\.trim\(\)/);
  assert.match(source, /No remediation guidance was recorded/);
  assert.doesNotMatch(source, /finding\.title\.toLowerCase|category\?\.toLowerCase\(\)\.includes\('injection'\)/);
});

test('missing source evidence is described accurately', () => {
  assert.match(source, /No source evidence is attached/);
  assert.doesNotMatch(source, /Identified in repository configuration or manifest/);
});
