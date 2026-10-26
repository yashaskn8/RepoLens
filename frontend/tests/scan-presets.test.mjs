import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import test from 'node:test';
const source = readFileSync(join(dirname(dirname(fileURLToPath(import.meta.url))), 'src/app/scan/page.tsx'), 'utf8');

test('scan presets are accessible buttons, not mouse-only divs', () => {
  const section = source.slice(source.indexOf('{PRESET_CARDS.map'), source.indexOf('/* Right Column'));
  assert.match(section, /<button/);
  assert.match(section, /type="button"/);
  assert.match(section, /disabled=\{isScanning\}/);
  assert.match(section, /aria-pressed=/);
  assert.doesNotMatch(section, /<div\s+key=\{preset\.name\}/);
});
test('the scan workspace does not incorrectly claim all optional scanners are active', () => {
  assert.doesNotMatch(source, /4 Active Analysis Engines/);
  assert.match(source, /external security scanners may be unavailable/);
});
test('FastAPI example uses the current canonical repository', () => {
  assert.match(source, /https:\/\/github\.com\/fastapi\/fastapi/);
});
