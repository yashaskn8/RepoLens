import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const source = readFileSync(new URL('../src/features/change-analysis/ChangeAnalysisWorkspace.tsx', import.meta.url), 'utf8');

test('completed analysis offers explicit recovery when artifacts are missing', () => {
  assert.match(source, /activeAnalysis\?\.status === 'COMPLETED' && artifactError/);
  assert.match(source, /Retry missing artifacts/);
  assert.match(source, /onClick=\{\(\) => void retryCompletedArtifacts\(\)\}/);
});

test('artifact retry is limited to completed analysis and avoids concurrent retries', () => {
  assert.match(source, /activeAnalysis\.status !== 'COMPLETED' \|\| isRetryingArtifacts/);
  assert.match(source, /disabled=\{isRetryingArtifacts\}/);
});

test('retry uses existing generation-guarded artifact loader', () => {
  assert.match(source, /await loadCompletedAnalysisData\(activeAnalysis\.id, generation\)/);
  assert.match(source, /if \(generation !== analysisGenerationRef\.current\) return/);
});
