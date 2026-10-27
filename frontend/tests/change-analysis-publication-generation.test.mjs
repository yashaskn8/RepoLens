import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const source = readFileSync(
  new URL('../src/features/change-analysis/ChangeAnalysisWorkspace.tsx', import.meta.url),
  'utf8',
);

// Exercise the actual checked-in handler bodies without importing React or
// invoking any network services. The test context provides inert API fakes.
function handler(name, context) {
  const match = source.match(new RegExp(
    `  const ${name} = async \\(\\) => \\{([\\s\\S]*?)\\n  \\};`,
  ));
  assert.ok(match, `missing ${name} handler`);
  const body = match[1].replaceAll('catch (err: unknown)', 'catch (err)');
  return new Function('context', `with (context) { return async () => { ${body} }; }`)(context);
}

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}

function setup() {
  const writes = { publications: [], errors: [], preview: [], approve: [], publish: [], confirms: [] };
  const context = {
    activeAnalysis: { id: 'analysis-A' },
    publication: { preview_digest: 'digest-A' },
    analysisGenerationRef: { current: 1 },
    publicationPendingRef: { current: false },
    setPublication: (value) => writes.publications.push(value),
    setPubError: (value) => writes.errors.push(value),
    setIsGeneratingPreview: (value) => writes.preview.push(value),
    setIsApprovingPub: (value) => writes.approve.push(value),
    setIsPublishingPub: (value) => writes.publish.push(value),
    setShowPublishConfirm: (value) => writes.confirms.push(value),
  };
  return { context, writes };
}

test('late preview success cannot repopulate a newer analysis or unlock its action', async () => {
  const { context, writes } = setup();
  const request = deferred();
  context.generateReviewPublicationPreview = () => request.promise;
  const running = handler('handleGeneratePreview', context)();
  context.analysisGenerationRef.current = 2;
  context.publicationPendingRef.current = true;
  request.resolve({ preview_digest: 'old-preview' });
  await running;
  assert.deepEqual(writes.publications, []);
  assert.deepEqual(writes.preview, [true]);
  assert.equal(context.publicationPendingRef.current, true);
});

test('late approval failure cannot display an old error or release a newer lock', async () => {
  const { context, writes } = setup();
  const request = deferred();
  context.approveReviewPublication = () => request.promise;
  const running = handler('handleApprovePublication', context)();
  context.analysisGenerationRef.current = 2;
  context.publicationPendingRef.current = true;
  request.reject(new Error('old approval failed'));
  await running;
  assert.deepEqual(writes.errors, [null]);
  assert.deepEqual(writes.approve, [true]);
  assert.equal(context.publicationPendingRef.current, true);
});

test('late publication refresh cannot overwrite the new preview or close its confirmation', async () => {
  const { context, writes } = setup();
  const refresh = deferred();
  context.publishReviewPublication = async () => {};
  context.fetchReviewPublication = () => refresh.promise;
  const running = handler('handlePublishReview', context)();
  // Wait for the first await to advance into the refresh.
  await Promise.resolve();
  context.analysisGenerationRef.current = 2;
  context.publicationPendingRef.current = true;
  refresh.resolve({ status: 'PUBLISHED', preview_digest: 'old-preview' });
  await running;
  assert.deepEqual(writes.publications, []);
  assert.deepEqual(writes.confirms, []);
  assert.deepEqual(writes.publish, [true]);
  assert.equal(context.publicationPendingRef.current, true);
});

test('publication actions share a synchronous lock and release it after success', async () => {
  const { context, writes } = setup();
  const request = deferred();
  let previews = 0;
  let approvals = 0;
  context.generateReviewPublicationPreview = () => { previews++; return request.promise; };
  context.approveReviewPublication = async () => { approvals++; return { status: 'APPROVED' }; };
  const preview = handler('handleGeneratePreview', context);
  const approve = handler('handleApprovePublication', context);
  const first = preview();
  await preview();
  await approve();
  assert.equal(previews, 1);
  assert.equal(approvals, 0);
  request.resolve({ preview_digest: 'digest-A' });
  await first;
  assert.equal(context.publicationPendingRef.current, false);
  await approve();
  assert.equal(approvals, 1);
  assert.equal(writes.publications.length, 2);
});

test('current-generation failure reports an error and allows retry', async () => {
  const { context, writes } = setup();
  context.approveReviewPublication = async () => { throw new Error('temporary failure'); };
  await handler('handleApprovePublication', context)();
  assert.deepEqual(writes.errors, [null, 'temporary failure']);
  assert.equal(context.publicationPendingRef.current, false);
  assert.deepEqual(writes.approve, [true, false]);
});

test('starting a new analysis clears publication state and pending-action UI', () => {
  const start = source.match(/  const handleStartAnalysis = async \(e: React\.FormEvent\) => \{([\s\S]*?)\n  \};/);
  assert.ok(start);
  for (const required of [
    'publicationPendingRef.current = false',
    'setIsGeneratingPreview(false)',
    'setIsApprovingPub(false)',
    'setIsPublishingPub(false)',
    'setShowPublishConfirm(false)',
    'setPublication(null)',
  ]) assert.ok(start[1].includes(required), `missing reset: ${required}`);
});
