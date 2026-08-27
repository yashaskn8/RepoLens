'use client';

import React, { useEffect, useState } from 'react';
import {
  DeliveryPreviewResponse,
  DeliveryResponse,
  Finding,
  FixPlan,
  PatchResponse,
  PatchWorkflowResult,
  ResearchResult,
} from '@/types/domain';
import {
  approvePatch,
  fetchDeliveryByPatch,
  fetchDeliveryPreview,
  rejectPatch,
  requestDelivery,
  requestFindingResearch,
  requestFixPlan,
  requestPatchGeneration,
  revisePatch,
} from '@/lib/api';
import { DiffViewer } from './DiffViewer';

interface RemediationLifecycleProps {
  finding: Finding;
  initialPatch?: PatchResponse | null;
}

export const RemediationLifecycle: React.FC<RemediationLifecycleProps> = ({
  finding,
  initialPatch = null,
}) => {
  const [research, setResearch] = useState<ResearchResult | null>(null);
  const [plan, setPlan] = useState<FixPlan | null>(null);
  const [workflowResult, setWorkflowResult] = useState<PatchWorkflowResult | null>(null);
  const [patchStatus, setPatchStatus] = useState<string>(initialPatch?.status || 'DRAFT');
  const [patchId, setPatchId] = useState<string | null>(initialPatch?.id || null);
  const [diff, setDiff] = useState<string>(initialPatch?.unified_diff || '');
  const [filesModified, setFilesModified] = useState<string[]>(initialPatch?.files_modified || []);

  const [loadingStep, setLoadingStep] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [revisionFeedback, setRevisionFeedback] = useState<string>('');
  const [rejectReason, setRejectReason] = useState<string>('');
  const [showRejectInput, setShowRejectInput] = useState(false);
  const [showReviseInput, setShowReviseInput] = useState(false);

  // Delivery state (Phase 5)
  const [deliveryPreview, setDeliveryPreview] = useState<DeliveryPreviewResponse | null>(null);
  const [delivery, setDelivery] = useState<DeliveryResponse | null>(null);
  const [showDeliveryModal, setShowDeliveryModal] = useState<boolean>(false);
  const [deliveryNotes, setDeliveryNotes] = useState<string>('');
  const [deliveryRequestedBy, setDeliveryRequestedBy] = useState<string>('lead-engineer');

  // Step 1: Request Research
  const handleRequestResearch = async () => {
    try {
      setError(null);
      setLoadingStep('research');
      const res = await requestFindingResearch(finding.id);
      setResearch(res);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Research failed');
    } finally {
      setLoadingStep(null);
    }
  };

  // Step 2: Request Fix Plan
  const handleRequestPlan = async () => {
    try {
      setError(null);
      setLoadingStep('plan');
      const res = await requestFixPlan(finding.id);
      setPlan(res);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Fix plan generation failed');
    } finally {
      setLoadingStep(null);
    }
  };

  // Step 3: Request Safe Patch Generation & Sandbox Verification
  const handleRequestPatch = async () => {
    try {
      setError(null);
      setLoadingStep('patch');
      const res = await requestPatchGeneration(finding.id);
      setWorkflowResult(res);
      setPatchId(res.proposal.id);
      setDiff(res.proposal.unified_diff);
      setFilesModified(res.proposal.files_modified);
      setPatchStatus(
        res.machine_verdict === 'PASSED' || res.final_verdict === 'PASSED'
          ? 'VERIFIED'
          : res.machine_verdict === 'REJECTED' || res.final_verdict === 'REJECTED'
          ? 'REJECTED'
          : 'NEEDS_REVIEW'
      );
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Patch generation failed');
    } finally {
      setLoadingStep(null);
    }
  };

  // Step 4: Human Approval
  const handleApprove = async () => {
    if (!patchId) return;
    try {
      setError(null);
      setLoadingStep('approve');
      const updated = await approvePatch(patchId, { approved_by: 'lead-engineer' });
      setPatchStatus(updated.status);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Approval failed');
    } finally {
      setLoadingStep(null);
    }
  };

  // Step 5: Human Rejection
  const handleReject = async () => {
    if (!patchId || !rejectReason.trim()) return;
    try {
      setError(null);
      setLoadingStep('reject');
      const updated = await rejectPatch(patchId, { reason: rejectReason });
      setPatchStatus(updated.status);
      setShowRejectInput(false);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Rejection failed');
    } finally {
      setLoadingStep(null);
    }
  };

  // Step 6: Human Requested Revision
  const handleRevise = async () => {
    if (!patchId || !revisionFeedback.trim()) return;
    try {
      setError(null);
      setLoadingStep('revise');
      const updated = await revisePatch(patchId, { user_feedback: revisionFeedback });
      setPatchStatus(updated.status);
      setShowReviseInput(false);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Revision request failed');
    } finally {
      setLoadingStep(null);
    }
  };

  // Step 7: Load Delivery Preview & Existing Delivery (Phase 5)
  useEffect(() => {
    if (!patchId || patchStatus !== 'APPROVED') return;

    let isMounted = true;
    const loadDeliveryData = async () => {
      try {
        const [prev, del] = await Promise.all([
          fetchDeliveryPreview(patchId).catch(() => null),
          fetchDeliveryByPatch(patchId).catch(() => null),
        ]);
        if (isMounted) {
          if (prev) setDeliveryPreview(prev);
          if (del) setDelivery(del);
        }
      } catch (err: unknown) {
        console.error('Failed to load delivery data:', err);
      }
    };

    loadDeliveryData();
    return () => {
      isMounted = false;
    };
  }, [patchId, patchStatus]);

  // Step 8: Execute Safe GitHub Delivery
  const handleDeliver = async () => {
    if (!patchId) return;
    try {
      setError(null);
      setLoadingStep('deliver');
      const res = await requestDelivery(patchId, {
        requested_by: deliveryRequestedBy.trim() || 'user',
        notes: deliveryNotes.trim() || undefined,
      });
      setDelivery(res);
      setShowDeliveryModal(false);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Pull request delivery failed');
    } finally {
      setLoadingStep(null);
    }
  };

  return (
    <div className="rounded-xl border border-neutral-800 bg-neutral-950 p-6 space-y-6 text-neutral-200">
      {/* Header & Badges */}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-neutral-800 pb-4">
        <div>
          <div className="flex items-center space-x-2">
            <h3 className="text-lg font-semibold text-neutral-100">{finding.title}</h3>
            <span className="px-2 py-0.5 text-xs font-semibold rounded bg-neutral-900 border border-neutral-700 text-neutral-300">
              {finding.severity}
            </span>
          </div>
          <p className="text-xs text-neutral-400 mt-1">{finding.description}</p>
        </div>

        {/* Dynamic Status Badges */}
        <div className="flex items-center space-x-2">
          <span className="px-2.5 py-1 text-[11px] font-bold rounded-md uppercase tracking-wider bg-purple-950/80 text-purple-300 border border-purple-800">
            🤖 AI GENERATED
          </span>

          {workflowResult?.verification_result?.status === 'PASSED' && (
            <span className="px-2.5 py-1 text-[11px] font-bold rounded-md uppercase tracking-wider bg-sky-950/80 text-sky-300 border border-sky-800">
              🛡️ DETERMINISTICALLY VERIFIED
            </span>
          )}

          {patchStatus === 'APPROVED' ? (
            <span className="px-2.5 py-1 text-[11px] font-bold rounded-md uppercase tracking-wider bg-emerald-950 text-emerald-300 border border-emerald-700">
              ✅ HUMAN APPROVED
            </span>
          ) : patchStatus === 'REJECTED' ? (
            <span className="px-2.5 py-1 text-[11px] font-bold rounded-md uppercase tracking-wider bg-rose-950 text-rose-300 border border-rose-800">
              ❌ REJECTED
            </span>
          ) : (
            <span className="px-2.5 py-1 text-[11px] font-bold rounded-md uppercase tracking-wider bg-amber-950/70 text-amber-300 border border-amber-800">
              ⏳ AWAITING HUMAN REVIEW
            </span>
          )}
        </div>
      </div>

      {error && (
        <div className="p-3 text-xs bg-rose-950/60 border border-rose-800 text-rose-300 rounded-lg">
          {error}
        </div>
      )}

      {/* Lifecycle Flow Tabs / Cards */}
      <div className="grid grid-cols-1 gap-4">
        {/* 1. Technical Research Card */}
        <div className="rounded-lg border border-neutral-800 bg-neutral-900/40 p-4 space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-neutral-300 uppercase tracking-wider">
              1. Technical Research & Upgrade Intelligence
            </span>
            <button
              onClick={handleRequestResearch}
              disabled={loadingStep === 'research'}
              className="px-3 py-1 text-xs font-medium bg-neutral-800 hover:bg-neutral-700 disabled:opacity-50 text-neutral-200 rounded border border-neutral-700 transition"
            >
              {loadingStep === 'research' ? 'Researching...' : research ? 'Re-run Research' : 'Investigate Library'}
            </button>
          </div>

          {research && (
            <div className="text-xs space-y-2 text-neutral-300 pt-2 border-t border-neutral-800">
              <div className="flex items-center justify-between">
                <span className="font-medium text-neutral-200">Library: {research.target_framework}</span>
                {research.recommended_version && (
                  <span className="text-[10px] text-sky-400 font-mono">Recommended: {research.recommended_version}</span>
                )}
              </div>
              <div>
                <span className="text-[11px] font-semibold text-neutral-400">Migration Summary: </span>
                <span>{research.migration_summary}</span>
              </div>
              <div>
                <span className="text-[11px] font-semibold text-neutral-400">Repository Impact: </span>
                <span className="text-neutral-400">{research.repository_impact}</span>
              </div>
            </div>
          )}
        </div>

        {/* 2. Structured Fix Plan Card */}
        <div className="rounded-lg border border-neutral-800 bg-neutral-900/40 p-4 space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-neutral-300 uppercase tracking-wider">
              2. Structured Root-Cause Fix Plan
            </span>
            <button
              onClick={handleRequestPlan}
              disabled={loadingStep === 'plan'}
              className="px-3 py-1 text-xs font-medium bg-neutral-800 hover:bg-neutral-700 disabled:opacity-50 text-neutral-200 rounded border border-neutral-700 transition"
            >
              {loadingStep === 'plan' ? 'Planning...' : plan ? 'Regenerate Plan' : 'Generate Fix Plan'}
            </button>
          </div>

          {plan && (
            <div className="text-xs space-y-2 text-neutral-300 pt-2 border-t border-neutral-800">
              <div>
                <span className="font-semibold text-neutral-400">Objective: </span>
                <span>{plan.objective}</span>
              </div>
              <div>
                <span className="font-semibold text-neutral-400">Root Cause: </span>
                <span>{plan.root_cause}</span>
              </div>
              <div>
                <span className="font-semibold text-neutral-400">Confined Target Files: </span>
                <span className="font-mono text-[11px] text-sky-400">{plan.files_expected_to_change.join(', ')}</span>
              </div>
            </div>
          )}
        </div>

        {/* 3. Candidate Unified Diff & Sandbox Verification */}
        <div className="rounded-lg border border-neutral-800 bg-neutral-900/40 p-4 space-y-4">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-neutral-300 uppercase tracking-wider">
              3. Proposed Patch & Sandbox Verification
            </span>
            <button
              onClick={handleRequestPatch}
              disabled={loadingStep === 'patch'}
              className="px-3 py-1 text-xs font-medium bg-sky-900/80 hover:bg-sky-800 disabled:opacity-50 text-sky-200 rounded border border-sky-700 transition"
            >
              {loadingStep === 'patch' ? 'Generating & Verifying...' : diff ? 'Regenerate Patch' : 'Generate Safe Patch'}
            </button>
          </div>

          {diff && (
            <div className="space-y-3">
              <DiffViewer unifiedDiff={diff} filesModified={filesModified} status={patchStatus} />

              {/* 12-Point Sandbox Verification Breakdown */}
              {workflowResult?.verification_result && (
                <div className="rounded-lg border border-neutral-800 bg-neutral-950 p-3 space-y-2 text-xs">
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-neutral-300">Deterministic 12-Point Sandbox Verification</span>
                    <span className="text-[10px] text-sky-400">
                      {workflowResult.verification_result.checks_passed.length} / 12 Checks Passed
                    </span>
                  </div>
                  <p className="text-[11px] text-neutral-400">{workflowResult.verification_result.explanation}</p>
                </div>
              )}

              {/* Independent Critic Telemetry if Triggered */}
              {workflowResult?.critic_report && (
                <div className="rounded-lg border border-neutral-800 bg-neutral-950 p-3 space-y-1 text-xs">
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-purple-300">Independent Patch Critic Report</span>
                    <span className="text-[10px] uppercase font-bold text-purple-400">
                      Verdict: {workflowResult.critic_report.verdict}
                    </span>
                  </div>
                  <p className="text-[11px] text-neutral-400">{workflowResult.critic_report.evidence_notes}</p>
                </div>
              )}
            </div>
          )}
        </div>

        {/* 4. Human Approval Action Gate */}
        {diff && patchStatus !== 'APPROVED' && patchStatus !== 'REJECTED' && (
          <div className="rounded-lg border border-amber-900/50 bg-amber-950/20 p-4 space-y-3">
            <div className="flex items-center justify-between">
              <div>
                <span className="text-xs font-bold text-amber-300 uppercase tracking-wider">
                  4. Human Authorization Checkpoint
                </span>
                <p className="text-[11px] text-neutral-400 mt-0.5">
                  LLM generated changes require explicit human authorization before remediation merge.
                </p>
              </div>

              <div className="flex items-center space-x-2">
                <button
                  onClick={() => setShowReviseInput(!showReviseInput)}
                  className="px-3 py-1.5 text-xs font-medium bg-neutral-800 hover:bg-neutral-700 text-neutral-200 rounded border border-neutral-700 transition"
                >
                  Request Revision
                </button>
                <button
                  onClick={() => setShowRejectInput(!showRejectInput)}
                  className="px-3 py-1.5 text-xs font-medium bg-rose-950 hover:bg-rose-900 text-rose-300 rounded border border-rose-800 transition"
                >
                  Reject
                </button>
                <button
                  onClick={handleApprove}
                  disabled={loadingStep === 'approve'}
                  className="px-4 py-1.5 text-xs font-semibold bg-emerald-700 hover:bg-emerald-600 disabled:opacity-50 text-white rounded border border-emerald-600 shadow-sm transition"
                >
                  {loadingStep === 'approve' ? 'Approving...' : 'Approve Patch'}
                </button>
              </div>
            </div>

            {/* Revision Feedback Input */}
            {showReviseInput && (
              <div className="space-y-2 pt-2 border-t border-amber-900/40">
                <label className="text-[11px] font-medium text-neutral-300">
                  Targeted Revision Feedback (Allows 1 Automatic Revision):
                </label>
                <div className="flex items-center space-x-2">
                  <input
                    type="text"
                    value={revisionFeedback}
                    onChange={(e) => setRevisionFeedback(e.target.value)}
                    placeholder="e.g. Please add explicit type annotations and timezone check"
                    className="flex-1 bg-neutral-900 border border-neutral-700 rounded px-3 py-1.5 text-xs text-neutral-200 focus:outline-none focus:border-sky-500"
                  />
                  <button
                    onClick={handleRevise}
                    disabled={!revisionFeedback.trim() || loadingStep === 'revise'}
                    className="px-3 py-1.5 text-xs font-medium bg-sky-800 hover:bg-sky-700 disabled:opacity-50 text-sky-100 rounded transition"
                  >
                    Submit
                  </button>
                </div>
              </div>
            )}

            {/* Rejection Justification Input */}
            {showRejectInput && (
              <div className="space-y-2 pt-2 border-t border-amber-900/40">
                <label className="text-[11px] font-medium text-neutral-300">
                  Rejection Justification:
                </label>
                <div className="flex items-center space-x-2">
                  <input
                    type="text"
                    value={rejectReason}
                    onChange={(e) => setRejectReason(e.target.value)}
                    placeholder="e.g. Breaks backward compatibility with legacy endpoints"
                    className="flex-1 bg-neutral-900 border border-neutral-700 rounded px-3 py-1.5 text-xs text-neutral-200 focus:outline-none focus:border-rose-500"
                  />
                  <button
                    onClick={handleReject}
                    disabled={!rejectReason.trim() || loadingStep === 'reject'}
                    className="px-3 py-1.5 text-xs font-medium bg-rose-800 hover:bg-rose-700 disabled:opacity-50 text-rose-100 rounded transition"
                  >
                    Confirm Rejection
                  </button>
                </div>
              </div>
            )}
          </div>
        )}

        {/* 5. GitHub Pull Request Delivery (Phase 5) */}
        {patchStatus === 'APPROVED' && (
          <div className="rounded-lg border border-emerald-900/60 bg-emerald-950/20 p-5 space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <span className="text-xs font-bold text-emerald-400 uppercase tracking-wider flex items-center gap-1.5">
                  <span>🚀</span> 5. Safe GitHub Delivery & Pull Request
                </span>
                <p className="text-[11px] text-neutral-400 mt-0.5">
                  Deliver the human-approved patch to a dedicated remediation branch on GitHub. No direct writes to main.
                </p>
              </div>

              {delivery?.status === 'PR_CREATED' ? (
                <a
                  href={delivery.pr_url || '#'}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="px-4 py-1.5 text-xs font-semibold bg-emerald-700 hover:bg-emerald-600 text-white rounded border border-emerald-500 inline-flex items-center gap-1.5 shadow-sm transition"
                >
                  <span>View PR #{delivery.pr_number} on GitHub</span>
                  <span>↗</span>
                </a>
              ) : (
                <button
                  onClick={() => setShowDeliveryModal(true)}
                  disabled={
                    loadingStep === 'deliver' ||
                    (deliveryPreview !== null && (!deliveryPreview.eligible || !deliveryPreview.github_delivery_configured)) ||
                    delivery?.status === 'BLOCKED'
                  }
                  className="px-4 py-1.5 text-xs font-semibold bg-emerald-700 hover:bg-emerald-600 disabled:opacity-50 disabled:cursor-not-allowed text-white rounded border border-emerald-600 shadow-sm transition inline-flex items-center gap-1.5"
                >
                  {loadingStep === 'deliver' ? (
                    'Creating Pull Request...'
                  ) : (
                    <>
                      <span>Open GitHub Pull Request</span>
                      <span>→</span>
                    </>
                  )}
                </button>
              )}
            </div>

            {/* Unconfigured GitHub Delivery Warning */}
            {deliveryPreview && !deliveryPreview.github_delivery_configured && (
              <div className="rounded-lg border border-amber-800 bg-amber-950/40 p-3.5 text-xs space-y-1 text-amber-200">
                <div className="flex items-center gap-2 font-semibold text-amber-300">
                  <span>⚠️ GitHub Delivery Not Configured</span>
                </div>
                <p className="text-[11px] text-amber-300/90">
                  GitHub delivery is not configured for this RepoLens instance.
                </p>
              </div>
            )}

            {/* Success Banner if PR is Created */}
            {delivery?.status === 'PR_CREATED' && (
              <div className="rounded-lg border border-emerald-700 bg-emerald-950/60 p-3.5 text-xs space-y-2">
                <div className="flex items-center justify-between text-emerald-300 font-semibold">
                  <span>✅ Pull Request Created Successfully</span>
                  <span className="font-mono text-[11px]">PR #{delivery.pr_number}</span>
                </div>
                <div className="grid grid-cols-2 gap-2 text-[11px] text-neutral-300 pt-1 border-t border-emerald-900/60">
                  <div>
                    <span className="text-neutral-400">Head Branch: </span>
                    <span className="font-mono text-emerald-400">{delivery.head_branch}</span>
                  </div>
                  <div>
                    <span className="text-neutral-400">Base Branch: </span>
                    <span className="font-mono text-emerald-400">{delivery.base_branch}</span>
                  </div>
                  <div>
                    <span className="text-neutral-400">Commit SHA: </span>
                    <span className="font-mono text-neutral-300">{delivery.head_sha?.slice(0, 8)}</span>
                  </div>
                  <div>
                    <span className="text-neutral-400">Delivered By: </span>
                    <span>{delivery.requested_by}</span>
                  </div>
                </div>
              </div>
            )}

            {/* Base Drift Warning Banner */}
            {(deliveryPreview?.failure_code === 'BLOCKED_BASE_DRIFT' ||
              delivery?.failure_code === 'BLOCKED_BASE_DRIFT') && (
              <div className="rounded-lg border border-amber-800 bg-amber-950/40 p-3.5 text-xs space-y-1.5 text-amber-200">
                <div className="flex items-center gap-2 font-semibold text-amber-300">
                  <span>⚠️ Base Branch Drift Detected</span>
                </div>
                <p className="text-[11px] text-amber-300/90 leading-relaxed">
                  The remote repository base branch has updated on GitHub since this scan was performed. To ensure exact-commit patch integrity, automated delivery is blocked.
                </p>
                <div className="text-[10px] font-mono text-amber-400/80 pt-1">
                  Scanned Base SHA: {deliveryPreview?.scanned_base_sha?.slice(0, 8) || 'N/A'} | Current Remote HEAD: {deliveryPreview?.observed_base_sha?.slice(0, 8) || 'N/A'}
                </div>
                <p className="text-[11px] font-medium text-amber-200 pt-0.5">
                  Please initiate a new repository scan before opening a pull request.
                </p>
              </div>
            )}

            {/* Delivery Preview Parameters */}
            {deliveryPreview && delivery?.status !== 'PR_CREATED' && (
              <div className="rounded-lg border border-neutral-800 bg-neutral-950 p-3.5 space-y-2 text-xs">
                <div className="flex items-center justify-between text-neutral-300 font-medium">
                  <span>Target Repository: {deliveryPreview.repository_owner}/{deliveryPreview.repository_name}</span>
                  <span className="text-[11px] text-sky-400 font-mono">Base: {deliveryPreview.base_branch}</span>
                </div>
                <div className="grid grid-cols-2 gap-2 text-[11px] text-neutral-400 pt-1 border-t border-neutral-800">
                  <div>
                    <span>Dedicated Branch: </span>
                    <span className="font-mono text-neutral-200">{deliveryPreview.proposed_branch_name}</span>
                  </div>
                  <div>
                    <span>Modified Files: </span>
                    <span className="text-neutral-200">{deliveryPreview.files_modified.length} file(s)</span>
                  </div>
                </div>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Delivery Confirmation Modal */}
      {showDeliveryModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 p-4 backdrop-blur-xs">
          <div className="w-full max-w-lg rounded-xl border border-neutral-800 bg-neutral-950 p-6 shadow-2xl space-y-5 text-neutral-200">
            <div className="flex items-center justify-between border-b border-neutral-800 pb-3">
              <h3 className="text-base font-semibold text-neutral-100 flex items-center gap-2">
                <span>🛡️</span> Confirm GitHub Pull Request Delivery
              </h3>
              <button
                onClick={() => setShowDeliveryModal(false)}
                className="text-neutral-400 hover:text-neutral-200 transition"
              >
                ✕
              </button>
            </div>

            <div className="text-xs space-y-3 text-neutral-300">
              <div className="rounded-lg bg-neutral-900 p-3 space-y-1.5 border border-neutral-800">
                <div className="flex justify-between">
                  <span className="text-neutral-400">Target Repository:</span>
                  <span className="font-semibold text-neutral-100">
                    {deliveryPreview?.repository_owner}/{deliveryPreview?.repository_name}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-neutral-400">Target Base Branch:</span>
                  <span className="font-mono text-sky-400">{deliveryPreview?.base_branch || 'main'}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-neutral-400">New Dedicated Branch:</span>
                  <span className="font-mono text-emerald-400">{deliveryPreview?.proposed_branch_name}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-neutral-400">Files to Patch:</span>
                  <span>{deliveryPreview?.files_modified.length || 0} file(s)</span>
                </div>
              </div>

              {/* Safety Guarantees Callout */}
              <div className="rounded-lg bg-sky-950/30 border border-sky-900/60 p-3 space-y-1 text-[11px] text-sky-300">
                <div className="font-semibold">Safety Boundary & Execution Rules:</div>
                <ul className="list-disc list-inside space-y-0.5 text-neutral-300">
                  <li>RepoLens will <strong>never write directly</strong> to the default/base branch.</li>
                  <li>RepoLens will <strong>never automatically merge</strong> or close pull requests.</li>
                  <li>The pull request contains human-approved code verified against commit <code>{deliveryPreview?.scanned_base_sha?.slice(0, 8)}</code>.</li>
                </ul>
              </div>

              {/* Sign-off Inputs */}
              <div className="space-y-2 pt-1">
                <div>
                  <label className="block text-[11px] font-medium text-neutral-300 mb-1">
                    Requested By (User Identifier):
                  </label>
                  <input
                    type="text"
                    value={deliveryRequestedBy}
                    onChange={(e) => setDeliveryRequestedBy(e.target.value)}
                    placeholder="e.g. lead-engineer"
                    className="w-full bg-neutral-900 border border-neutral-700 rounded px-3 py-1.5 text-xs text-neutral-200 focus:outline-none focus:border-sky-500"
                  />
                </div>
                <div>
                  <label className="block text-[11px] font-medium text-neutral-300 mb-1">
                    Optional Delivery Notes / Sign-off:
                  </label>
                  <textarea
                    rows={2}
                    value={deliveryNotes}
                    onChange={(e) => setDeliveryNotes(e.target.value)}
                    placeholder="e.g. Reviewed and authorized for production remediation"
                    className="w-full bg-neutral-900 border border-neutral-700 rounded px-3 py-1.5 text-xs text-neutral-200 focus:outline-none focus:border-sky-500 resize-none"
                  />
                </div>
              </div>
            </div>

            <div className="flex items-center justify-end space-x-3 pt-2 border-t border-neutral-800">
              <button
                onClick={() => setShowDeliveryModal(false)}
                className="px-3.5 py-1.5 text-xs font-medium text-neutral-400 hover:text-neutral-200 transition"
              >
                Cancel
              </button>
              <button
                onClick={handleDeliver}
                disabled={loadingStep === 'deliver'}
                className="px-4 py-1.5 text-xs font-semibold bg-emerald-700 hover:bg-emerald-600 disabled:opacity-50 text-white rounded border border-emerald-600 shadow-sm transition"
              >
                {loadingStep === 'deliver' ? 'Delivering...' : 'Confirm & Create Pull Request'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

