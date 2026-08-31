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
import { ResearchPanel } from './ResearchPanel';
import { FixPlanPanel } from './FixPlanPanel';
import { PatchCandidatePanel } from './PatchCandidatePanel';
import { HumanReviewControls } from './HumanReviewControls';
import { DeliveryPreviewModal } from './DeliveryPreviewModal';
import { Alert } from '@/components/ui/Alert';

export interface RemediationLifecycleProps {
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
        <div className="flex items-center space-x-2 flex-wrap gap-1.5">
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

      {error && <Alert variant="error">{error}</Alert>}

      {/* Lifecycle Steps */}
      <div className="grid grid-cols-1 gap-4">
        {/* 1. Technical Research */}
        <ResearchPanel
          research={research}
          isLoading={loadingStep === 'research'}
          onRequestResearch={handleRequestResearch}
        />

        {/* 2. Structured Fix Plan */}
        <FixPlanPanel
          plan={plan}
          isLoading={loadingStep === 'plan'}
          onRequestPlan={handleRequestPlan}
        />

        {/* 3. Patch Candidate & Sandbox Verification */}
        <PatchCandidatePanel
          diff={diff}
          filesModified={filesModified}
          patchStatus={patchStatus}
          workflowResult={workflowResult}
          isLoading={loadingStep === 'patch'}
          onRequestPatch={handleRequestPatch}
        />

        {/* 4. Human Approval / Rejection / Revision Gate */}
        {diff && patchStatus !== 'APPROVED' && patchStatus !== 'REJECTED' && (
          <HumanReviewControls
            patchStatus={patchStatus}
            loadingStep={loadingStep}
            showReviseInput={showReviseInput}
            onToggleReviseInput={() => setShowReviseInput(!showReviseInput)}
            showRejectInput={showRejectInput}
            onToggleRejectInput={() => setShowRejectInput(!showRejectInput)}
            revisionFeedback={revisionFeedback}
            onRevisionFeedbackChange={setRevisionFeedback}
            rejectReason={rejectReason}
            onRejectReasonChange={setRejectReason}
            onApprove={handleApprove}
            onRevise={handleRevise}
            onReject={handleReject}
          />
        )}

        {/* 5. GitHub Pull Request Delivery (Phase 5) */}
        {patchStatus === 'APPROVED' && (
          <div className="rounded-lg border border-emerald-900/60 bg-emerald-950/20 p-5 space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <span className="text-xs font-bold text-emerald-400 uppercase tracking-wider flex items-center gap-1.5">
                  <span aria-hidden="true">🚀</span> 5. Safe GitHub Delivery & Pull Request
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
                  <span aria-hidden="true">↗</span>
                </a>
              ) : (
                <button
                  type="button"
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
                      <span aria-hidden="true">→</span>
                    </>
                  )}
                </button>
              )}
            </div>

            {/* Unconfigured GitHub Delivery Warning */}
            {deliveryPreview && !deliveryPreview.github_delivery_configured && (
              <div className="rounded-lg border border-amber-800 bg-amber-950/40 p-3.5 text-xs space-y-1 text-amber-200">
                <div className="flex items-center gap-2 font-semibold text-amber-300">
                  <span aria-hidden="true">⚠️</span> GitHub Delivery Not Configured
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
                  <span aria-hidden="true">⚠️</span> Base Branch Drift Detected
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
      <DeliveryPreviewModal
        isOpen={showDeliveryModal}
        onClose={() => setShowDeliveryModal(false)}
        deliveryPreview={deliveryPreview}
        deliveryRequestedBy={deliveryRequestedBy}
        onDeliveryRequestedByChange={setDeliveryRequestedBy}
        deliveryNotes={deliveryNotes}
        onDeliveryNotesChange={setDeliveryNotes}
        onConfirmDelivery={handleDeliver}
        isDelivering={loadingStep === 'deliver'}
      />
    </div>
  );
};
