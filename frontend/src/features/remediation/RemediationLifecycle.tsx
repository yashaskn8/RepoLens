'use client';

import React, { useEffect, useRef, useState } from 'react';
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
  fetchDelivery,
  fetchDeliveryPreview,
  fetchScanPatches,
  fetchJobResult,
  listJobs,
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
import { useAuth } from '@/context/AuthContext';
import { findLatestRemediationJobs } from '@/lib/remediationHistory';

export interface RemediationLifecycleProps {
  finding: Finding;
  initialPatch?: PatchResponse | null;
}

export const RemediationLifecycle: React.FC<RemediationLifecycleProps> = ({
  finding,
  initialPatch = null,
}) => {
  const { isOperator, user } = useAuth();
  const [research, setResearch] = useState<ResearchResult | null>(null);
  const [plan, setPlan] = useState<FixPlan | null>(null);
  const [workflowResult, setWorkflowResult] = useState<PatchWorkflowResult | null>(null);
  const [patchStatus, setPatchStatus] = useState<string>(initialPatch?.status || 'DRAFT');
  const [revisionNumber, setRevisionNumber] = useState<number>(initialPatch?.revision_number ?? 0);
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
  const localPatchActionRef = useRef(false);
  const researchActionRef = useRef(false);
  const planActionRef = useRef(false);
  // One lifecycle action at a time: an old approval must not authorize a new patch.
  const actionInFlightRef = useRef(false);

  // Reset state whenever the selected finding changes. Do not carry a
  // previous finding's patch or delivery approval to another resource.
  useEffect(() => {
    localPatchActionRef.current = false;
    researchActionRef.current = false;
    planActionRef.current = false;
    setResearch(null);
    setPlan(null);
    setWorkflowResult(null);
    setPatchId(initialPatch?.id || null);
    setPatchStatus(initialPatch?.status || 'DRAFT');
    setRevisionNumber(initialPatch?.revision_number ?? 0);
    setDiff(initialPatch?.unified_diff || '');
    setFilesModified(initialPatch?.files_modified || []);
    setDelivery(null);
    setDeliveryPreview(null);
    setError(null);
  }, [finding.id, initialPatch?.id]);

  // Restore the latest persisted proposal after refresh. A late recovery
  // response must not overwrite a newly generated or revised patch.
  useEffect(() => {
    if (initialPatch) return;
    let active = true;
    void (async () => {
      try {
        const history = await fetchScanPatches(finding.scan_id);
        if (!active || localPatchActionRef.current) return;
        const saved = history.find((patch) => patch.finding_id === finding.id);
        if (!saved) return;
        setPatchId(saved.id);
        setPatchStatus(saved.status);
        setRevisionNumber(saved.revision_number ?? 0);
        setDiff(saved.unified_diff);
        setFilesModified(saved.files_modified);
        setWorkflowResult(null);
      } catch {
        if (active && !localPatchActionRef.current) {
          setError('Saved patch history could not be loaded; retry after checking the API connection.');
        }
      }
    })();
    return () => { active = false; };
  }, [finding.id, finding.scan_id, initialPatch?.id]);

  // Restore previously completed research and planning artifacts from the
  // tenant-owned durable jobs. Never replay provider work just to recover UI.
  useEffect(() => {
    let active = true;
    void (async () => {
      try {
        const latest = await findLatestRemediationJobs(
          finding.id, (cursor) => listJobs(100, cursor),
        );
        const [restoredResearch, restoredPlan] = await Promise.allSettled([
          latest.research?.state === 'SUCCEEDED'
            ? fetchJobResult<ResearchResult>(latest.research.id)
            : Promise.resolve(null),
          latest.plan?.state === 'SUCCEEDED'
            ? fetchJobResult<FixPlan>(latest.plan.id)
            : Promise.resolve(null),
        ]);
        if (!active) return;
        if (restoredResearch.status === 'fulfilled' && restoredResearch.value && !researchActionRef.current) {
          setResearch(restoredResearch.value);
        }
        if (restoredPlan.status === 'fulfilled' && restoredPlan.value && !planActionRef.current) {
          setPlan(restoredPlan.value);
        }
        if (
          (restoredResearch.status === 'rejected' && !researchActionRef.current) ||
          (restoredPlan.status === 'rejected' && !planActionRef.current)
        ) {
          setError('Some persisted remediation artifacts could not be restored.');
        }
      } catch {
        if (active && !researchActionRef.current && !planActionRef.current) {
          setError('Remediation job history is unavailable or incomplete.');
        }
      }
    })();
    return () => { active = false; };
  }, [finding.id]);

  // Step 1: Request Research
  const handleRequestResearch = async () => {
    if (actionInFlightRef.current) return;
    actionInFlightRef.current = true;
    try {
      setError(null);
      setLoadingStep('research');
      // Invalidate an older persisted result as soon as a new request starts,
      // not only after it completes. Recovery can resolve while this is pending.
      researchActionRef.current = true;
      const res = await requestFindingResearch(finding.id);
      setResearch(res);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Research failed');
    } finally {
      actionInFlightRef.current = false;
      setLoadingStep(null);
    }
  };

  // Step 2: Request Fix Plan
  const handleRequestPlan = async () => {
    if (actionInFlightRef.current) return;
    actionInFlightRef.current = true;
    try {
      setError(null);
      setLoadingStep('plan');
      // A pending new plan supersedes a late historical plan response.
      planActionRef.current = true;
      const res = await requestFixPlan(finding.id);
      setPlan(res);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Fix plan generation failed');
    } finally {
      actionInFlightRef.current = false;
      setLoadingStep(null);
    }
  };

  // Step 3: Request Safe Patch Generation & Sandbox Verification
  const handleRequestPatch = async () => {
    if (actionInFlightRef.current) return;
    actionInFlightRef.current = true;
    try {
      setError(null);
      setLoadingStep('patch');
      const res = await requestPatchGeneration(finding.id);
      localPatchActionRef.current = true;
      setWorkflowResult(res);
      setPatchId(res.proposal.id);
      setRevisionNumber(0);
      setDiff(res.proposal.unified_diff);
      setFilesModified(res.proposal.files_modified);
      setDelivery(null);
      setDeliveryPreview(null);
      setPatchStatus(
        res.machine_verdict === 'REJECTED' || res.verification_result?.status === 'FAILED'
          ? 'REJECTED'
          : res.machine_verdict === 'PASSED' && res.verification_result?.status === 'PASSED'
          ? 'VERIFIED'
          : 'NEEDS_REVIEW'
      );
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Patch generation failed');
    } finally {
      actionInFlightRef.current = false;
      setLoadingStep(null);
    }
  };

  // Step 4: Human Approval
  const handleApprove = async () => {
    if (!patchId) return;
    if (actionInFlightRef.current) return;
    actionInFlightRef.current = true;
    try {
      setError(null);
      setLoadingStep('approve');
      const updated = await approvePatch(patchId, {});
      setPatchStatus(updated.status);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Approval failed');
    } finally {
      actionInFlightRef.current = false;
      setLoadingStep(null);
    }
  };

  // Step 5: Human Rejection
  const handleReject = async () => {
    if (!patchId || !rejectReason.trim()) return;
    if (actionInFlightRef.current) return;
    actionInFlightRef.current = true;
    try {
      setError(null);
      setLoadingStep('reject');
      const updated = await rejectPatch(patchId, { reason: rejectReason });
      setPatchStatus(updated.status);
      setShowRejectInput(false);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Rejection failed');
    } finally {
      actionInFlightRef.current = false;
      setLoadingStep(null);
    }
  };

  // Step 6: Human Requested Revision
  const handleRevise = async () => {
    if (!patchId || !revisionFeedback.trim()) return;
    if (actionInFlightRef.current) return;
    actionInFlightRef.current = true;
    try {
      setError(null);
      setLoadingStep('revise');
      const updated = await revisePatch(patchId, { user_feedback: revisionFeedback });
      localPatchActionRef.current = true;
      // A revision is a different persisted patch. The old ID/diff and
      // verifier result must not remain actionable as the child proposal.
      setPatchId(updated.id);
      setDiff(updated.unified_diff);
      setFilesModified(updated.files_modified);
      setPatchStatus(updated.status);
      setRevisionNumber(updated.revision_number ?? 1);
      setWorkflowResult(null);
      setDeliveryPreview(null);
      setDelivery(null);
      setRevisionFeedback('');
      setShowReviseInput(false);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Revision request failed');
    } finally {
      actionInFlightRef.current = false;
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
          fetchDeliveryPreview(patchId),
          fetchDeliveryByPatch(patchId).catch(() => null),
        ]);
        if (isMounted) {
          setDeliveryPreview(prev);
          setDelivery(del);
        }
      } catch {
        if (isMounted) {
          setDeliveryPreview(null);
          setError('Delivery preview is unavailable. GitHub delivery remains blocked until the server confirms eligibility.');
        }
      }
    };

    loadDeliveryData();
    return () => {
      isMounted = false;
    };
  }, [patchId, patchStatus]);

  // A successful submission may only enqueue GitHub delivery. Keep
  // reading the same authorized record until a terminal state is persisted;
  // never submit another write because the initial response was HTTP 202.
  useEffect(() => {
    if (!delivery?.id || ['PR_CREATED', 'FAILED', 'BLOCKED'].includes(delivery.status)) return;
    let active = true;
    let attempts = 0;
    let timer: ReturnType<typeof setTimeout> | null = null;
    const refresh = async () => {
      try {
        const next = await fetchDelivery(delivery.id);
        if (!active) return;
        if (next.id !== delivery.id || next.patch_id !== patchId) {
          setError('Delivery status does not match the approved patch.');
          return;
        }
        setDelivery(next);
        if (['PR_CREATED', 'FAILED', 'BLOCKED'].includes(next.status)) return;
      } catch {
        if (active) setError('Delivery status could not be refreshed. Check the persisted delivery before retrying.');
      }
      if (active && ++attempts < 120) {
        timer = setTimeout(() => { void refresh(); }, 2000);
      } else if (active) {
        setError('GitHub delivery is still processing. Refresh the page to recover its persisted state.');
      }
    };
    timer = setTimeout(() => { void refresh(); }, 2000);
    return () => {
      active = false;
      if (timer !== null) clearTimeout(timer);
    };
  }, [delivery?.id, delivery?.status, patchId]);

  // Step 8: Execute Safe GitHub Delivery
  const handleDeliver = async () => {
    if (!patchId || !user?.id || !isOperator || !deliveryPreview?.eligible || !deliveryPreview.github_delivery_configured) {
      setError('GitHub delivery requires an authorized operator and a confirmed eligible preview.');
      return;
    }
    if (actionInFlightRef.current) return;
    actionInFlightRef.current = true;
    try {
      setError(null);
      setLoadingStep('deliver');
      const res = await requestDelivery(patchId, {
        requested_by: user.id,
        notes: deliveryNotes.trim() || undefined,
      });
      setDelivery(res);
      setShowDeliveryModal(false);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Pull request delivery failed');
    } finally {
      actionInFlightRef.current = false;
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
          {patchId && (
            <span className="px-2.5 py-1 text-[11px] font-bold rounded-md uppercase tracking-wider bg-purple-950/80 text-purple-300 border border-purple-800">
              🤖 AI GENERATED
            </span>
          )}

          {workflowResult?.verification_result?.status === 'PASSED' && (
            <span className="px-2.5 py-1 text-[11px] font-bold rounded-md uppercase tracking-wider bg-sky-950/80 text-sky-300 border border-sky-800">
              🛡️ DETERMINISTICALLY VERIFIED
            </span>
          )}

          {!patchId ? (
            <span className="px-2.5 py-1 text-[11px] font-bold rounded-md uppercase tracking-wider bg-neutral-900 text-neutral-300 border border-neutral-700">
              No patch proposal yet
            </span>
          ) : patchStatus === 'APPROVED' ? (
            <span className="px-2.5 py-1 text-[11px] font-bold rounded-md uppercase tracking-wider bg-emerald-950 text-emerald-300 border border-emerald-700">
              ✅ HUMAN APPROVED
            </span>
          ) : patchStatus === 'REJECTED' ? (
            <span className="px-2.5 py-1 text-[11px] font-bold rounded-md uppercase tracking-wider bg-rose-950 text-rose-300 border border-rose-800">
              ❌ REJECTED
            </span>
          ) : (
            <span className="px-2.5 py-1 text-[11px] font-bold rounded-md uppercase tracking-wider bg-amber-950/70 text-amber-300 border border-amber-800">
              {patchStatus === 'DRAFT' ? 'Not yet verified' : 'Awaiting human review'}
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
          disabled={loadingStep !== null}
          onRequestResearch={handleRequestResearch}
        />

        {/* 2. Structured Fix Plan */}
        <FixPlanPanel
          plan={plan}
          isLoading={loadingStep === 'plan'}
          disabled={loadingStep !== null}
          onRequestPlan={handleRequestPlan}
        />

        {/* 3. Patch Candidate & Sandbox Verification */}
        <PatchCandidatePanel
          diff={diff}
          filesModified={filesModified}
          patchStatus={patchStatus}
          workflowResult={workflowResult}
          isLoading={loadingStep === 'patch'}
          disabled={loadingStep !== null}
          onRequestPatch={handleRequestPatch}
        />

        {/* 4. Human Approval / Rejection / Revision Gate */}
        {diff && patchStatus !== 'APPROVED' && patchStatus !== 'REJECTED' && (
          <HumanReviewControls
            patchStatus={patchStatus}
            canRevise={revisionNumber < 1}
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
                    loadingStep !== null ||
                    !isOperator ||
                    !deliveryPreview?.eligible ||
                    !deliveryPreview.github_delivery_configured ||
                    (delivery !== null && !['FAILED', 'BLOCKED'].includes(delivery.status))
                  }
                  className="px-4 py-1.5 text-xs font-semibold bg-emerald-700 hover:bg-emerald-600 disabled:opacity-50 disabled:cursor-not-allowed text-white rounded border border-emerald-600 shadow-sm transition inline-flex items-center gap-1.5"
                >
                  {loadingStep === 'deliver' || (delivery !== null && !['FAILED', 'BLOCKED'].includes(delivery.status)) ? (
                    'Delivery in progress...'
                  ) : (
                    <>
                      <span>Open GitHub Pull Request</span>
                      <span aria-hidden="true">→</span>
                    </>
                  )}
                </button>
              )}
            </div>

            {!isOperator && (
              <Alert variant="warning">GitHub delivery requires an operator account. You may review the approved patch without publishing it.</Alert>
            )}

            {deliveryPreview && !deliveryPreview.eligible && (
              <Alert variant="warning">{deliveryPreview.blocking_reason || 'The server did not approve this delivery preview.'}</Alert>
            )}

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
        deliveryNotes={deliveryNotes}
        onDeliveryNotesChange={setDeliveryNotes}
        onConfirmDelivery={handleDeliver}
        isDelivering={loadingStep === 'deliver'}
      />
    </div>
  );
};
