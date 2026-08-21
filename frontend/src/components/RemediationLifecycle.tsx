'use client';

import React, { useState } from 'react';
import {
  Finding,
  FixPlan,
  PatchResponse,
  PatchWorkflowResult,
  ResearchResult,
} from '@/types/domain';
import {
  approvePatch,
  rejectPatch,
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
      </div>
    </div>
  );
};
