import React from 'react';
import { PatchWorkflowResult } from '@/types/domain';
import { Button } from '@/components/ui/Button';
import { DiffViewer } from '@/features/diff/DiffViewer';

export interface PatchCandidatePanelProps {
  diff: string;
  filesModified: string[];
  patchStatus: string;
  workflowResult: PatchWorkflowResult | null;
  isLoading: boolean;
  onRequestPatch: () => void;
}

export const PatchCandidatePanel: React.FC<PatchCandidatePanelProps> = ({
  diff,
  filesModified,
  patchStatus,
  workflowResult,
  isLoading,
  onRequestPatch,
}) => {
  return (
    <div className="rounded-lg border border-neutral-800 bg-neutral-900/40 p-4 space-y-4">
      <div className="flex items-center justify-between flex-wrap gap-2">
        <span className="text-xs font-semibold text-neutral-300 uppercase tracking-wider">
          3. Proposed Patch & Sandbox Verification
        </span>
        <Button
          variant="filter"
          size="sm"
          onClick={onRequestPatch}
          disabled={isLoading}
          isLoading={isLoading}
          className="bg-sky-900/80 hover:bg-sky-800 text-sky-200 border-sky-700"
        >
          {isLoading
            ? 'Generating & Verifying...'
            : diff
            ? 'Regenerate Patch'
            : 'Generate Safe Patch'}
        </Button>
      </div>

      {diff && (
        <div className="space-y-3">
          <DiffViewer
            unifiedDiff={diff}
            filesModified={filesModified}
            status={patchStatus}
          />

          {/* 12-Point Sandbox Verification Breakdown */}
          {workflowResult?.verification_result && (
            <div className="rounded-lg border border-neutral-800 bg-neutral-950 p-3 space-y-2 text-xs">
              <div className="flex items-center justify-between flex-wrap gap-2">
                <span className="font-semibold text-neutral-300">
                  Deterministic 12-Point Sandbox Verification
                </span>
                <span className="text-[10px] text-sky-400 font-mono">
                  {workflowResult.verification_result.checks_passed.length} / 12 Checks Passed
                </span>
              </div>
              <p className="text-[11px] text-neutral-400 leading-relaxed">
                {workflowResult.verification_result.explanation}
              </p>
            </div>
          )}

          {/* Independent Critic Telemetry if Triggered */}
          {workflowResult?.critic_report && (
            <div className="rounded-lg border border-neutral-800 bg-neutral-950 p-3 space-y-1 text-xs">
              <div className="flex items-center justify-between flex-wrap gap-2">
                <span className="font-semibold text-purple-300">
                  Independent Patch Critic Report
                </span>
                <span className="text-[10px] uppercase font-bold text-purple-400 font-mono">
                  Verdict: {workflowResult.critic_report.verdict}
                </span>
              </div>
              <p className="text-[11px] text-neutral-400 leading-relaxed">
                {workflowResult.critic_report.evidence_notes}
              </p>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
