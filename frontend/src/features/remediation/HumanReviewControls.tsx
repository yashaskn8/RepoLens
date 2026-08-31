import React from 'react';
import { Button } from '@/components/ui/Button';

export interface HumanReviewControlsProps {
  patchStatus: string;
  loadingStep: string | null;
  showReviseInput: boolean;
  onToggleReviseInput: () => void;
  showRejectInput: boolean;
  onToggleRejectInput: () => void;
  revisionFeedback: string;
  onRevisionFeedbackChange: (val: string) => void;
  rejectReason: string;
  onRejectReasonChange: (val: string) => void;
  onApprove: () => void;
  onRevise: () => void;
  onReject: () => void;
}

export const HumanReviewControls: React.FC<HumanReviewControlsProps> = ({
  loadingStep,
  showReviseInput,
  onToggleReviseInput,
  showRejectInput,
  onToggleRejectInput,
  revisionFeedback,
  onRevisionFeedbackChange,
  rejectReason,
  onRejectReasonChange,
  onApprove,
  onRevise,
  onReject,
}) => {
  return (
    <div className="rounded-lg border border-amber-900/50 bg-amber-950/20 p-4 space-y-3">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <span className="text-xs font-bold text-amber-300 uppercase tracking-wider">
            4. Human Authorization Checkpoint
          </span>
          <p className="text-[11px] text-neutral-400 mt-0.5">
            LLM generated changes require explicit human authorization before remediation merge.
          </p>
        </div>

        <div className="flex items-center space-x-2 flex-wrap gap-2">
          <Button
            variant="filter"
            size="sm"
            onClick={onToggleReviseInput}
          >
            Request Revision
          </Button>
          <Button
            variant="danger"
            size="sm"
            onClick={onToggleRejectInput}
          >
            Reject
          </Button>
          <Button
            variant="primary"
            size="sm"
            onClick={onApprove}
            disabled={loadingStep === 'approve'}
            isLoading={loadingStep === 'approve'}
            className="bg-emerald-700 hover:bg-emerald-600 border-emerald-600"
          >
            {loadingStep === 'approve' ? 'Approving...' : 'Approve Patch'}
          </Button>
        </div>
      </div>

      {/* Revision Feedback Input */}
      {showReviseInput && (
        <div className="space-y-2 pt-2 border-t border-amber-900/40">
          <label className="text-[11px] font-medium text-neutral-300 block">
            Targeted Revision Feedback (Allows 1 Automatic Revision):
          </label>
          <div className="flex items-center space-x-2">
            <input
              type="text"
              value={revisionFeedback}
              onChange={(e) => onRevisionFeedbackChange(e.target.value)}
              placeholder="e.g. Please add explicit type annotations and timezone check"
              className="flex-1 bg-neutral-900 border border-neutral-700 rounded px-3 py-1.5 text-xs text-neutral-200 focus:outline-none focus:border-sky-500"
            />
            <Button
              variant="filter-active"
              size="sm"
              onClick={onRevise}
              disabled={!revisionFeedback.trim() || loadingStep === 'revise'}
              isLoading={loadingStep === 'revise'}
            >
              Submit
            </Button>
          </div>
        </div>
      )}

      {/* Rejection Justification Input */}
      {showRejectInput && (
        <div className="space-y-2 pt-2 border-t border-amber-900/40">
          <label className="text-[11px] font-medium text-neutral-300 block">
            Rejection Justification:
          </label>
          <div className="flex items-center space-x-2">
            <input
              type="text"
              value={rejectReason}
              onChange={(e) => onRejectReasonChange(e.target.value)}
              placeholder="e.g. Breaks backward compatibility with legacy endpoints"
              className="flex-1 bg-neutral-900 border border-neutral-700 rounded px-3 py-1.5 text-xs text-neutral-200 focus:outline-none focus:border-rose-500"
            />
            <Button
              variant="danger"
              size="sm"
              onClick={onReject}
              disabled={!rejectReason.trim() || loadingStep === 'reject'}
              isLoading={loadingStep === 'reject'}
            >
              Confirm Rejection
            </Button>
          </div>
        </div>
      )}
    </div>
  );
};
