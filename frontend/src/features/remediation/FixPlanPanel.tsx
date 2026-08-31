import React from 'react';
import { FixPlan } from '@/types/domain';
import { Button } from '@/components/ui/Button';

export interface FixPlanPanelProps {
  plan: FixPlan | null;
  isLoading: boolean;
  onRequestPlan: () => void;
}

export const FixPlanPanel: React.FC<FixPlanPanelProps> = ({
  plan,
  isLoading,
  onRequestPlan,
}) => {
  return (
    <div className="rounded-lg border border-neutral-800 bg-neutral-900/40 p-4 space-y-3">
      <div className="flex items-center justify-between flex-wrap gap-2">
        <span className="text-xs font-semibold text-neutral-300 uppercase tracking-wider">
          2. Structured Root-Cause Fix Plan
        </span>
        <Button
          variant="filter"
          size="sm"
          onClick={onRequestPlan}
          disabled={isLoading}
          isLoading={isLoading}
        >
          {isLoading
            ? 'Planning...'
            : plan
            ? 'Regenerate Plan'
            : 'Generate Fix Plan'}
        </Button>
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
            <span className="font-mono text-[11px] text-sky-400">
              {plan.files_expected_to_change.join(', ')}
            </span>
          </div>
        </div>
      )}
    </div>
  );
};
