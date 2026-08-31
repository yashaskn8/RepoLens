import React from 'react';
import { ResearchResult } from '@/types/domain';
import { Button } from '@/components/ui/Button';

export interface ResearchPanelProps {
  research: ResearchResult | null;
  isLoading: boolean;
  onRequestResearch: () => void;
}

export const ResearchPanel: React.FC<ResearchPanelProps> = ({
  research,
  isLoading,
  onRequestResearch,
}) => {
  return (
    <div className="rounded-lg border border-neutral-800 bg-neutral-900/40 p-4 space-y-3">
      <div className="flex items-center justify-between flex-wrap gap-2">
        <span className="text-xs font-semibold text-neutral-300 uppercase tracking-wider">
          1. Technical Research & Upgrade Intelligence
        </span>
        <Button
          variant="filter"
          size="sm"
          onClick={onRequestResearch}
          disabled={isLoading}
          isLoading={isLoading}
        >
          {isLoading
            ? 'Researching...'
            : research
            ? 'Re-run Research'
            : 'Investigate Library'}
        </Button>
      </div>

      {research && (
        <div className="text-xs space-y-2 text-neutral-300 pt-2 border-t border-neutral-800">
          <div className="flex items-center justify-between flex-wrap gap-2">
            <span className="font-medium text-neutral-200">
              Library: {research.target_framework}
            </span>
            {research.recommended_version && (
              <span className="text-[10px] text-sky-400 font-mono">
                Recommended: {research.recommended_version}
              </span>
            )}
          </div>
          <div>
            <span className="text-[11px] font-semibold text-neutral-400">
              Migration Summary:{' '}
            </span>
            <span>{research.migration_summary}</span>
          </div>
          <div>
            <span className="text-[11px] font-semibold text-neutral-400">
              Repository Impact:{' '}
            </span>
            <span className="text-neutral-400">{research.repository_impact}</span>
          </div>
        </div>
      )}
    </div>
  );
};
