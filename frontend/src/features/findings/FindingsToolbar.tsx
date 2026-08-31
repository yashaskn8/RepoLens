import React from 'react';
import { Button } from '@/components/ui/Button';

export interface FindingsToolbarProps {
  totalCount: number;
  filteredCount: number;
  severityFilter: string;
  onSeverityFilterChange: (sev: string) => void;
}

export const FindingsToolbar: React.FC<FindingsToolbarProps> = ({
  filteredCount,
  severityFilter,
  onSeverityFilterChange,
}) => {
  const severities = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

  return (
    <div className="flex justify-between items-center flex-wrap gap-4 mb-6">
      <div>
        <h2 className="text-xl font-bold text-slate-100 m-0">
          Verified Grounded Findings ({filteredCount})
        </h2>
        <p className="text-xs text-slate-400 mt-0.5">
          Validated against source evidence with false-positive rejection
        </p>
      </div>

      {/* Severity Filter Pills */}
      <div className="flex gap-2 flex-wrap" role="group" aria-label="Filter findings by severity">
        {severities.map((sev) => (
          <Button
            key={sev}
            variant={severityFilter === sev ? 'filter-active' : 'filter'}
            size="sm"
            onClick={() => onSeverityFilterChange(sev)}
            aria-pressed={severityFilter === sev}
          >
            {sev}
          </Button>
        ))}
      </div>
    </div>
  );
};
