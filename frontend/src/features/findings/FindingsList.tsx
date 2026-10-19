import React from 'react';
import { Finding } from '@/types/domain';
import { Card } from '@/components/ui/Card';
import { EmptyState } from '@/components/ui/EmptyState';
import { FindingsToolbar } from './FindingsToolbar';
import { FindingCard } from './FindingCard';

export interface FindingsListProps {
  findings: Finding[];
  severityFilter: string;
  onSeverityFilterChange: (sev: string) => void;
  expandedFindingId: string | null;
  onToggleExpand: (id: string) => void;
}

export const FindingsList: React.FC<FindingsListProps> = ({
  findings,
  severityFilter,
  onSeverityFilterChange,
  expandedFindingId,
  onToggleExpand,
}) => {
  const filteredFindings = findings.filter((f) => {
    return severityFilter === 'ALL' || f.severity === severityFilter;
  });

  return (
    <Card>
      <FindingsToolbar
        totalCount={findings.length}
        filteredCount={filteredFindings.length}
        severityFilter={severityFilter}
        onSeverityFilterChange={onSeverityFilterChange}
      />

      {filteredFindings.length === 0 ? (
        <EmptyState
          icon="🛡️"
          title={findings.length === 0 ? 'No confirmed findings returned' : 'No findings matching filters'}
          description={findings.length === 0
            ? 'No confirmed finding was returned in the available scan coverage. This does not establish that the repository is free of defects.'
            : 'Try selecting a different severity filter.'}
        />
      ) : (
        <div className="flex flex-col gap-5">
          {filteredFindings.map((finding) => (
            <FindingCard
              key={finding.id}
              finding={finding}
              isExpanded={expandedFindingId === finding.id}
              onToggleExpand={() => onToggleExpand(finding.id)}
            />
          ))}
        </div>
      )}
    </Card>
  );
};
