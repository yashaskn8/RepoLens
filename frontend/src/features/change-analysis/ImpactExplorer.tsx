import React from 'react';
import { ChangeImpact } from '@/types/domain';
import { Badge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { EmptyState } from '@/components/ui/EmptyState';

export interface ImpactExplorerProps {
  impacts: ChangeImpact[];
  severityFilter: string;
  onSeverityFilterChange: (sev: string) => void;
  statusFilter: string;
  onStatusFilterChange: (status: string) => void;
  expandedImpactId: string | null;
  onToggleExpand: (id: string) => void;
}

export const ImpactExplorer: React.FC<ImpactExplorerProps> = ({
  impacts,
  severityFilter,
  onSeverityFilterChange,
  statusFilter,
  onStatusFilterChange,
  expandedImpactId,
  onToggleExpand,
}) => {
  const filteredImpacts = impacts.filter((imp) => {
    const matchesSev = severityFilter === 'ALL' || imp.severity === severityFilter;
    const matchesStat = statusFilter === 'ALL' || imp.verification_status === statusFilter;
    return matchesSev && matchesStat;
  });

  return (
    <div>
      {/* Filter Toolbar */}
      <div className="flex justify-between items-center mb-5 flex-wrap gap-3">
        <div className="flex gap-2 items-center flex-wrap" role="group" aria-label="Filter by severity">
          <span className="text-xs text-slate-400 font-semibold">Severity:</span>
          {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((sev) => (
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

        <div className="flex gap-2 items-center flex-wrap" role="group" aria-label="Filter by verification status">
          <span className="text-xs text-slate-400 font-semibold">Status:</span>
          {['ALL', 'FACT', 'INFERENCE', 'ASSUMPTION'].map((stat) => (
            <Button
              key={stat}
              variant={statusFilter === stat ? 'filter-active' : 'filter'}
              size="sm"
              onClick={() => onStatusFilterChange(stat)}
              aria-pressed={statusFilter === stat}
            >
              {stat}
            </Button>
          ))}
        </div>
      </div>

      {/* Impact Cards List */}
      {filteredImpacts.length === 0 ? (
        <EmptyState
          icon="💥"
          title="No impacts matching filters"
          description="Adjust severity or verification status filters to view blast radius details."
        />
      ) : (
        <div className="flex flex-col gap-4">
          {filteredImpacts.map((imp) => {
            const isExpanded = expandedImpactId === imp.id;
            return (
              <div
                key={imp.id}
                className="finding-card cursor-pointer"
                onClick={() => onToggleExpand(imp.id)}
              >
                <div className="flex justify-between items-start flex-wrap gap-2">
                  <div className="flex items-center gap-2 flex-wrap">
                    <Badge severity={imp.severity}>{imp.severity}</Badge>
                    <Badge variant="tag">{imp.impact_type}</Badge>
                    <Badge
                      variant={
                        imp.verification_status === 'FACT'
                          ? 'success'
                          : imp.verification_status === 'INFERENCE'
                          ? 'low'
                          : 'medium'
                      }
                    >
                      {imp.verification_status}
                    </Badge>
                  </div>
                  <span className="text-xs text-slate-400">
                    {isExpanded ? '▲ Hide Evidence' : '▼ Expand Evidence'}
                  </span>
                </div>

                <div className="text-base font-semibold mt-2.5 text-slate-100">
                  {imp.title}
                </div>

                <div className="text-xs text-slate-300 mt-1 leading-relaxed">
                  {imp.description}
                </div>

                {/* Source -> Affected mapping */}
                <div className="flex items-center gap-2 mt-3 text-xs font-mono flex-wrap">
                  <span className="text-sky-400">
                    {imp.source_file} {imp.source_symbol ? `(${imp.source_symbol})` : ''}
                  </span>
                  <span className="text-slate-500">→</span>
                  <span className="text-pink-400">
                    {imp.affected_file} {imp.affected_symbol ? `(${imp.affected_symbol})` : ''}
                  </span>
                </div>

                {/* Expandable Evidence Drawer */}
                {isExpanded && (
                  <div
                    className="evidence-box mt-3"
                    onClick={(e) => e.stopPropagation()}
                  >
                    <div className="text-xs font-semibold text-slate-400 mb-2">
                      DETERMINISTIC EVIDENCE & CONTEXT PAYLOAD
                    </div>
                    <pre className="code-snippet">
                      {JSON.stringify(imp.evidence_payload || {}, null, 2)}
                    </pre>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};
