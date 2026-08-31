import React from 'react';
import { ChangeReviewFinding } from '@/types/domain';
import { Badge } from '@/components/ui/Badge';
import { EmptyState } from '@/components/ui/EmptyState';

export interface ChangeReviewPanelProps {
  reviewFindings: ChangeReviewFinding[];
  expandedFindingId: string | null;
  onToggleExpand: (id: string) => void;
}

export const ChangeReviewPanel: React.FC<ChangeReviewPanelProps> = ({
  reviewFindings,
  expandedFindingId,
  onToggleExpand,
}) => {
  if (reviewFindings.length === 0) {
    return (
      <EmptyState
        icon="🤖"
        title="No AI review findings"
        description="No findings generated or analysis is still in progress."
      />
    );
  }

  return (
    <div className="flex flex-col gap-4">
      {reviewFindings.map((rf) => {
        const isExpanded = expandedFindingId === rf.id;
        return (
          <div
            key={rf.id}
            className="finding-card cursor-pointer"
            onClick={() => onToggleExpand(rf.id)}
          >
            <div className="flex justify-between items-start flex-wrap gap-2">
              <div className="flex items-center gap-2 flex-wrap">
                <Badge severity={rf.severity}>{rf.severity}</Badge>
                <Badge variant="tag">{rf.risk_type}</Badge>
                <Badge
                  variant={rf.verdict === 'CONFIRMED' ? 'success' : 'low'}
                >
                  {rf.verdict} ({Math.round(rf.confidence * 100)}%)
                </Badge>
              </div>
              <span className="text-xs text-slate-400">
                {isExpanded ? '▲ Hide Details' : '▼ View Details'}
              </span>
            </div>

            <div className="text-base font-semibold mt-2.5 text-slate-100">
              {rf.title}
            </div>

            <div className="text-xs text-slate-300 mt-1 leading-relaxed">
              {rf.reasoning_summary}
            </div>

            {/* Affected targets */}
            <div className="flex flex-wrap gap-1.5 mt-3">
              {rf.affected_files.map((p, idx) => (
                <span key={idx} className="badge-tag">
                  📄 {p}
                </span>
              ))}
              {rf.affected_symbols.map((s, idx) => (
                <span key={idx} className="badge-tag text-sky-400">
                  🧩 {s}
                </span>
              ))}
            </div>

            {/* Expanded details */}
            {isExpanded && (
              <div
                className="evidence-box mt-3"
                onClick={(e) => e.stopPropagation()}
              >
                <div className="text-xs font-semibold text-slate-400 mb-1">
                  GROUNDED EVIDENCE REFS
                </div>
                <div className="text-xs text-slate-300 mb-3 font-mono">
                  {rf.evidence_refs.join(', ') || 'Direct AST diff facts'}
                </div>

                {rf.assumptions && rf.assumptions.length > 0 && (
                  <>
                    <div className="text-xs font-semibold text-slate-400 mb-1">
                      DISCLOSED ASSUMPTIONS
                    </div>
                    <ul className="text-xs text-slate-300 pl-4 list-disc space-y-0.5">
                      {rf.assumptions.map((asm, idx) => (
                        <li key={idx}>{asm}</li>
                      ))}
                    </ul>
                  </>
                )}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
};
