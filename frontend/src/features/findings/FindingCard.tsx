import React from 'react';
import { Finding } from '@/types/domain';
import { Badge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { FindingEvidence } from './FindingEvidence';
import { RemediationLifecycle } from '@/components/RemediationLifecycle';

export interface FindingCardProps {
  finding: Finding;
  isExpanded: boolean;
  onToggleExpand: () => void;
}

export const FindingCard: React.FC<FindingCardProps> = ({
  finding,
  isExpanded,
  onToggleExpand,
}) => {
  return (
    <article className="finding-card">
      {/* Header Badges & Attribution */}
      <div className="flex justify-between items-start gap-4 flex-wrap">
        <div className="flex items-center gap-2 flex-wrap">
          <Badge severity={finding.severity}>{finding.severity}</Badge>

          {finding.verification_verdict && (
            <Badge
              variant={finding.verification_verdict === 'CONFIRMED' ? 'success' : 'medium'}
            >
              {finding.verification_verdict}
            </Badge>
          )}

          <span className="text-xs text-slate-400 uppercase font-semibold">
            {finding.category || 'General'}
          </span>
        </div>

        {finding.model_metadata && (
          <span className="text-xs text-slate-500">
            Agent: {finding.model_metadata.provider || 'AI'} ({finding.model_metadata.model_name})
          </span>
        )}
      </div>

      {/* Finding Title & Description */}
      <h3 className="text-base font-semibold text-slate-100 mt-3 mb-2">
        {finding.title}
      </h3>

      <p className="text-sm text-slate-300 mb-3 leading-relaxed">
        {finding.description}
      </p>

      {/* Verification Rationale */}
      {finding.verification_reason && (
        <div className="text-xs text-slate-400 bg-slate-950/40 p-2.5 rounded border border-white/5 mb-3 leading-relaxed">
          <strong className="text-slate-200">Verification: </strong>
          {finding.verification_reason}
        </div>
      )}

      {/* Evidence Box */}
      {finding.evidences && finding.evidences.length > 0 && (
        <FindingEvidence evidence={finding.evidences[0]} />
      )}

      {/* Mitigation Guidance */}
      {finding.mitigation_guidance && (
        <div className="mt-3 text-xs text-emerald-300 leading-relaxed">
          <strong>Remediation: </strong>
          {finding.mitigation_guidance}
        </div>
      )}

      {/* Remediation Lifecycle Action Button */}
      <div className="mt-4 flex justify-end">
        <Button
          variant={isExpanded ? 'filter-active' : 'filter'}
          size="sm"
          onClick={onToggleExpand}
          aria-expanded={isExpanded}
        >
          {isExpanded ? 'Hide Remediation & Patch ▴' : '🛠️ Remediate & Safe Patch ▾'}
        </Button>
      </div>

      {/* Embedded Remediation Lifecycle */}
      {isExpanded && (
        <div className="mt-4 pt-4 border-t border-slate-800">
          <RemediationLifecycle finding={finding} />
        </div>
      )}
    </article>
  );
};
