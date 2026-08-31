import React from 'react';
import { ChangeAnalysisResponse } from '@/types/domain';
import { Card } from '@/components/ui/Card';

export interface ChangeSummaryProps {
  analysis: ChangeAnalysisResponse;
}

export const ChangeSummary: React.FC<ChangeSummaryProps> = ({ analysis }) => {
  const getRiskBadgeColor = (risk?: string | null) => {
    switch (risk) {
      case 'CRITICAL':
        return { bg: 'rgba(239, 68, 68, 0.2)', border: '#ef4444', text: '#f87171' };
      case 'HIGH':
        return { bg: 'rgba(249, 115, 22, 0.2)', border: '#f97316', text: '#fb923c' };
      case 'MEDIUM':
        return { bg: 'rgba(234, 179, 8, 0.2)', border: '#eab308', text: '#fde047' };
      case 'LOW':
      default:
        return { bg: 'rgba(59, 130, 246, 0.2)', border: '#3b82f6', text: '#60a5fa' };
    }
  };

  const riskStyle = getRiskBadgeColor(analysis.risk_level);

  return (
    <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
      <Card className="!p-5">
        <div className="metric-label">FILES CHANGED</div>
        <div className="text-2xl font-extrabold text-slate-100 mt-1">
          {analysis.changed_files_count}
        </div>
      </Card>

      <Card className="!p-5">
        <div className="metric-label">SYMBOLS CHANGED</div>
        <div className="text-2xl font-extrabold text-sky-400 mt-1">
          {analysis.changed_symbols_count}
        </div>
      </Card>

      <Card className="!p-5">
        <div className="metric-label">BLAST RADIUS (IMPACTED)</div>
        <div className="text-2xl font-extrabold text-orange-400 mt-1">
          {analysis.impacted_symbols_count}
        </div>
      </Card>

      <Card
        className="!p-5"
        style={{
          border: `1px solid ${riskStyle.border}`,
          background: riskStyle.bg,
        }}
      >
        <div className="metric-label">DETERMINISTIC RISK</div>
        <div
          className="text-2xl font-extrabold mt-1"
          style={{ color: riskStyle.text }}
        >
          {analysis.risk_level || 'LOW'}
        </div>
      </Card>
    </div>
  );
};
