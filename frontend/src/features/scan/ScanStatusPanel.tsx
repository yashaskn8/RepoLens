import React from 'react';
import { Scan } from '@/types/domain';
import { Card } from '@/components/ui/Card';

export interface ScanStatusPanelProps {
  scan: Scan;
}

export const ScanStatusPanel: React.FC<ScanStatusPanelProps> = ({ scan }) => {
  const isRunning = scan.status === 'PENDING' || scan.status === 'RUNNING';

  const getStatusBadgeStyle = (): React.CSSProperties => {
    if (scan.status === 'COMPLETED') {
      return { background: 'rgba(34, 197, 94, 0.2)', color: '#4ade80' };
    }
    if (scan.status === 'FAILED') {
      return { background: 'rgba(239, 68, 68, 0.2)', color: '#fca5a5' };
    }
    return { background: 'rgba(59, 130, 246, 0.2)', color: '#93c5fd' };
  };

  return (
    <Card
      title="Scan Lifecycle Progress"
      badge={
        <span className="badge-tag" style={getStatusBadgeStyle()}>
          {scan.status}
        </span>
      }
      style={{ marginBottom: '2rem' }}
    >
      <div className="grid-metrics">
        <div className="metric-item">
          <div className="metric-label">SCAN ID</div>
          <div className="metric-value-mono">{scan.id}</div>
        </div>
        <div className="metric-item">
          <div className="metric-label">REPOSITORY</div>
          <div className="metric-value text-sm truncate">{scan.repository_url}</div>
        </div>
        <div className="metric-item">
          <div className="metric-label">COMMIT SHA</div>
          <div className="metric-value-mono">{scan.commit_hash || 'Resolving...'}</div>
        </div>
        <div className="metric-item">
          <div className="metric-label">VERIFIED FINDINGS</div>
          <div className="metric-value text-sky-400 font-bold">{scan.findings_count}</div>
        </div>
      </div>

      {isRunning && (
        <div className="mt-5">
          <div className="progress-bar-container" role="progressbar" aria-label="Scan in progress">
            <div className="progress-bar-animated" />
          </div>
          <div className="text-xs text-slate-400 mt-2 text-center">
            Executing shallow clone, deterministic parsing (Semgrep/Trivy/OSV), and LangGraph specialists...
          </div>
        </div>
      )}
    </Card>
  );
};
