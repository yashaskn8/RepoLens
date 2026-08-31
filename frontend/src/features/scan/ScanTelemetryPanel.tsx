import React from 'react';
import { ScanTelemetry } from '@/types/domain';
import { Card } from '@/components/ui/Card';
import { Badge } from '@/components/ui/Badge';
import { Alert } from '@/components/ui/Alert';

export interface ScanTelemetryPanelProps {
  telemetry: ScanTelemetry;
}

export const ScanTelemetryPanel: React.FC<ScanTelemetryPanelProps> = ({ telemetry }) => {
  return (
    <Card
      title="Execution Telemetry & Diagnostics"
      badge={
        <Badge variant="tag">
          Status: {telemetry.status}
        </Badge>
      }
      style={{ marginBottom: '2rem' }}
    >
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4 mt-2">
        <div className="metric-item">
          <div className="metric-label">DURATION</div>
          <div className="metric-value">
            {telemetry.total_duration_ms != null
              ? `${(telemetry.total_duration_ms / 1000).toFixed(1)}s`
              : 'N/A'}
          </div>
        </div>
        <div className="metric-item">
          <div className="metric-label">WORKFLOW EVENTS</div>
          <div className="metric-value text-sky-400">{telemetry.event_count}</div>
        </div>
        <div className="metric-item">
          <div className="metric-label">PIPELINE STAGES</div>
          <div className="metric-value text-purple-400">{telemetry.stage_count}</div>
        </div>
        <div className="metric-item">
          <div className="metric-label">TOOLS (OK / FAIL / N/A)</div>
          <div className="metric-value text-sm">
            <span className="text-emerald-400">{telemetry.tools_completed}</span>
            {' / '}
            <span className="text-red-400">{telemetry.tools_failed}</span>
            {' / '}
            <span className="text-slate-400">{telemetry.tools_unavailable}</span>
          </div>
        </div>
        <div className="metric-item">
          <div className="metric-label">CONFIRMED FINDINGS</div>
          <div className="metric-value text-amber-400">{telemetry.confirmed_findings}</div>
        </div>
        <div className="metric-item">
          <div className="metric-label">REMEDIATION PATCHES</div>
          <div className="metric-value text-emerald-400">{telemetry.patches_generated}</div>
        </div>
      </div>

      {(telemetry.llm_retries != null ||
        telemetry.provider_fallbacks != null ||
        telemetry.total_tokens != null) && (
        <div className="mt-3 pt-3 border-t border-white/5 flex gap-4 text-xs text-slate-400 flex-wrap">
          {telemetry.llm_calls != null && (
            <span>
              LLM Calls: <strong className="text-slate-200">{telemetry.llm_calls}</strong>
            </span>
          )}
          {telemetry.llm_retries != null && (
            <span>
              Retries: <strong className="text-slate-200">{telemetry.llm_retries}</strong>
            </span>
          )}
          {telemetry.provider_fallbacks != null && (
            <span>
              Fallbacks: <strong className="text-slate-200">{telemetry.provider_fallbacks}</strong>
            </span>
          )}
          {telemetry.total_tokens != null && (
            <span>
              Total Tokens: <strong className="text-slate-200">{telemetry.total_tokens}</strong>
            </span>
          )}
        </div>
      )}

      {telemetry.analysis_truncated && (
        <div className="mt-3">
          <Alert variant="error" title="Analysis Truncated">
            {telemetry.analysis_truncation_reason || 'File/byte limit reached during ingestion'}
          </Alert>
        </div>
      )}
    </Card>
  );
};
