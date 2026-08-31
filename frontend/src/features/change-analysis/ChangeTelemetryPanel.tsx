import React from 'react';
import { ChangeAnalysisTelemetry } from '@/types/domain';
import { Card } from '@/components/ui/Card';

export interface ChangeTelemetryPanelProps {
  telemetry: ChangeAnalysisTelemetry | null;
}

export const ChangeTelemetryPanel: React.FC<ChangeTelemetryPanelProps> = ({ telemetry }) => {
  return (
    <div>
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
        <Card className="!p-4">
          <div className="metric-label">EXECUTION TIME</div>
          <div className="text-xl font-bold text-slate-100 mt-1">
            {telemetry?.duration_ms ? `${(telemetry.duration_ms / 1000).toFixed(2)}s` : 'N/A'}
          </div>
        </Card>

        <Card className="!p-4">
          <div className="metric-label">TOTAL TOKENS</div>
          <div className="text-xl font-bold text-sky-400 mt-1">
            {telemetry?.total_tokens || 0}
          </div>
        </Card>

        <Card className="!p-4">
          <div className="metric-label">DIRECT IMPACTS</div>
          <div className="text-xl font-bold text-emerald-400 mt-1">
            {telemetry?.direct_impacts || 0}
          </div>
        </Card>

        <Card className="!p-4">
          <div className="metric-label">TRANSITIVE IMPACTS</div>
          <div className="text-xl font-bold text-purple-400 mt-1">
            {telemetry?.transitive_impacts || 0}
          </div>
        </Card>
      </div>

      <div className="evidence-box">
        <div className="text-xs font-semibold text-slate-400 mb-2">
          RAW TELEMETRY PAYLOAD (NO SECRETS)
        </div>
        <pre className="code-snippet">{JSON.stringify(telemetry || {}, null, 2)}</pre>
      </div>
    </div>
  );
};
