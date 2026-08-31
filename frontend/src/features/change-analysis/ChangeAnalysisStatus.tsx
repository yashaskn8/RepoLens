import React from 'react';
import { ChangeAnalysisResponse, WorkflowEvent } from '@/types/domain';
import { Card } from '@/components/ui/Card';
import { Button } from '@/components/ui/Button';

export interface ChangeAnalysisStatusProps {
  analysis: ChangeAnalysisResponse;
  isRunning: boolean;
  workflowEvents: WorkflowEvent[];
  onDownloadMarkdown: () => void;
}

export const ChangeAnalysisStatus: React.FC<ChangeAnalysisStatusProps> = ({
  analysis,
  isRunning,
  workflowEvents,
  onDownloadMarkdown,
}) => {
  const getStatusBadgeStyle = (): React.CSSProperties => {
    if (analysis.status === 'COMPLETED') {
      return { background: 'rgba(34, 197, 94, 0.2)', color: '#4ade80' };
    }
    if (analysis.status === 'FAILED') {
      return { background: 'rgba(239, 68, 68, 0.2)', color: '#fca5a5' };
    }
    return { background: 'rgba(59, 130, 246, 0.2)', color: '#93c5fd' };
  };

  return (
    <Card>
      <div className="flex justify-between items-center flex-wrap gap-4">
        <div>
          <div className="flex items-center gap-3 flex-wrap">
            <span className="badge" style={getStatusBadgeStyle()}>
              {analysis.status}
            </span>
            <span className="text-xs text-slate-400 font-mono">ID: {analysis.id}</span>
          </div>

          {analysis.model_metadata?.pr_number && (
            <div className="mt-2 text-lg font-bold text-slate-100">
              Pull Request #{analysis.model_metadata.pr_number}: {analysis.model_metadata.pr_title || ''}
            </div>
          )}

          <div className="mt-1 text-xs text-slate-300">
            <span className="font-mono text-sky-400">
              {analysis.base_ref || 'base'} ({analysis.base_commit_sha.slice(0, 8)})
            </span>{' '}
            →{' '}
            <span className="font-mono text-purple-400">
              {analysis.head_ref || 'head'} ({analysis.head_commit_sha.slice(0, 8)})
            </span>
          </div>
        </div>

        {analysis.status === 'COMPLETED' && (
          <div className="flex gap-2">
            <Button
              variant="primary"
              size="sm"
              onClick={onDownloadMarkdown}
            >
              📥 Download Report (.md)
            </Button>
          </div>
        )}
      </div>

      {/* Running Progress Bar */}
      {isRunning && (
        <div className="mt-5">
          <div className="progress-bar-container" role="progressbar" aria-label="Analysis in progress">
            <div className="progress-bar-animated" />
          </div>
          <div className="flex justify-between text-xs text-slate-400 mt-2">
            <span>Durable Workflow Pipeline: ACQUIRE → DIFF → IMPACT → REVIEW → VERIFY → COMPLETE</span>
            <span>Streaming SSE Events...</span>
          </div>
        </div>
      )}

      {/* Real-time SSE Workflow Events Trail */}
      {workflowEvents.length > 0 && (
        <div className="mt-5 p-3 bg-slate-950/80 rounded-lg border border-white/5">
          <div className="text-xs font-semibold text-slate-400 mb-2">
            DURABLE WORKFLOW AUDIT TRAIL ({workflowEvents.length} events)
          </div>
          <div className="max-h-[120px] overflow-y-auto flex flex-col gap-1 pr-1">
            {workflowEvents.slice(-6).map((ev) => (
              <div key={ev.id} className="text-xs font-mono text-slate-300">
                <span className="text-indigo-400">[{ev.stage || 'WORKFLOW'}]</span> {ev.message}
              </div>
            ))}
          </div>
        </div>
      )}
    </Card>
  );
};
