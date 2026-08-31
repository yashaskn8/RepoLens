import React from 'react';
import { ChangeAnalysisReportResponse } from '@/types/domain';
import { Button } from '@/components/ui/Button';

export interface ReviewReportPanelProps {
  report: ChangeAnalysisReportResponse | null;
  copiedReport: boolean;
  onCopyMarkdown: () => void;
  onDownloadMarkdown: () => void;
}

export const ReviewReportPanel: React.FC<ReviewReportPanelProps> = ({
  report,
  copiedReport,
  onCopyMarkdown,
  onDownloadMarkdown,
}) => {
  return (
    <div>
      <div className="flex justify-between items-center mb-4 flex-wrap gap-3">
        <span className="text-xs text-slate-400">
          Deterministic Markdown Report with full provenance and limitations.
        </span>
        <div className="flex gap-2">
          <Button
            variant="filter"
            size="sm"
            onClick={onCopyMarkdown}
          >
            {copiedReport ? '✓ Copied!' : '📋 Copy Markdown'}
          </Button>
          <Button
            variant="primary"
            size="sm"
            onClick={onDownloadMarkdown}
          >
            📥 Download (.md)
          </Button>
        </div>
      </div>

      {/* Epistemic Guarantee Banner */}
      <div className="p-3 bg-blue-950/20 border border-blue-800/40 rounded-lg mb-4 text-xs text-sky-300">
        🛡️ <strong>Epistemic Guarantee:</strong> Analysis is grounded strictly in AST diff facts and dependency graph traversal. Repository test suites and CI pipelines were <strong>not executed</strong>.
      </div>

      <pre className="bg-slate-950 border border-white/10 rounded-lg p-5 text-xs font-mono text-slate-200 max-h-[500px] overflow-y-auto whitespace-pre-wrap leading-relaxed">
        {report?.markdown_report || 'Generating report...'}
      </pre>
    </div>
  );
};
