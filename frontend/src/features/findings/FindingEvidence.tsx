import React from 'react';
import { Evidence } from '@/types/domain';

export interface FindingEvidenceProps {
  evidence: Evidence;
}

export const FindingEvidence: React.FC<FindingEvidenceProps> = ({ evidence }) => {
  return (
    <div className="evidence-box">
      <div className="text-xs font-semibold text-sky-400 mb-2 flex items-center gap-1.5 flex-wrap">
        <span aria-hidden="true">📍</span>
        <span className="font-mono">{evidence.file_path}</span>
        {evidence.start_line && (
          <span className="text-slate-400 font-normal">
            (Lines {evidence.start_line}
            {evidence.end_line && evidence.end_line !== evidence.start_line
              ? `-${evidence.end_line}`
              : ''}
            )
          </span>
        )}
      </div>

      {evidence.code_snippet && (
        <pre className="code-snippet">
          <code>{evidence.code_snippet}</code>
        </pre>
      )}
    </div>
  );
};
