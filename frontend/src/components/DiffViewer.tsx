'use client';

import React from 'react';

interface DiffViewerProps {
  unifiedDiff: string;
  filesModified?: string[];
  status?: string;
}

export const DiffViewer: React.FC<DiffViewerProps> = ({
  unifiedDiff,
  filesModified = [],
  status,
}) => {
  if (!unifiedDiff || !unifiedDiff.trim()) {
    return (
      <div className="p-4 text-xs text-neutral-500 font-mono bg-neutral-900/60 rounded border border-neutral-800">
        No unified diff available.
      </div>
    );
  }

  const lines = unifiedDiff.split('\n');

  return (
    <div className="rounded-lg border border-neutral-800 bg-[#0d1117] text-neutral-200 overflow-hidden font-mono text-xs">
      {/* Header */}
      <div className="flex items-center justify-between px-3 py-2 bg-neutral-900 border-b border-neutral-800">
        <div className="flex items-center space-x-2">
          <span className="text-neutral-400 font-medium">Unified Diff</span>
          {filesModified.length > 0 && (
            <span className="text-[10px] text-neutral-400 bg-neutral-800 px-2 py-0.5 rounded">
              {filesModified.join(', ')}
            </span>
          )}
        </div>
        {status && (
          <span
            className={`px-2 py-0.5 text-[10px] font-semibold rounded uppercase tracking-wider ${
              status === 'APPROVED'
                ? 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                : status === 'VERIFIED'
                ? 'bg-blue-950 text-blue-300 border border-blue-800'
                : status === 'REJECTED'
                ? 'bg-rose-950 text-rose-300 border border-rose-800'
                : 'bg-amber-950 text-amber-300 border border-amber-800'
            }`}
          >
            {status}
          </span>
        )}
      </div>

      {/* Code Diff Display */}
      <div className="p-2 overflow-x-auto max-h-[420px] divide-y divide-neutral-900/40">
        {lines.map((line, idx) => {
          let lineBg = 'hover:bg-neutral-800/30';
          let textColor = 'text-neutral-300';
          let prefixMarker = '';

          if (line.startsWith('+++') || line.startsWith('---')) {
            textColor = 'text-neutral-400 font-bold';
            lineBg = 'bg-neutral-800/40';
          } else if (line.startsWith('@@')) {
            textColor = 'text-sky-400 bg-sky-950/30 font-semibold';
            lineBg = 'bg-sky-950/20';
          } else if (line.startsWith('+')) {
            textColor = 'text-emerald-300';
            lineBg = 'bg-emerald-950/40 border-l-2 border-emerald-500';
            prefixMarker = '+';
          } else if (line.startsWith('-')) {
            textColor = 'text-rose-300';
            lineBg = 'bg-rose-950/40 border-l-2 border-rose-500';
            prefixMarker = '-';
          }

          return (
            <div
              key={idx}
              className={`flex items-start font-mono leading-5 px-2 py-0.5 ${lineBg} ${textColor} select-text`}
            >
              <span className="w-8 text-neutral-600 select-none text-[10px] text-right pr-2">
                {idx + 1}
              </span>
              <pre className="flex-1 whitespace-pre-wrap break-all font-mono">
                {line}
              </pre>
            </div>
          );
        })}
      </div>
    </div>
  );
};
