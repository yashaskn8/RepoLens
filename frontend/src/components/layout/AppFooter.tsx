'use client';

import React from 'react';
import { HealthResponse } from '@/types/domain';

export interface AppFooterProps {
  health?: HealthResponse | null;
}

export const AppFooter: React.FC<AppFooterProps> = ({ health }) => {
  const isHealthy = health?.status === 'healthy';

  return (
    <footer className="footer-glass" role="contentinfo">
      <div className="flex flex-col md:flex-row items-center justify-between gap-6 pb-6 border-b border-white/5">
        {/* Brand */}
        <div className="flex items-center gap-3">
          <div className="brand-icon w-8 h-8 text-sm" aria-hidden="true">
            RL
          </div>
          <div>
            <div className="text-sm font-bold text-white font-display">RepoLens</div>
            <div className="text-xs text-slate-400">AI Code Intelligence &amp; Security Platform</div>
          </div>
        </div>

        {/* Tech Stack Pills */}
        <div className="flex items-center gap-2 flex-wrap justify-center">
          <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-slate-900/60 border border-slate-800 text-slate-400">
            Tree-sitter AST
          </span>
          <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-slate-900/60 border border-slate-800 text-slate-400">
            Semgrep
          </span>
          <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-slate-900/60 border border-slate-800 text-slate-400">
            Trivy &amp; OSV
          </span>
          <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-slate-900/60 border border-slate-800 text-slate-400">
            Next.js App Router
          </span>
          <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-slate-900/60 border border-slate-800 text-slate-400">
            FastAPI Engine
          </span>
        </div>

        {/* Status Indicator */}
        <div className="flex items-center gap-2 text-xs text-slate-400">
          <span
            className={`w-2 h-2 rounded-full ${
              isHealthy ? 'bg-emerald-400 shadow-[0_0_8px_#34d399]' : 'bg-rose-400 shadow-[0_0_8px_#fb7185]'
            }`}
            aria-hidden="true"
          />
          <span>Engine {isHealthy ? 'Operational' : 'Ready / Offline'}</span>
        </div>
      </div>

      <div className="flex flex-col sm:flex-row items-center justify-between gap-3 pt-4 text-[11px] text-slate-500">
        <p>© {new Date().getFullYear()} RepoLens. Deterministic Multi-Agent Code Intelligence.</p>
        <p className="font-mono">v1.0.1 • Zero Hallucinations • Verifiable Diffs</p>
      </div>
    </footer>
  );
};
