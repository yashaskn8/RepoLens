import React from 'react';
import { Button } from '@/components/ui/Button';
import { Card } from '@/components/ui/Card';
import { Badge } from '@/components/ui/Badge';
import { Alert } from '@/components/ui/Alert';
import { PresetPicker } from '@/features/landing/PresetPicker';

export interface RepositoryScanFormProps {
  repoUrl: string;
  onRepoUrlChange: (url: string) => void;
  branch: string;
  onBranchChange: (branch: string) => void;
  onSubmit: (e: React.FormEvent) => void;
  isSubmitting: boolean;
  isScanRunning: boolean;
  errorMsg: string | null;
  isAuthenticated?: boolean;
  onOpenAuthModal?: () => void;
  onQuickDemoLogin?: () => void;
}

export const RepositoryScanForm: React.FC<RepositoryScanFormProps> = ({
  repoUrl,
  onRepoUrlChange,
  branch,
  onBranchChange,
  onSubmit,
  isSubmitting,
  isScanRunning,
  errorMsg,
  isAuthenticated = true,
  onOpenAuthModal,
  onQuickDemoLogin,
}) => {
  const isBusy = isSubmitting || isScanRunning;

  const handleSelectPreset = (url: string, b: string) => {
    onRepoUrlChange(url);
    onBranchChange(b);
  };

  return (
    <Card
      title="Analyze Public GitHub Repository"
      badge={<Badge variant="tag">AST &amp; Multi-Agent</Badge>}
      style={{ marginBottom: '2rem' }}
    >
      <form onSubmit={onSubmit} className="flex flex-col gap-4">
        {/* Unauthenticated Helper Banner */}
        {!isAuthenticated && (
          <div className="p-3.5 rounded-xl bg-gradient-to-r from-indigo-950/60 via-purple-950/40 to-slate-900/60 border border-indigo-500/35 flex flex-col sm:flex-row items-center justify-between gap-3">
            <div className="flex items-center gap-2.5">
              <span className="text-xl" aria-hidden="true">🔑</span>
              <div>
                <div className="text-xs font-bold text-white">Authentication Required to Dispatch Scans</div>
                <div className="text-[11px] text-slate-300">Sign in with credentials or launch with instant 1-click Demo Access.</div>
              </div>
            </div>
            <div className="flex items-center gap-2 shrink-0">
              {onQuickDemoLogin && (
                <button
                  type="button"
                  className="py-1.5 px-3 rounded-lg text-xs font-bold bg-gradient-to-r from-indigo-600 to-purple-600 hover:from-indigo-500 hover:to-purple-500 text-white shadow-md transition-all cursor-pointer"
                  onClick={onQuickDemoLogin}
                >
                  ⚡ 1-Click Demo Sign-In
                </button>
              )}
              {onOpenAuthModal && (
                <button
                  type="button"
                  className="filter-btn text-xs py-1.5 px-3"
                  onClick={onOpenAuthModal}
                >
                  Sign In / Register
                </button>
              )}
            </div>
          </div>
        )}

        <div className="flex gap-3 flex-wrap items-center">
          <div className="flex-1 min-w-[280px]">
            <input
              type="text"
              className="search-input w-full"
              value={repoUrl}
              onChange={(e) => onRepoUrlChange(e.target.value)}
              placeholder="https://github.com/owner/repository"
              aria-label="GitHub Repository HTTPS URL"
              disabled={isBusy}
              required
            />
          </div>
          <div className="w-[120px]">
            <input
              type="text"
              className="search-input w-full"
              value={branch}
              onChange={(e) => onBranchChange(e.target.value)}
              placeholder="main"
              aria-label="Repository branch"
              disabled={isBusy}
            />
          </div>
          <Button
            type="submit"
            variant="primary"
            disabled={isBusy}
            isLoading={isBusy}
          >
            {isBusy ? 'Analyzing...' : 'Analyze Repository'}
          </Button>
        </div>

        {/* Quick Presets */}
        <PresetPicker onSelect={handleSelectPreset} disabled={isBusy} />

        {errorMsg && (
          <Alert variant="error">
            <div className="flex items-center justify-between gap-3 w-full flex-wrap">
              <span>{errorMsg}</span>
              {!isAuthenticated && onQuickDemoLogin && (
                <button
                  type="button"
                  className="text-xs underline text-indigo-300 hover:text-indigo-200 font-semibold cursor-pointer"
                  onClick={onQuickDemoLogin}
                >
                  Click here to sign in with Demo Account →
                </button>
              )}
            </div>
          </Alert>
        )}
      </form>
    </Card>
  );
};
