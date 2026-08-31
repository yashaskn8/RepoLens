import React from 'react';
import { Button } from '@/components/ui/Button';
import { Card } from '@/components/ui/Card';
import { Badge } from '@/components/ui/Badge';
import { Alert } from '@/components/ui/Alert';

export interface ChangeAnalysisInputProps {
  inputMode: 'PR' | 'EXACT';
  onInputModeChange: (mode: 'PR' | 'EXACT') => void;
  prUrl: string;
  onPrUrlChange: (url: string) => void;
  repoUrl: string;
  onRepoUrlChange: (url: string) => void;
  baseSha: string;
  onBaseShaChange: (sha: string) => void;
  headSha: string;
  onHeadShaChange: (sha: string) => void;
  baseRef: string;
  onBaseRefChange: (ref: string) => void;
  headRef: string;
  onHeadRefChange: (ref: string) => void;
  onSubmit: (e: React.FormEvent) => void;
  isSubmitting: boolean;
  isRunning: boolean;
  errorMsg: string | null;
}

export const ChangeAnalysisInput: React.FC<ChangeAnalysisInputProps> = ({
  inputMode,
  onInputModeChange,
  prUrl,
  onPrUrlChange,
  repoUrl,
  onRepoUrlChange,
  baseSha,
  onBaseShaChange,
  headSha,
  onHeadShaChange,
  baseRef,
  onBaseRefChange,
  headRef,
  onHeadRefChange,
  onSubmit,
  isSubmitting,
  isRunning,
  errorMsg,
}) => {
  const isBusy = isSubmitting || isRunning;

  return (
    <Card
      title="Change Intelligence & PR Review"
      badge={<Badge variant="tag">Evidence Grounded</Badge>}
      action={
        <div className="flex gap-2" role="group" aria-label="Input mode selector">
          <Button
            variant={inputMode === 'PR' ? 'filter-active' : 'filter'}
            size="sm"
            onClick={() => onInputModeChange('PR')}
            disabled={isRunning}
            aria-pressed={inputMode === 'PR'}
          >
            Public PR URL
          </Button>
          <Button
            variant={inputMode === 'EXACT' ? 'filter-active' : 'filter'}
            size="sm"
            onClick={() => onInputModeChange('EXACT')}
            disabled={isRunning}
            aria-pressed={inputMode === 'EXACT'}
          >
            Exact SHAs (Advanced)
          </Button>
        </div>
      }
    >
      <form onSubmit={onSubmit} className="flex flex-col gap-4 mt-2">
        {inputMode === 'PR' ? (
          <div className="flex flex-col gap-3">
            <div className="flex gap-3 flex-wrap">
              <input
                type="text"
                className="search-input flex-1 min-w-[320px]"
                value={prUrl}
                onChange={(e) => onPrUrlChange(e.target.value)}
                placeholder="https://github.com/owner/repository/pull/123"
                aria-label="GitHub Pull Request URL"
                disabled={isBusy}
                required
              />
              <Button
                type="submit"
                variant="primary"
                disabled={isBusy}
                isLoading={isBusy}
              >
                {isBusy ? 'Analyzing Revisions...' : 'Analyze Pull Request'}
              </Button>
            </div>

            {/* Quick Sample PR Presets */}
            <div className="preset-bar" role="group" aria-label="Sample Pull Requests">
              <span className="text-xs text-slate-400 font-medium mr-1 flex items-center gap-1">
                <span aria-hidden="true">💡</span> Sample PRs:
              </span>
              <button
                type="button"
                disabled={isBusy}
                onClick={() => onPrUrlChange('https://github.com/fastapi/fastapi/pull/10500')}
                className="preset-chip"
              >
                <span>FastAPI #10500</span>
              </button>
              <button
                type="button"
                disabled={isBusy}
                onClick={() => onPrUrlChange('https://github.com/pallets/flask/pull/5000')}
                className="preset-chip"
              >
                <span>Flask #5000</span>
              </button>
              <button
                type="button"
                disabled={isBusy}
                onClick={() => onPrUrlChange('https://github.com/yashaskn8/RepoLens/pull/1')}
                className="preset-chip"
              >
                <span>RepoLens #1</span>
              </button>
            </div>
          </div>
        ) : (
          <div className="flex flex-col gap-3">
            <input
              type="text"
              className="search-input w-full"
              value={repoUrl}
              onChange={(e) => onRepoUrlChange(e.target.value)}
              placeholder="https://github.com/owner/repository"
              aria-label="GitHub Repository URL"
              disabled={isBusy}
              required
            />
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <input
                type="text"
                className="search-input w-full font-mono text-xs"
                value={baseSha}
                onChange={(e) => onBaseShaChange(e.target.value)}
                placeholder="Base 40-character commit SHA"
                aria-label="Base commit SHA"
                disabled={isBusy}
                required
              />
              <input
                type="text"
                className="search-input w-full font-mono text-xs"
                value={headSha}
                onChange={(e) => onHeadShaChange(e.target.value)}
                placeholder="Head 40-character commit SHA"
                aria-label="Head commit SHA"
                disabled={isBusy}
                required
              />
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <input
                type="text"
                className="search-input w-full text-xs"
                value={baseRef}
                onChange={(e) => onBaseRefChange(e.target.value)}
                placeholder="Base branch / ref (e.g. main)"
                aria-label="Base branch reference"
                disabled={isBusy}
              />
              <input
                type="text"
                className="search-input w-full text-xs"
                value={headRef}
                onChange={(e) => onHeadRefChange(e.target.value)}
                placeholder="Head branch / ref (e.g. feature/auth)"
                aria-label="Head branch reference"
                disabled={isBusy}
              />
            </div>
            <div>
              <Button
                type="submit"
                variant="primary"
                disabled={isBusy}
                isLoading={isBusy}
              >
                {isBusy ? 'Analyzing Revisions...' : 'Analyze Changes'}
              </Button>
            </div>
          </div>
        )}

        {errorMsg && <Alert variant="error">{errorMsg}</Alert>}
      </form>
    </Card>
  );
};
