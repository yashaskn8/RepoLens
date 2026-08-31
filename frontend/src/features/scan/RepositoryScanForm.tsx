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
      <form onSubmit={onSubmit} className="flex flex-col gap-3">
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

        {errorMsg && <Alert variant="error">{errorMsg}</Alert>}
      </form>
    </Card>
  );
};

