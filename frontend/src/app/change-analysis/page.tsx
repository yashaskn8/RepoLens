'use client';

import React, { useState, useEffect, Suspense } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import Link from 'next/link';
import { AppShell } from '@/components/layout/AppShell';
import { Card } from '@/components/ui/Card';
import { Button } from '@/components/ui/Button';
import { Input } from '@/components/ui/Input';
import { Badge } from '@/components/ui/Badge';
import { Tabs } from '@/components/ui/Tabs';
import { EmptyState } from '@/components/ui/EmptyState';
import { Skeleton } from '@/components/ui/Skeleton';
import { startChangeAnalysis, startChangeAnalysisFromPR, listChangeAnalyses } from '@/lib/api';
import { ChangeAnalysisSummary } from '@/types/domain';
import {
  GitPullRequest,
  GitBranch,
  Terminal,
  ArrowRight,
  ShieldCheck,
  AlertCircle,
  Clock,
  Layers,
  ChevronRight,
  Zap,
} from 'lucide-react';

function ChangeAnalysisEntryContent() {
  const router = useRouter();
  const searchParams = useSearchParams();

  const [mode, setMode] = useState<'pr' | 'commits'>('pr');
  const [prUrl, setPrUrl] = useState('https://github.com/yashaskn8/RepoLens/pull/1');
  const [repoUrl, setRepoUrl] = useState(searchParams.get('repo') || 'https://github.com/yashaskn8/RepoLens');
  const [baseRef, setBaseRef] = useState('main');
  const [headRef, setHeadRef] = useState('feature/auth-contracts');

  const [recentAnalyses, setRecentAnalyses] = useState<ChangeAnalysisSummary[]>([]);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [isLoadingRecent, setIsLoadingRecent] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    async function loadRecent() {
      try {
        const analyses = await listChangeAnalyses(undefined, 10, 0);
        setRecentAnalyses(analyses || []);
      } catch {
        setRecentAnalyses([]);
      } finally {
        setIsLoadingRecent(false);
      }
    }
    loadRecent();
  }, []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setIsSubmitting(true);

    try {
      if (mode === 'pr') {
        const result = await startChangeAnalysisFromPR({
          pr_url: prUrl,
        });
        router.push(`/changes/${result.id}`);
      } else {
        const result = await startChangeAnalysis({
          repository_url: repoUrl,
          base_commit_sha: baseRef,
          head_commit_sha: headRef,
        });
        router.push(`/changes/${result.id}`);
      }
    } catch (err: any) {
      setError(err?.message || 'Failed to initiate change analysis.');
      setIsSubmitting(false);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '2rem' }}>
      {/* Top Header */}
      <div>
        <h1
          style={{
            fontSize: '1.75rem',
            fontWeight: 800,
            fontFamily: 'var(--font-display)',
            color: '#ffffff',
            marginBottom: '0.4rem',
          }}
        >
          Change Intelligence & PR Blast Radius
        </h1>
        <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)' }}>
          Compute structural diffs, cross-layer contract breaks, affected UI components, and automated review findings.
        </p>
      </div>

      {/* Main Analysis Launcher Card */}
      <Card glow="cyan" style={{ padding: '2rem' }}>
        <div style={{ marginBottom: '1.5rem' }}>
          <Tabs
            tabs={[
              { id: 'pr', label: 'GitHub Pull Request', icon: <GitPullRequest size={15} /> },
              { id: 'commits', label: 'Git Branch / Commit Diff', icon: <GitBranch size={15} /> },
            ]}
            activeTab={mode}
            onChange={(id) => setMode(id as 'pr' | 'commits')}
          />
        </div>

        <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
          {error && (
            <div
              style={{
                padding: '0.85rem 1rem',
                borderRadius: 'var(--radius-md)',
                background: 'var(--error-bg)',
                border: '1px solid var(--error-border)',
                color: 'var(--error-text)',
                fontSize: '0.875rem',
                display: 'flex',
                alignItems: 'center',
                gap: '0.5rem',
              }}
            >
              <AlertCircle size={16} />
              <span>{error}</span>
            </div>
          )}

          {mode === 'pr' ? (
            <Input
              label="GitHub Pull Request URL or Reference"
              required
              placeholder="https://github.com/owner/repo/pull/42 or owner/repo#42"
              leftIcon={<GitPullRequest size={15} />}
              value={prUrl}
              onChange={(e) => setPrUrl(e.target.value)}
              disabled={isSubmitting}
            />
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              <Input
                label="Repository Git URL"
                required
                placeholder="https://github.com/owner/repository"
                leftIcon={<Terminal size={15} />}
                value={repoUrl}
                onChange={(e) => setRepoUrl(e.target.value)}
                disabled={isSubmitting}
              />
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
                <Input
                  label="Base Ref / Branch"
                  required
                  placeholder="main"
                  leftIcon={<GitBranch size={15} />}
                  value={baseRef}
                  onChange={(e) => setBaseRef(e.target.value)}
                  disabled={isSubmitting}
                />
                <Input
                  label="Head Ref / Branch"
                  required
                  placeholder="feature/branch"
                  leftIcon={<GitBranch size={15} />}
                  value={headRef}
                  onChange={(e) => setHeadRef(e.target.value)}
                  disabled={isSubmitting}
                />
              </div>
            </div>
          )}

          <div
            style={{
              padding: '0.75rem 1rem',
              borderRadius: 'var(--radius-md)',
              background: 'rgba(5, 8, 18, 0.8)',
              border: '1px solid var(--border-subtle)',
              fontSize: '0.75rem',
              color: 'var(--text-muted)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              flexWrap: 'wrap',
              gap: '0.5rem',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <ShieldCheck size={14} style={{ color: 'var(--success-text)' }} />
              <span>Computes transitive impact, schema breaks, and generates verified review comments.</span>
            </div>
            <Badge variant="cyan" size="sm">
              AST AST-Diff v1.2
            </Badge>
          </div>

          <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '0.5rem' }}>
            <Button
              type="submit"
              variant="accent-cyan"
              size="lg"
              isLoading={isSubmitting}
              rightIcon={<ArrowRight size={16} />}
            >
              {isSubmitting ? 'Analyzing Changes...' : 'Launch Change Intelligence'}
            </Button>
          </div>
        </form>
      </Card>

      {/* Recent Analyses List */}
      <div>
        <h3
          style={{
            fontSize: '1.125rem',
            fontWeight: 700,
            fontFamily: 'var(--font-display)',
            color: '#ffffff',
            marginBottom: '1rem',
          }}
        >
          Recent PR & Commit Analyses
        </h3>

        {isLoadingRecent ? (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
            <Skeleton height="4rem" />
            <Skeleton height="4rem" />
          </div>
        ) : recentAnalyses.length === 0 ? (
          <EmptyState
            icon={<GitPullRequest size={24} />}
            title="No past analyses"
            description="Submit a pull request or branch comparison above to view full blast radius reports."
          />
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
            {recentAnalyses.map((analysis) => (
              <Link
                key={analysis.id}
                href={`/changes/${analysis.id}`}
                style={{
                  padding: '1.25rem 1.5rem',
                  borderRadius: 'var(--radius-lg)',
                  backgroundColor: 'rgba(9, 13, 26, 0.75)',
                  border: '1px solid var(--border-glass)',
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  gap: '1rem',
                  transition: 'all var(--transition-fast)',
                }}
                className="glass-panel-interactive"
              >
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', marginBottom: '0.25rem' }}>
                    <span style={{ fontSize: '0.9375rem', fontWeight: 600, color: '#ffffff' }}>
                      {analysis.repository_owner}/{analysis.repository_name}
                    </span>
                    <Badge variant="default" size="sm">
                      {analysis.status}
                    </Badge>
                  </div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                    Base: {analysis.base_commit_sha?.slice(0, 8)} • Head: {analysis.head_commit_sha?.slice(0, 8)}
                  </div>
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                  {analysis.risk_level && (
                    <Badge
                      variant={
                        analysis.risk_level === 'CRITICAL'
                          ? 'critical'
                          : analysis.risk_level === 'HIGH'
                          ? 'high'
                          : analysis.risk_level === 'MEDIUM'
                          ? 'medium'
                          : 'low'
                      }
                      size="sm"
                    >
                      {analysis.risk_level} RISK
                    </Badge>
                  )}
                  <ChevronRight size={16} style={{ color: 'var(--text-muted)' }} />
                </div>
              </Link>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

export default function ChangeAnalysisPage() {
  return (
    <AppShell breadcrumbs={[{ label: 'Change Intelligence' }]} title="Change Analysis">
      <Suspense fallback={<div>Loading Change Intelligence...</div>}>
        <ChangeAnalysisEntryContent />
      </Suspense>
    </AppShell>
  );
}
