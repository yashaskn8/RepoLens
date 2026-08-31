'use client';

import React, { useState, useEffect, Suspense } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import { AppShell } from '@/components/layout/AppShell';
import { Card } from '@/components/ui/Card';
import { Button } from '@/components/ui/Button';
import { Input } from '@/components/ui/Input';
import { Badge } from '@/components/ui/Badge';
import { StatusIndicator } from '@/components/ui/StatusIndicator';
import { startScan, fetchScan } from '@/lib/api';
import { useWorkflowStream } from '@/lib/useWorkflowStream';
import { Scan, ScanStatus } from '@/types/domain';
import {
  Scan as ScanIcon,
  GitBranch,
  Terminal,
  ShieldCheck,
  Zap,
  CheckCircle2,
  AlertCircle,
  Clock,
  Layers,
  ArrowRight,
  ExternalLink,
  Loader2,
  FileCode,
} from 'lucide-react';

function ScanWorkspaceContent() {
  const router = useRouter();
  const searchParams = useSearchParams();

  const [repoUrl, setRepoUrl] = useState(searchParams.get('repo') || 'https://github.com/yashaskn8/RepoLens');
  const [branch, setBranch] = useState(searchParams.get('branch') || 'main');
  const [activeScan, setActiveScan] = useState<Scan | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Workflow streaming
  const { events, status: streamStatus } = useWorkflowStream(
    activeScan?.id,
    Boolean(activeScan?.id && (activeScan?.status === 'PENDING' || activeScan?.status === 'RUNNING'))
  );

  // Poll scan completion if running
  useEffect(() => {
    if (!activeScan?.id) return;
    if (activeScan.status === 'COMPLETED' || activeScan.status === 'FAILED') return;

    const interval = setInterval(async () => {
      try {
        const updated = await fetchScan(activeScan.id);
        setActiveScan(updated);

        // Save to local storage recent scans
        if (typeof window !== 'undefined') {
          const stored = localStorage.getItem('repolens_recent_scans');
          const list: Scan[] = stored ? JSON.parse(stored) : [];
          const filtered = list.filter((s) => s.id !== updated.id);
          localStorage.setItem('repolens_recent_scans', JSON.stringify([updated, ...filtered].slice(0, 10)));
        }

        if (updated.status === 'COMPLETED' || updated.status === 'FAILED') {
          clearInterval(interval);
        }
      } catch {
        // ignore polling error
      }
    }, 2000);

    return () => clearInterval(interval);
  }, [activeScan?.id, activeScan?.status]);

  const handleStartScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!repoUrl) return;

    setError(null);
    setIsSubmitting(true);

    try {
      const scanResult = await startScan({
        repository_url: repoUrl,
        branch: branch || 'main',
      });
      setActiveScan(scanResult);

      // Save initial scan
      if (typeof window !== 'undefined') {
        const stored = localStorage.getItem('repolens_recent_scans');
        const list: Scan[] = stored ? JSON.parse(stored) : [];
        localStorage.setItem('repolens_recent_scans', JSON.stringify([scanResult, ...list].slice(0, 10)));
      }
    } catch (err: any) {
      setError(err?.message || 'Failed to initiate repository scan.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const PRESETS = [
    { label: 'RepoLens', url: 'https://github.com/yashaskn8/RepoLens', branch: 'main' },
    { label: 'FastAPI Microservice', url: 'https://github.com/tiangolo/fastapi', branch: 'master' },
    { label: 'Express Backend', url: 'https://github.com/expressjs/express', branch: 'master' },
  ];

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
          Repository Scan Workspace
        </h1>
        <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)' }}>
          Run deterministic AST extraction, discover cross-layer contract dependencies, and verify code quality.
        </p>
      </div>

      {/* Main Scan Form Card */}
      <Card glow="indigo" style={{ padding: '2rem' }}>
        <form onSubmit={handleStartScan} style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
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

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1rem' }}>
            <Input
              label="Repository Git URL"
              required
              placeholder="https://github.com/owner/repository"
              leftIcon={<Terminal size={15} />}
              value={repoUrl}
              onChange={(e) => setRepoUrl(e.target.value)}
              disabled={isSubmitting || (activeScan?.status === 'RUNNING' || activeScan?.status === 'PENDING')}
            />

            <Input
              label="Target Branch / Commit Ref"
              placeholder="main"
              leftIcon={<GitBranch size={15} />}
              value={branch}
              onChange={(e) => setBranch(e.target.value)}
              disabled={isSubmitting || (activeScan?.status === 'RUNNING' || activeScan?.status === 'PENDING')}
            />
          </div>

          {/* Quick Presets */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Quick Presets:</span>
            {PRESETS.map((preset) => (
              <button
                key={preset.label}
                type="button"
                onClick={() => {
                  setRepoUrl(preset.url);
                  setBranch(preset.branch);
                }}
                disabled={isSubmitting || (activeScan?.status === 'RUNNING' || activeScan?.status === 'PENDING')}
                style={{
                  background: 'rgba(255, 255, 255, 0.05)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: 'var(--radius-full)',
                  padding: '0.2rem 0.65rem',
                  color: 'var(--text-secondary)',
                  fontSize: '0.75rem',
                  cursor: 'pointer',
                  transition: 'all var(--transition-fast)',
                }}
              >
                {preset.label}
              </button>
            ))}
          </div>

          {/* Security & Sandbox Scope Notice */}
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
              <span>Isolated execution. Read-only Git clone. No code sent to external cloud storage.</span>
            </div>
            <Badge variant="cyan" size="sm">
              Sandbox v2.4
            </Badge>
          </div>

          <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '0.5rem' }}>
            <Button
              type="submit"
              variant="glow"
              size="lg"
              isLoading={isSubmitting}
              disabled={activeScan?.status === 'RUNNING' || activeScan?.status === 'PENDING'}
              rightIcon={<ArrowRight size={16} />}
            >
              {activeScan?.status === 'RUNNING' || activeScan?.status === 'PENDING'
                ? 'Scan In Progress...'
                : 'Start Full Repository Scan'}
            </Button>
          </div>
        </form>
      </Card>

      {/* Active Scan Progress / Results Display */}
      {activeScan && (
        <Card style={{ padding: '2rem', display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '1rem', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '1.25rem' }}>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem', marginBottom: '0.35rem' }}>
                <h3 style={{ fontSize: '1.25rem', fontWeight: 700, fontFamily: 'var(--font-display)', color: '#ffffff' }}>
                  Scan: {activeScan.repository_url.split('/').slice(-2).join('/')}
                </h3>
                <Badge
                  variant={
                    activeScan.status === 'COMPLETED'
                      ? 'success'
                      : activeScan.status === 'FAILED'
                      ? 'error'
                      : 'cyan'
                  }
                  size="sm"
                >
                  {activeScan.status}
                </Badge>
              </div>
              <div style={{ fontSize: '0.75rem', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
                ID: {activeScan.id} • Ref: {activeScan.resolved_branch_or_ref || activeScan.branch || 'main'} • Commit: {activeScan.commit_hash?.slice(0, 7) || activeScan.commit_sha?.slice(0, 7) || 'HEAD'}
              </div>
            </div>

            <div style={{ display: 'flex', gap: '0.75rem' }}>
              <Button
                variant="glow"
                size="md"
                onClick={() => router.push(`/scans/${activeScan.id}`)}
                rightIcon={<ArrowRight size={14} />}
              >
                Open Investigation Workspace
              </Button>
            </div>
          </div>

          {/* Real-time Streaming Event Timeline */}
          <div>
            <div style={{ fontSize: '0.8125rem', fontWeight: 600, color: 'var(--text-light)', marginBottom: '0.75rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <Clock size={14} /> Live AST Execution Log ({events.length} events)
            </div>

            <div
              style={{
                maxHeight: '18rem',
                overflowY: 'auto',
                padding: '1rem',
                background: 'var(--bg-code)',
                border: '1px solid var(--border-subtle)',
                borderRadius: 'var(--radius-md)',
                display: 'flex',
                flexDirection: 'column',
                gap: '0.5rem',
              }}
            >
              {events.length === 0 ? (
                <div style={{ color: 'var(--text-muted)', fontSize: '0.75rem', fontFamily: 'var(--font-mono)' }}>
                  Awaiting worker task dispatch and AST stream...
                </div>
              ) : (
                events.map((event) => (
                  <div
                    key={event.id}
                    style={{
                      display: 'flex',
                      alignItems: 'baseline',
                      gap: '0.75rem',
                      fontSize: '0.75rem',
                      fontFamily: 'var(--font-mono)',
                    }}
                  >
                    <span style={{ color: 'var(--text-muted)' }}>
                      {new Date(event.created_at).toLocaleTimeString()}
                    </span>
                    <Badge variant="default" size="sm">
                      {event.event_type}
                    </Badge>
                    <span style={{ color: 'var(--text-code)' }}>{event.message}</span>
                  </div>
                ))
              )}
            </div>
          </div>
        </Card>
      )}
    </div>
  );
}

export default function ScanPage() {
  return (
    <AppShell breadcrumbs={[{ label: 'Scans', href: '/scan' }, { label: 'New Workspace' }]} title="Repository Scan">
      <Suspense fallback={<div>Loading workspace...</div>}>
        <ScanWorkspaceContent />
      </Suspense>
    </AppShell>
  );
}
