'use client';

import React, { useState, useEffect, Suspense } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import Link from 'next/link';
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
  Lock,
  Cpu,
  Code2,
  Server,
  Activity,
  Boxes,
  ChevronRight,
  ShieldAlert,
} from 'lucide-react';

const PRESET_CARDS = [
  {
    name: 'RepoLens (Self-Scan)',
    url: 'https://github.com/yashaskn8/RepoLens',
    branch: 'main',
    stack: 'Next.js 15 + FastAPI',
    astScope: '~180 AST Symbols',
    tag: 'Full-Stack',
  },
  {
    name: 'FastAPI Microservice',
    url: 'https://github.com/tiangolo/fastapi',
    branch: 'master',
    stack: 'Python 3.12 + Pydantic',
    astScope: '~450 Routes & Schemas',
    tag: 'Backend',
  },
  {
    name: 'Express API Server',
    url: 'https://github.com/expressjs/express',
    branch: 'master',
    stack: 'Node.js + JavaScript',
    astScope: '~320 Endpoints',
    tag: 'Node.js',
  },
];

const ANALYSIS_ENGINES = [
  { id: 'ast_graph', label: 'Cross-Layer AST Contract Matching', desc: 'Connects TSX fetch() calls to FastAPI route decorators', default: true },
  { id: 'treesitter', label: 'Tree-sitter Syntax Grammar Parse', desc: 'Extracts classes, functions, and call hierarchies', default: true },
  { id: 'semgrep', label: 'Deterministic Static Rulesets', desc: 'Scans for authorization, CSRF, and injection flaws', default: true },
  { id: 'osv', label: 'OSV Dependency Vulnerability Checker', desc: 'Cross-references package manifests with vulnerability databases', default: true },
];

function ScanWorkspaceContent() {
  const router = useRouter();
  const searchParams = useSearchParams();

  const [repoUrl, setRepoUrl] = useState(searchParams.get('repo') || 'https://github.com/yashaskn8/RepoLens');
  const [branch, setBranch] = useState(searchParams.get('branch') || 'main');
  const [activeScan, setActiveScan] = useState<Scan | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [recentScans, setRecentScans] = useState<Scan[]>([]);

  // Workflow streaming
  const { events, status: streamStatus } = useWorkflowStream(
    activeScan?.id,
    Boolean(activeScan?.id && (activeScan?.status === 'PENDING' || activeScan?.status === 'RUNNING'))
  );

  // Load recent scans on mount
  useEffect(() => {
    if (typeof window !== 'undefined') {
      const stored = localStorage.getItem('repolens_recent_scans');
      if (stored) {
        try {
          setRecentScans(JSON.parse(stored));
        } catch {
          // ignore
        }
      }
    }
  }, []);

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
          const updatedList = [updated, ...filtered].slice(0, 10);
          setRecentScans(updatedList);
          localStorage.setItem('repolens_recent_scans', JSON.stringify(updatedList));
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
        const updatedList = [scanResult, ...list].slice(0, 10);
        setRecentScans(updatedList);
        localStorage.setItem('repolens_recent_scans', JSON.stringify(updatedList));
      }
    } catch (err: any) {
      setError(err?.message || 'Failed to initiate repository scan.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const isScanning = activeScan?.status === 'RUNNING' || activeScan?.status === 'PENDING';

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      {/* Top Header Bar */}
      <div
        className="glass-panel"
        style={{
          padding: '1.25rem 1.75rem',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: '1rem',
        }}
      >
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem', marginBottom: '0.2rem' }}>
            <h1
              style={{
                fontSize: '1.35rem',
                fontWeight: 800,
                fontFamily: 'var(--font-display)',
                letterSpacing: '-0.02em',
                color: '#ffffff',
              }}
            >
              Repository AST Scan Workspace
            </h1>
            <Badge variant="cyan" size="sm">
              Tree-sitter Engine
            </Badge>
          </div>
          <p style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)' }}>
            Deterministic structural static analysis, cross-layer contract tracing, and verified quality scanning.
          </p>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '0.4rem',
              fontSize: '0.75rem',
              color: 'var(--text-muted)',
              padding: '0.35rem 0.75rem',
              borderRadius: 'var(--radius-sm)',
              background: 'rgba(255, 255, 255, 0.04)',
              border: '1px solid var(--border-subtle)',
            }}
          >
            <Lock size={12} style={{ color: 'var(--success-text)' }} />
            <span>Isolated Read-Only Sandbox</span>
          </div>
        </div>
      </div>

      {/* Main 2-Column Split Workspace */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'minmax(0, 1.4fr) minmax(0, 1fr)',
          gap: '1.5rem',
        }}
      >
        {/* Left Column: Repository Configuration & Execution Cockpit */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
          <div
            className="glass-panel"
            style={{
              padding: '1.75rem',
              display: 'flex',
              flexDirection: 'column',
              gap: '1.25rem',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '0.85rem' }}>
              <Terminal size={18} style={{ color: 'var(--accent-cyan)' }} />
              <h2 style={{ fontSize: '1.0625rem', fontWeight: 700, fontFamily: 'var(--font-display)', color: '#ffffff' }}>
                Scan Target Parameters
              </h2>
            </div>

            <form onSubmit={handleStartScan} style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
              {error && (
                <div
                  style={{
                    padding: '0.75rem 1rem',
                    borderRadius: 'var(--radius-md)',
                    background: 'var(--error-bg)',
                    border: '1px solid var(--error-border)',
                    color: 'var(--error-text)',
                    fontSize: '0.8125rem',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.5rem',
                  }}
                >
                  <AlertCircle size={16} />
                  <span>{error}</span>
                </div>
              )}

              {/* URL & Branch Grid */}
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 140px', gap: '1rem' }}>
                <Input
                  label="Git Repository URL"
                  required
                  placeholder="https://github.com/owner/repository"
                  leftIcon={<Terminal size={15} />}
                  value={repoUrl}
                  onChange={(e) => setRepoUrl(e.target.value)}
                  disabled={isSubmitting || isScanning}
                />

                <Input
                  label="Branch / Ref"
                  placeholder="main"
                  leftIcon={<GitBranch size={15} />}
                  value={branch}
                  onChange={(e) => setBranch(e.target.value)}
                  disabled={isSubmitting || isScanning}
                />
              </div>

              {/* Active Analysis Engines */}
              <div>
                <span style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-light)', textTransform: 'uppercase', letterSpacing: '0.05em', display: 'block', marginBottom: '0.65rem' }}>
                  Enabled Analysis Engines (Deterministic Pass)
                </span>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.5rem' }}>
                  {ANALYSIS_ENGINES.map((engine) => (
                    <div
                      key={engine.id}
                      style={{
                        padding: '0.65rem 0.85rem',
                        borderRadius: 'var(--radius-md)',
                        background: 'rgba(4, 7, 17, 0.7)',
                        border: '1px solid var(--border-subtle)',
                        display: 'flex',
                        flexDirection: 'column',
                        gap: '0.2rem',
                      }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                        <CheckCircle2 size={13} style={{ color: 'var(--accent-cyan)' }} />
                        <span style={{ fontSize: '0.75rem', fontWeight: 600, color: '#ffffff' }}>
                          {engine.label}
                        </span>
                      </div>
                      <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', paddingLeft: '1.2rem' }}>
                        {engine.desc}
                      </span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Security Confinement Chips */}
              <div
                style={{
                  padding: '0.75rem 1rem',
                  borderRadius: 'var(--radius-md)',
                  background: 'rgba(16, 185, 129, 0.06)',
                  border: '1px solid rgba(16, 185, 129, 0.2)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  flexWrap: 'wrap',
                  gap: '0.5rem',
                  fontSize: '0.75rem',
                  color: 'var(--text-light)',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                  <ShieldCheck size={14} style={{ color: 'var(--success-text)' }} />
                  <span>Hostile Repo Confinement: Zero untrusted code execution. Ephemeral shallow clone.</span>
                </div>
                <Badge variant="success" size="sm">
                  100% PASSIVE
                </Badge>
              </div>

              {/* Primary Launch Action Button */}
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', paddingTop: '0.5rem' }}>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                  Estimated extraction duration: ~8–15s
                </span>
                <Button
                  type="submit"
                  variant="glow"
                  size="lg"
                  isLoading={isSubmitting}
                  disabled={isScanning}
                  rightIcon={<ArrowRight size={16} />}
                >
                  {isScanning ? 'AST Scan in Progress...' : 'Launch AST Extraction'}
                </Button>
              </div>
            </form>
          </div>

          {/* Quick Preset Repositories Grid */}
          <div
            className="glass-panel"
            style={{
              padding: '1.5rem',
              display: 'flex',
              flexDirection: 'column',
              gap: '1rem',
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                Verified Benchmark Presets
              </span>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Click to auto-populate</span>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '0.75rem' }}>
              {PRESET_CARDS.map((preset) => (
                <div
                  key={preset.name}
                  onClick={() => {
                    if (!isScanning) {
                      setRepoUrl(preset.url);
                      setBranch(preset.branch);
                    }
                  }}
                  style={{
                    padding: '1rem',
                    borderRadius: 'var(--radius-md)',
                    background: repoUrl === preset.url ? 'rgba(99, 102, 241, 0.15)' : 'rgba(4, 7, 17, 0.7)',
                    border: repoUrl === preset.url ? '1px solid var(--accent-primary)' : '1px solid var(--border-subtle)',
                    cursor: isScanning ? 'not-allowed' : 'pointer',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '0.35rem',
                    transition: 'all var(--transition-fast)',
                  }}
                  className="interactive-btn"
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span style={{ fontSize: '0.8125rem', fontWeight: 700, color: '#ffffff' }}>
                      {preset.name}
                    </span>
                    <Badge variant="cyan" size="sm">{preset.tag}</Badge>
                  </div>
                  <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>{preset.stack}</span>
                  <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>{preset.astScope}</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Right Column: Live Stream & Pipeline Status */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
          {/* Active Scan Execution Log */}
          {activeScan ? (
            <div
              className="glass-panel"
              style={{
                padding: '1.5rem',
                display: 'flex',
                flexDirection: 'column',
                gap: '1.25rem',
                border: '1px solid var(--border-glass-hover)',
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '1rem' }}>
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.2rem' }}>
                    <span style={{ fontSize: '1rem', fontWeight: 700, color: '#ffffff' }}>
                      {activeScan.repository_url.split('/').slice(-2).join('/')}
                    </span>
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
                  <span style={{ fontSize: '0.75rem', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
                    ID: {activeScan.id} • Branch: {activeScan.branch || 'main'}
                  </span>
                </div>

                <Button
                  variant="glow"
                  size="sm"
                  onClick={() => router.push(`/scans/${activeScan.id}`)}
                  rightIcon={<ChevronRight size={14} />}
                >
                  View Findings
                </Button>
              </div>

              {/* Streaming Event Feed */}
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.65rem' }}>
                  <span style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-light)', display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                    <Clock size={13} style={{ color: 'var(--accent-cyan)' }} />
                    Live AST Stream ({events.length} milestones)
                  </span>
                  {isScanning && (
                    <span style={{ fontSize: '0.7rem', color: 'var(--accent-cyan)', display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
                      <Loader2 size={12} className="animate-spin" /> Ingesting
                    </span>
                  )}
                </div>

                <div
                  style={{
                    maxHeight: '18rem',
                    overflowY: 'auto',
                    padding: '0.85rem',
                    background: '#030611',
                    border: '1px solid var(--border-glass)',
                    borderRadius: 'var(--radius-md)',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '0.4rem',
                  }}
                >
                  {events.length === 0 ? (
                    <div style={{ color: 'var(--text-muted)', fontSize: '0.75rem', fontFamily: 'var(--font-mono)' }}>
                      Awaiting worker task dispatch and AST stream...
                    </div>
                  ) : (
                    events.map((ev) => (
                      <div
                        key={ev.id}
                        style={{
                          display: 'flex',
                          alignItems: 'baseline',
                          gap: '0.65rem',
                          fontSize: '0.75rem',
                          fontFamily: 'var(--font-mono)',
                        }}
                      >
                        <span style={{ color: 'var(--text-muted)' }}>
                          {new Date(ev.created_at).toLocaleTimeString()}
                        </span>
                        <Badge variant="default" size="sm">
                          {ev.event_type}
                        </Badge>
                        <span style={{ color: 'var(--text-code)' }}>{ev.message}</span>
                      </div>
                    ))
                  )}
                </div>
              </div>
            </div>
          ) : (
            /* 5-Phase Architecture Pipeline Indicator */
            <div
              className="glass-panel"
              style={{
                padding: '1.5rem',
                display: 'flex',
                flexDirection: 'column',
                gap: '1rem',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <Activity size={18} style={{ color: 'var(--accent-primary)' }} />
                <h3 style={{ fontSize: '1rem', fontWeight: 700, fontFamily: 'var(--font-display)', color: '#ffffff' }}>
                  Deterministic 5-Phase Pipeline
                </h3>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                {[
                  { num: '01', title: 'Passive Ingestion', desc: 'Ephemeral shallow clone, no credentials stored' },
                  { num: '02', title: 'Tree-sitter Parsing', desc: 'Generates AST nodes for Python, TypeScript, and TSX' },
                  { num: '03', title: 'Cross-Layer Mapping', desc: 'Links client fetch() calls to FastAPI route handlers' },
                  { num: '04', title: 'Deterministic Verifier', desc: 'Validates 12 AST invariants to discard hallucinations' },
                  { num: '05', title: 'Evidence Generation', desc: 'Produces line-grounded security and quality findings' },
                ].map((st, idx) => (
                  <div
                    key={st.num}
                    style={{
                      padding: '0.65rem 0.85rem',
                      borderRadius: 'var(--radius-md)',
                      background: 'rgba(4, 7, 17, 0.7)',
                      border: '1px solid var(--border-subtle)',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '0.75rem',
                    }}
                  >
                    <span style={{ fontSize: '0.75rem', fontFamily: 'var(--font-mono)', fontWeight: 700, color: 'var(--accent-cyan)' }}>
                      {st.num}
                    </span>
                    <div>
                      <div style={{ fontSize: '0.8125rem', fontWeight: 600, color: '#ffffff' }}>{st.title}</div>
                      <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>{st.desc}</div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Recent Scans Cockpit */}
          <div
            className="glass-panel"
            style={{
              padding: '1.5rem',
              display: 'flex',
              flexDirection: 'column',
              gap: '0.85rem',
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                Recent Workspace Scans ({recentScans.length})
              </span>
              <Link href="/findings" style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: '0.2rem' }}>
                All findings <ChevronRight size={12} />
              </Link>
            </div>

            {recentScans.length === 0 ? (
              <div style={{ padding: '1rem', textAlign: 'center', color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
                No recent scans yet. Launch your first scan to inspect results.
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                {recentScans.slice(0, 4).map((sc) => (
                  <Link
                    key={sc.id}
                    href={`/scans/${sc.id}`}
                    style={{
                      padding: '0.75rem 0.85rem',
                      borderRadius: 'var(--radius-md)',
                      background: 'rgba(4, 7, 17, 0.7)',
                      border: '1px solid var(--border-subtle)',
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                    }}
                    className="interactive-btn"
                  >
                    <div>
                      <div style={{ fontSize: '0.8125rem', fontWeight: 600, color: '#ffffff' }}>
                        {sc.repository_url.split('/').slice(-2).join('/')}
                      </div>
                      <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                        Branch: {sc.branch || 'main'}
                      </div>
                    </div>
                    <Badge
                      variant={sc.status === 'COMPLETED' ? 'success' : sc.status === 'FAILED' ? 'error' : 'default'}
                      size="sm"
                    >
                      {sc.status}
                    </Badge>
                  </Link>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
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
