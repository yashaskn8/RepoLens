'use client';

import React, { useState, useEffect, Suspense } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import Link from 'next/link';
import { AppShell } from '@/components/layout/AppShell';
import { Card } from '@/components/ui/Card';
import { Button } from '@/components/ui/Button';
import { Input } from '@/components/ui/Input';
import { Badge } from '@/components/ui/Badge';
import { startScan, fetchScan } from '@/lib/api';
import { useWorkflowStream } from '@/lib/useWorkflowStream';
import { Scan } from '@/types/domain';
import { useAuth } from '@/context/AuthContext';
import {
  Scan as ScanIcon,
  GitBranch,
  Terminal,
  ShieldCheck,
  CheckCircle2,
  AlertCircle,
  Clock,
  ArrowRight,
  Loader2,
  Lock,
  ChevronRight,
  ChevronDown,
  Activity,
} from 'lucide-react';

const PRESET_CARDS = [
  {
    name: 'RepoLens',
    url: 'https://github.com/yashaskn8/RepoLens',
    branch: 'main',
    stack: 'Next.js + FastAPI',
    desc: 'Full-stack application',
    tag: 'Full-Stack',
  },
  {
    name: 'FastAPI',
    url: 'https://github.com/tiangolo/fastapi',
    branch: 'master',
    stack: 'Python + Pydantic',
    desc: 'Python web framework',
    tag: 'Backend',
  },
  {
    name: 'Express',
    url: 'https://github.com/expressjs/express',
    branch: 'master',
    stack: 'Node.js + JavaScript',
    desc: 'Web server library',
    tag: 'Node.js',
  },
];

const ANALYSIS_ENGINES = [
  { id: 'ast_graph', label: 'Code Relationships', desc: 'Connects frontend API calls to backend route handlers' },
  { id: 'treesitter', label: 'Code Parser', desc: 'Reads classes, functions, and import hierarchies' },
  { id: 'semgrep', label: 'Security Rules', desc: 'Scans for authorization, CSRF, and injection flaws' },
  { id: 'osv', label: 'Dependency Vulnerabilities', desc: 'Checks dependencies against vulnerability databases' },
];

function getFriendlyEventLabel(eventType: string): string {
  switch (eventType?.toUpperCase()) {
    case 'INGESTION':
    case 'CLONE':
      return 'Preparing repository';
    case 'PARSING':
    case 'AST':
      return 'Reading code';
    case 'GRAPH':
    case 'MAPPING':
      return 'Finding relationships';
    case 'ANALYSIS':
    case 'SCANNING':
    case 'SEMGREP':
    case 'OSV':
      return 'Checking for risks';
    case 'COMPLETED':
    case 'SUMMARY':
      return 'Preparing results';
    default:
      return eventType?.toLowerCase() || 'Processing';
  }
}

function ScanWorkspaceContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const { isAuthenticated, isLoading: isAuthLoading } = useAuth();

  const [repoUrl, setRepoUrl] = useState(searchParams.get('repo') || 'https://github.com/yashaskn8/RepoLens');
  const [branch, setBranch] = useState(searchParams.get('branch') || 'main');
  const [activeScan, setActiveScan] = useState<Scan | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showEngines, setShowEngines] = useState(false);
  const [recentScans, setRecentScans] = useState<Scan[]>([]);

  // Workflow streaming
  const { events } = useWorkflowStream(
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

    if (!isAuthenticated) {
      setError('Sign in to analyze repositories.');
      window.dispatchEvent(new Event('repolens:open-auth'));
      return;
    }

    setError(null);
    setIsSubmitting(true);

    try {
      const scanResult = await startScan({
        repository_url: repoUrl,
        branch: branch || 'main',
      });
      setActiveScan(scanResult);

      if (typeof window !== 'undefined') {
        const stored = localStorage.getItem('repolens_recent_scans');
        const list: Scan[] = stored ? JSON.parse(stored) : [];
        const updatedList = [scanResult, ...list].slice(0, 10);
        setRecentScans(updatedList);
        localStorage.setItem('repolens_recent_scans', JSON.stringify(updatedList));
      }
    } catch (err: unknown) {
      if (err instanceof Error) {
        setError(err.message);
      } else {
        setError('Failed to initiate repository scan.');
      }
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
              Scan Repository
            </h1>
          </div>
          <p style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)' }}>
            Analyze any public GitHub repository to discover structure, code relationships, and security findings.
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
            <span>Passive &amp; Isolated Analysis</span>
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
        {/* Left Column: Repository Configuration */}
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
                Repository to Analyze
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
                  label="Repository URL"
                  required
                  placeholder="https://github.com/owner/repository"
                  leftIcon={<Terminal size={15} />}
                  value={repoUrl}
                  onChange={(e) => setRepoUrl(e.target.value)}
                  disabled={isSubmitting || isScanning}
                />

                <Input
                  label="Branch (optional)"
                  placeholder="main"
                  leftIcon={<GitBranch size={15} />}
                  value={branch}
                  onChange={(e) => setBranch(e.target.value)}
                  disabled={isSubmitting || isScanning}
                />
              </div>

              {/* Progressive Disclosure: Analysis Engines */}
              <div style={{ border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-md)', overflow: 'hidden' }}>
                <button
                  type="button"
                  onClick={() => setShowEngines(!showEngines)}
                  style={{
                    width: '100%',
                    padding: '0.65rem 0.85rem',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    background: 'rgba(255, 255, 255, 0.02)',
                    border: 'none',
                    cursor: 'pointer',
                    color: 'var(--text-secondary)',
                    fontSize: '0.75rem',
                    fontWeight: 600,
                  }}
                >
                  <span style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                    <CheckCircle2 size={13} style={{ color: 'var(--accent-cyan)' }} />
                    4 Active Analysis Engines (Code Relationships, Syntax, Security Rules, Dependencies)
                  </span>
                  <ChevronDown
                    size={14}
                    style={{
                      transform: showEngines ? 'rotate(180deg)' : 'none',
                      transition: 'transform var(--transition-fast)',
                    }}
                  />
                </button>

                {showEngines && (
                  <div style={{ padding: '0.75rem', background: 'rgba(4, 7, 17, 0.6)', display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.5rem', borderTop: '1px solid var(--border-subtle)' }}>
                    {ANALYSIS_ENGINES.map((engine) => (
                      <div
                        key={engine.id}
                        style={{
                          padding: '0.5rem 0.75rem',
                          borderRadius: 'var(--radius-sm)',
                          background: 'rgba(255, 255, 255, 0.02)',
                          border: '1px solid var(--border-subtle)',
                        }}
                      >
                        <div style={{ fontSize: '0.75rem', fontWeight: 600, color: '#ffffff' }}>
                          {engine.label}
                        </div>
                        <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>
                          {engine.desc}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Safety note */}
              <div
                style={{
                  padding: '0.65rem 0.85rem',
                  borderRadius: 'var(--radius-md)',
                  background: 'rgba(16, 185, 129, 0.06)',
                  border: '1px solid rgba(16, 185, 129, 0.2)',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.5rem',
                  fontSize: '0.75rem',
                  color: 'var(--text-light)',
                }}
              >
                <ShieldCheck size={14} style={{ color: 'var(--success-text)' }} />
                <span>Zero untrusted code execution. Repositories are analyzed passively.</span>
              </div>

              {/* Primary Action Button */}
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', paddingTop: '0.5rem' }}>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                  Estimated time: ~8–15 seconds
                </span>
                <Button
                  type="submit"
                  variant="glow"
                  size="lg"
                  isLoading={isSubmitting}
                  disabled={isScanning || isAuthLoading}
                  rightIcon={<ArrowRight size={16} />}
                >
                  {isScanning
                    ? 'Analyzing Repository...'
                    : isAuthenticated
                      ? 'Analyze Repository'
                      : 'Sign in to Analyze'}
                </Button>
              </div>
            </form>
          </div>

          {/* Quick Examples */}
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
                Example Repositories
              </span>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Click to fill</span>
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
                    padding: '0.85rem 1rem',
                    borderRadius: 'var(--radius-md)',
                    background: repoUrl === preset.url ? 'rgba(99, 102, 241, 0.15)' : 'rgba(4, 7, 17, 0.7)',
                    border: repoUrl === preset.url ? '1px solid var(--accent-primary)' : '1px solid var(--border-subtle)',
                    cursor: isScanning ? 'not-allowed' : 'pointer',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '0.3rem',
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
                  <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>{preset.desc}</span>
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
                      {activeScan.status === 'COMPLETED' ? 'Analysis Complete' : activeScan.status}
                    </Badge>
                  </div>
                  <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                    Branch: {activeScan.branch || 'main'}
                  </span>
                </div>

                <Button
                  variant="glow"
                  size="sm"
                  onClick={() => router.push(`/scans/${activeScan.id}`)}
                  rightIcon={<ChevronRight size={14} />}
                >
                  View Results
                </Button>
              </div>

              {/* Streaming Event Feed */}
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.65rem' }}>
                  <span style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-light)', display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                    <Clock size={13} style={{ color: 'var(--accent-cyan)' }} />
                    Analysis Progress ({events.length} steps)
                  </span>
                  {isScanning && (
                    <span style={{ fontSize: '0.7rem', color: 'var(--accent-cyan)', display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
                      <Loader2 size={12} className="animate-spin" /> Running
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
                      Starting analysis steps...
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
                        }}
                      >
                        <span style={{ color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontSize: '0.7rem' }}>
                          {new Date(ev.created_at).toLocaleTimeString()}
                        </span>
                        <Badge variant="default" size="sm">
                          {getFriendlyEventLabel(ev.event_type)}
                        </Badge>
                        <span style={{ color: 'var(--text-secondary)' }}>{ev.message}</span>
                      </div>
                    ))
                  )}
                </div>
              </div>
            </div>
          ) : (
            /* Clear 5-Phase Pipeline Indicator */
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
                  Analysis Sequence
                </h3>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                {[
                  { num: '01', title: 'Preparing repository', desc: 'Secure shallow clone, isolated in memory' },
                  { num: '02', title: 'Reading code', desc: 'Parsing classes, functions, and files' },
                  { num: '03', title: 'Finding relationships', desc: 'Mapping client API calls to backend handlers' },
                  { num: '04', title: 'Checking for risks', desc: 'Scanning for security, privacy, and contract issues' },
                  { num: '05', title: 'Preparing results', desc: 'Compiling findings with line-by-line evidence' },
                ].map((st) => (
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
                Recent Scans ({recentScans.length})
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
    <AppShell breadcrumbs={[{ label: 'Scans', href: '/scan' }, { label: 'Scan Repository' }]} title="Scan Repository">
      <Suspense fallback={<div>Loading workspace...</div>}>
        <ScanWorkspaceContent />
      </Suspense>
    </AppShell>
  );
}
