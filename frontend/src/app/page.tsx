'use client';

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { LandingNav } from '@/components/layout/LandingNav';
import { LandingFooter } from '@/components/layout/LandingFooter';
import { AuthModal } from '@/components/auth/AuthModal';
import { Button } from '@/components/ui/Button';
import { Badge } from '@/components/ui/Badge';
import { Card } from '@/components/ui/Card';
import { ArchitectureGraph } from '@/components/visualization/ArchitectureGraph';
import { HealthResponse } from '@/types/domain';
import { fetchHealth } from '@/lib/api';
import {
  ArrowRight,
  ShieldCheck,
  Zap,
  GitBranch,
  Search,
  CheckCircle2,
  Lock,
  Workflow,
  Sparkles,
  Layers,
  FileCode,
  Globe,
  Database,
  Terminal,
  ChevronRight,
  ShieldAlert,
  GitPullRequest,
  Check,
  Cpu,
  Boxes,
  Code2,
  FileDiff,
  Radio,
} from 'lucide-react';

export default function LandingPage() {
  const [isAuthModalOpen, setIsAuthModalOpen] = useState(false);
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [repoInput, setRepoInput] = useState('https://github.com/yashaskn8/RepoLens');
  const [branchInput, setBranchInput] = useState('main');
  const router = useRouter();

  useEffect(() => {
    fetchHealth()
      .then(setHealth)
      .catch(() => setHealth(null));
  }, []);

  const handleStartScan = (e: React.FormEvent) => {
    e.preventDefault();
    if (!repoInput) return;
    const query = new URLSearchParams({
      repo: repoInput,
      branch: branchInput || 'main',
    });
    router.push(`/scan?${query.toString()}`);
  };

  const PRESETS = [
    { label: 'RepoLens (Self-Scan)', url: 'https://github.com/yashaskn8/RepoLens', branch: 'main' },
    { label: 'FastAPI Microservice', url: 'https://github.com/tiangolo/fastapi', branch: 'master' },
    { label: 'Next.js Commerce Demo', url: 'https://github.com/vercel/commerce', branch: 'main' },
  ];

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column', backgroundColor: 'var(--bg-base)' }}>
      {/* Navigation Header */}
      <LandingNav onOpenAuthModal={() => setIsAuthModalOpen(true)} />

      {/* Auth Modal */}
      <AuthModal isOpen={isAuthModalOpen} onClose={() => setIsAuthModalOpen(false)} />

      <main style={{ flex: 1 }}>
        {/* ========================================================================= */}
        {/* HERO SECTION — 2-Column Split Composition                                 */}
        {/* ========================================================================= */}
        <section
          style={{
            position: 'relative',
            padding: '4.5rem 1.5rem 3.5rem 1.5rem',
            maxWidth: '84rem',
            margin: '0 auto',
          }}
        >
          {/* Ambient Glows */}
          <div
            style={{
              position: 'absolute',
              top: '5%',
              left: '20%',
              width: '35rem',
              height: '25rem',
              background: 'radial-gradient(circle, rgba(99, 102, 241, 0.16) 0%, transparent 70%)',
              filter: 'blur(80px)',
              pointerEvents: 'none',
              zIndex: 0,
            }}
          />
          <div
            style={{
              position: 'absolute',
              top: '20%',
              right: '15%',
              width: '30rem',
              height: '20rem',
              background: 'radial-gradient(circle, rgba(56, 189, 248, 0.12) 0%, transparent 70%)',
              filter: 'blur(70px)',
              pointerEvents: 'none',
              zIndex: 0,
            }}
          />

          <div
            style={{
              position: 'relative',
              zIndex: 1,
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(340px, 1fr))',
              gap: '3rem',
              alignItems: 'center',
            }}
          >
            {/* Left Column: Headlines & Scan Launcher Form */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
              <div style={{ display: 'inline-flex', alignItems: 'center', gap: '0.5rem' }}>
                <Badge variant="cyan" size="md" icon={<Sparkles size={13} />}>
                  Deterministic Codebase Intelligence
                </Badge>
                {health?.status === 'healthy' && (
                  <Badge variant="success" size="sm">
                    Engine Live
                  </Badge>
                )}
              </div>

              <h1
                style={{
                  fontSize: 'clamp(2.25rem, 4vw, 3.75rem)',
                  fontWeight: 900,
                  fontFamily: 'var(--font-display)',
                  letterSpacing: '-0.035em',
                  lineHeight: 1.12,
                  color: '#ffffff',
                }}
              >
                Inspect Codebases with{' '}
                <span className="gradient-text">Zero Untrusted Execution</span>
              </h1>

              <p
                style={{
                  fontSize: '1.0625rem',
                  color: 'var(--text-secondary)',
                  lineHeight: 1.6,
                  maxWidth: '38rem',
                }}
              >
                RepoLens reconstructs cross-layer AST dependency graphs between frontend client calls, backend API routes, and database schemas — validating candidate security fixes with 12-point AST verification.
              </p>

              {/* Interactive Repository Scanner Form */}
              <div
                className="glass-panel"
                style={{
                  padding: '1.25rem',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '0.85rem',
                  border: '1px solid var(--border-glass-hover)',
                  boxShadow: '0 8px 32px rgba(0, 0, 0, 0.4), var(--shadow-inner-glow)',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <span style={{ fontSize: '0.8125rem', fontWeight: 600, color: 'var(--text-light)', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                    <Search size={14} style={{ color: 'var(--accent-cyan)' }} />
                    Quick Git Repository Inspector
                  </span>
                  <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                    Ephemeral shallow clone
                  </span>
                </div>

                <form onSubmit={handleStartScan} style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
                  <input
                    type="url"
                    value={repoInput}
                    onChange={(e) => setRepoInput(e.target.value)}
                    placeholder="https://github.com/owner/repository"
                    style={{
                      flex: '1 1 240px',
                      height: '2.75rem',
                      padding: '0 1rem',
                      fontSize: '0.875rem',
                      fontFamily: 'var(--font-mono)',
                      color: 'var(--text-primary)',
                      backgroundColor: 'var(--bg-input)',
                      border: '1px solid var(--border-glass)',
                      borderRadius: 'var(--radius-md)',
                      outline: 'none',
                    }}
                    className="glass-input"
                    required
                  />
                  <input
                    type="text"
                    value={branchInput}
                    onChange={(e) => setBranchInput(e.target.value)}
                    placeholder="main"
                    style={{
                      width: '5.5rem',
                      height: '2.75rem',
                      padding: '0 0.75rem',
                      fontSize: '0.875rem',
                      fontFamily: 'var(--font-mono)',
                      color: 'var(--text-primary)',
                      backgroundColor: 'var(--bg-input)',
                      border: '1px solid var(--border-glass)',
                      borderRadius: 'var(--radius-md)',
                      outline: 'none',
                      textAlign: 'center',
                    }}
                    className="glass-input"
                  />
                  <Button type="submit" variant="glow" size="lg" rightIcon={<ArrowRight size={16} />}>
                    Launch AST Scan
                  </Button>
                </form>

                {/* Preset Fast-Launch Pills */}
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap', paddingTop: '0.25rem' }}>
                  <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Presets:</span>
                  {PRESETS.map((preset) => (
                    <button
                      key={preset.label}
                      type="button"
                      onClick={() => {
                        setRepoInput(preset.url);
                        setBranchInput(preset.branch);
                      }}
                      style={{
                        background: 'rgba(255, 255, 255, 0.05)',
                        border: '1px solid var(--border-subtle)',
                        borderRadius: 'var(--radius-sm)',
                        padding: '0.2rem 0.6rem',
                        fontSize: '0.75rem',
                        color: 'var(--text-secondary)',
                        cursor: 'pointer',
                        transition: 'all var(--transition-fast)',
                      }}
                      className="interactive-btn"
                    >
                      {preset.label}
                    </button>
                  ))}
                </div>
              </div>

              {/* Trust Indicators */}
              <div style={{ display: 'flex', gap: '1.75rem', flexWrap: 'wrap', fontSize: '0.8125rem', color: 'var(--text-muted)' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                  <CheckCircle2 size={15} style={{ color: 'var(--success-text)' }} />
                  <span>Tree-sitter AST Graph</span>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                  <CheckCircle2 size={15} style={{ color: 'var(--accent-cyan)' }} />
                  <span>Human-in-the-Loop Patch Gate</span>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                  <CheckCircle2 size={15} style={{ color: 'var(--accent-purple)' }} />
                  <span>Strict IDOR Tenant Isolation</span>
                </div>
              </div>
            </div>

            {/* Right Column: Live Terminal / Architecture Graph Preview */}
            <div
              className="glass-panel"
              style={{
                borderRadius: 'var(--radius-xl)',
                border: '1px solid var(--border-glass)',
                overflow: 'hidden',
                boxShadow: 'var(--shadow-xl), 0 0 35px rgba(99, 102, 241, 0.12)',
              }}
            >
              {/* Terminal Window Header */}
              <div
                style={{
                  padding: '0.75rem 1rem',
                  borderBottom: '1px solid var(--border-subtle)',
                  background: 'rgba(5, 7, 14, 0.9)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
                  <div style={{ width: '0.65rem', height: '0.65rem', borderRadius: '50%', background: '#ef4444' }} />
                  <div style={{ width: '0.65rem', height: '0.65rem', borderRadius: '50%', background: '#f59e0b' }} />
                  <div style={{ width: '0.65rem', height: '0.65rem', borderRadius: '50%', background: '#10b981' }} />
                  <span style={{ fontSize: '0.75rem', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)', marginLeft: '0.5rem' }}>
                    repolens graph --cross-layer --trace
                  </span>
                </div>
                <Badge variant="cyan" size="sm">
                  LIVE INTERACTIVE
                </Badge>
              </div>

              {/* Interactive Graph Box */}
              <div style={{ padding: '1rem', background: 'rgba(4, 7, 17, 0.85)' }}>
                <ArchitectureGraph />
              </div>
            </div>
          </div>
        </section>

        {/* ========================================================================= */}
        {/* 7-STEP EVIDENCE PIPELINE                                                  */}
        {/* ========================================================================= */}
        <section
          style={{
            padding: '3rem 1.5rem',
            maxWidth: '84rem',
            margin: '0 auto',
          }}
        >
          <div style={{ textAlign: 'center', marginBottom: '2rem' }}>
            <Badge variant="purple" size="sm">
              DETERMINISTIC VERIFICATION
            </Badge>
            <h2
              style={{
                fontSize: '1.875rem',
                fontWeight: 800,
                fontFamily: 'var(--font-display)',
                marginTop: '0.5rem',
                color: '#ffffff',
              }}
            >
              The 7-Step Evidence-First Pipeline
            </h2>
            <p style={{ fontSize: '0.9375rem', color: 'var(--text-secondary)', marginTop: '0.35rem' }}>
              Specialist agents operate only on verified machine evidence — rejecting unsupported claims.
            </p>
          </div>

          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))',
              gap: '0.75rem',
            }}
          >
            {[
              { num: '01', title: 'Passive Clone', desc: 'Ephemeral sandbox' },
              { num: '02', title: 'AST Graph', desc: 'Tree-sitter parse' },
              { num: '03', title: 'Static Analyzers', desc: 'Semgrep + OSV' },
              { num: '04', title: 'Evidence Gate', desc: 'Citation verification' },
              { num: '05', title: 'Patch Proposal', desc: '12-point AST check' },
              { num: '06', title: 'HITL Review', desc: 'Operator authority' },
              { num: '07', title: 'Safe Delivery', desc: 'Isolated branch PR' },
            ].map((step, idx) => (
              <div
                key={step.num}
                className="glass-panel"
                style={{
                  padding: '1rem 0.85rem',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '0.35rem',
                  border: idx === 3 ? '1px solid var(--border-glass-hover)' : '1px solid var(--border-subtle)',
                  background: idx === 3 ? 'rgba(99, 102, 241, 0.12)' : 'rgba(11, 16, 32, 0.6)',
                }}
              >
                <span
                  style={{
                    fontSize: '0.75rem',
                    fontFamily: 'var(--font-mono)',
                    fontWeight: 700,
                    color: idx === 3 ? 'var(--accent-cyan)' : 'var(--accent-primary)',
                  }}
                >
                  STEP {step.num}
                </span>
                <span style={{ fontSize: '0.875rem', fontWeight: 700, color: '#ffffff' }}>
                  {step.title}
                </span>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                  {step.desc}
                </span>
              </div>
            ))}
          </div>
        </section>

        {/* ========================================================================= */}
        {/* ASYMMETRIC BENTO GRID — Core Capabilities                                 */}
        {/* ========================================================================= */}
        <section
          style={{
            padding: '3rem 1.5rem 5rem 1.5rem',
            maxWidth: '84rem',
            margin: '0 auto',
          }}
        >
          <div style={{ textAlign: 'center', marginBottom: '2.5rem' }}>
            <Badge variant="cyan" size="sm">
              ARCHITECTURAL PILLARS
            </Badge>
            <h2
              style={{
                fontSize: '1.875rem',
                fontWeight: 800,
                fontFamily: 'var(--font-display)',
                marginTop: '0.5rem',
                color: '#ffffff',
              }}
            >
              Why Developers Choose RepoLens
            </h2>
          </div>

          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(12, 1fr)',
              gap: '1.25rem',
            }}
          >
            {/* Bento Card 1 (Span 7): Cross-Layer Contract Intelligence */}
            <div
              className="glass-panel"
              style={{
                gridColumn: 'span 7',
                padding: '2rem',
                display: 'flex',
                flexDirection: 'column',
                justifyContent: 'space-between',
                background: 'linear-gradient(135deg, rgba(99, 102, 241, 0.1) 0%, rgba(11, 16, 32, 0.8) 100%)',
                border: '1px solid var(--border-glass-hover)',
              }}
            >
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.75rem' }}>
                  <Code2 size={22} style={{ color: 'var(--accent-cyan)' }} />
                  <span style={{ fontSize: '0.8125rem', fontWeight: 600, color: 'var(--accent-cyan)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                    Static Contract Reconstruction
                  </span>
                </div>
                <h3 style={{ fontSize: '1.35rem', fontWeight: 800, fontFamily: 'var(--font-display)', color: '#ffffff', marginBottom: '0.65rem' }}>
                  Cross-Layer Frontend-to-Backend Contract Matching
                </h3>
                <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
                  While traditional linters analyze single files in isolation, RepoLens connects client API calls in TypeScript to backend route decorators and Pydantic schemas in Python, flagging breaking changes across repo boundaries.
                </p>
              </div>

              <div
                style={{
                  marginTop: '1.5rem',
                  padding: '1rem',
                  borderRadius: 'var(--radius-md)',
                  background: 'rgba(4, 7, 17, 0.8)',
                  border: '1px solid var(--border-subtle)',
                  fontFamily: 'var(--font-mono)',
                  fontSize: '0.8125rem',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '0.4rem',
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', color: 'var(--text-muted)' }}>
                  <span>TSX: fetch(&quot;/api/v1/scans&quot;)</span>
                  <span style={{ color: 'var(--success-text)' }}>MATCHED</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', color: 'var(--text-muted)' }}>
                  <span>FastAPI: @router.post(&quot;/scans&quot;)</span>
                  <span style={{ color: 'var(--accent-cyan)' }}>ScanCreateSchema</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', color: 'var(--text-muted)' }}>
                  <span>SQLAlchemy: models.Scan</span>
                  <span style={{ color: 'var(--accent-purple)' }}>PostgreSQL</span>
                </div>
              </div>
            </div>

            {/* Bento Card 2 (Span 5): Pull Request Blast Radius */}
            <div
              className="glass-panel"
              style={{
                gridColumn: 'span 5',
                padding: '2rem',
                display: 'flex',
                flexDirection: 'column',
                justifyContent: 'space-between',
              }}
            >
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.75rem' }}>
                  <GitPullRequest size={22} style={{ color: 'var(--high-text)' }} />
                  <span style={{ fontSize: '0.8125rem', fontWeight: 600, color: 'var(--high-text)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                    Change Intelligence
                  </span>
                </div>
                <h3 style={{ fontSize: '1.35rem', fontWeight: 800, fontFamily: 'var(--font-display)', color: '#ffffff', marginBottom: '0.65rem' }}>
                  Dual-Revision AST Blast Radius
                </h3>
                <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
                  Analyzes dual-revision AST diffs across commit ranges or public GitHub PRs, deterministically computing upstream caller blast radius with NetworkX graph traversal.
                </p>
              </div>

              <div style={{ marginTop: '1.5rem' }}>
                <Link href="/change-analysis">
                  <Button variant="secondary" size="md" rightIcon={<ChevronRight size={14} />}>
                    Try PR Diff Analyzer
                  </Button>
                </Link>
              </div>
            </div>

            {/* Bento Card 3 (Span 4): Zero Execution Sandbox */}
            <div
              className="glass-panel"
              style={{
                gridColumn: 'span 4',
                padding: '1.75rem',
                display: 'flex',
                flexDirection: 'column',
                gap: '0.75rem',
              }}
            >
              <Lock size={20} style={{ color: 'var(--success-text)' }} />
              <h3 style={{ fontSize: '1.125rem', fontWeight: 700, fontFamily: 'var(--font-display)', color: '#ffffff' }}>
                Hostile Repository Confinement
              </h3>
              <p style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', lineHeight: 1.55 }}>
                RepoLens never executes repository test suites, never executes arbitrary scripts or Makefiles, and never imports untrusted modules during analysis.
              </p>
            </div>

            {/* Bento Card 4 (Span 4): Guarded Remediation Authority */}
            <div
              className="glass-panel"
              style={{
                gridColumn: 'span 4',
                padding: '1.75rem',
                display: 'flex',
                flexDirection: 'column',
                gap: '0.75rem',
              }}
            >
              <ShieldAlert size={20} style={{ color: 'var(--accent-purple)' }} />
              <h3 style={{ fontSize: '1.125rem', fontWeight: 700, fontFamily: 'var(--font-display)', color: '#ffffff' }}>
                Human Approval Gate
              </h3>
              <p style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', lineHeight: 1.55 }}>
                Candidate patches are generated with 12-check AST verification and require explicit human operator approval before optional GitHub delivery.
              </p>
            </div>

            {/* Bento Card 5 (Span 4): Multi-Tenant IDOR Defense */}
            <div
              className="glass-panel"
              style={{
                gridColumn: 'span 4',
                padding: '1.75rem',
                display: 'flex',
                flexDirection: 'column',
                gap: '0.75rem',
              }}
            >
              <Boxes size={20} style={{ color: 'var(--accent-cyan)' }} />
              <h3 style={{ fontSize: '1.125rem', fontWeight: 700, fontFamily: 'var(--font-display)', color: '#ffffff' }}>
                Multi-Tenant Isolation
              </h3>
              <p style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', lineHeight: 1.55 }}>
                All database queries enforce strict user scoping (user_id == current_user.id). Attempting to access another tenant&apos;s artifacts returns 404 Not Found.
              </p>
            </div>
          </div>
        </section>
      </main>

      {/* Footer */}
      <LandingFooter />
    </div>
  );
}
