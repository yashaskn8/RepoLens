'use client';

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { LandingNav } from '@/components/layout/LandingNav';
import { LandingFooter } from '@/components/layout/LandingFooter';
import { AuthModal } from '@/components/auth/AuthModal';
import { Button } from '@/components/ui/Button';
import { Badge } from '@/components/ui/Badge';
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
  Activity,
  Workflow,
  ExternalLink,
} from 'lucide-react';

export default function LandingPage() {
  const [isAuthModalOpen, setIsAuthModalOpen] = useState(false);
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [activePreviewTab, setActivePreviewTab] = useState<'architecture' | 'blast_radius' | 'patch_verification'>('architecture');
  const [quickRepoInput, setQuickRepoInput] = useState('https://github.com/yashaskn8/RepoLens');
  const router = useRouter();

  useEffect(() => {
    fetchHealth()
      .then(setHealth)
      .catch(() => setHealth(null));
  }, []);

  const handleQuickScan = (e: React.FormEvent) => {
    e.preventDefault();
    if (!quickRepoInput) return;
    router.push(`/scan?repo=${encodeURIComponent(quickRepoInput)}&branch=main`);
  };

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column', backgroundColor: 'var(--bg-base)' }}>
      {/* Navigation Header */}
      <LandingNav onOpenAuthModal={() => setIsAuthModalOpen(true)} />

      {/* Auth Modal */}
      <AuthModal isOpen={isAuthModalOpen} onClose={() => setIsAuthModalOpen(false)} />

      <main style={{ flex: 1 }}>
        {/* ========================================================================= */}
        {/* 1. ELEGANT, CENTERED HERO SECTION                                         */}
        {/* ========================================================================= */}
        <section
          style={{
            position: 'relative',
            padding: '4rem 1.5rem 2.5rem 1.5rem',
            maxWidth: '68rem',
            margin: '0 auto',
            textAlign: 'center',
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
          }}
        >
          {/* Subtle Ambient Radial Lighting */}
          <div
            style={{
              position: 'absolute',
              top: '0%',
              left: '50%',
              transform: 'translateX(-50%)',
              width: '42rem',
              height: '18rem',
              background: 'radial-gradient(ellipse at center, rgba(99, 102, 241, 0.15) 0%, rgba(56, 189, 248, 0.04) 50%, transparent 80%)',
              filter: 'blur(50px)',
              pointerEvents: 'none',
              zIndex: 0,
            }}
          />

          {/* Top Pill / Badge */}
          <div style={{ position: 'relative', zIndex: 1, marginBottom: '1.25rem' }}>
            <div
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '0.5rem',
                padding: '0.3rem 0.85rem',
                borderRadius: 'var(--radius-full)',
                background: 'rgba(255, 255, 255, 0.04)',
                border: '1px solid var(--border-glass)',
                boxShadow: 'var(--shadow-inner-glow)',
              }}
            >
              <span style={{ display: 'inline-block', width: '0.45rem', height: '0.45rem', borderRadius: '50%', background: 'var(--accent-cyan)' }} />
              <span style={{ fontSize: '0.8125rem', fontWeight: 600, color: 'var(--text-light)', fontFamily: 'var(--font-sans)' }}>
                Evidence-First Repository Intelligence
              </span>
              <span style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>•</span>
              <span style={{ fontSize: '0.75rem', fontFamily: 'var(--font-mono)', color: 'var(--accent-cyan)' }}>v1.0.1</span>
            </div>
          </div>

          {/* Hero Headline — Proportional & Readable */}
          <h1
            style={{
              position: 'relative',
              zIndex: 1,
              fontSize: 'clamp(2.25rem, 4.2vw, 3.6rem)',
              fontWeight: 800,
              fontFamily: 'var(--font-display)',
              letterSpacing: '-0.03em',
              lineHeight: 1.15,
              color: '#ffffff',
              maxWidth: '52rem',
            }}
          >
            Understand Full-Stack Codebases with{' '}
            <span className="gradient-text">Zero Untrusted Execution</span>
          </h1>

          {/* Hero Subtitle */}
          <p
            style={{
              position: 'relative',
              zIndex: 1,
              fontSize: '1.0625rem',
              color: 'var(--text-secondary)',
              lineHeight: 1.6,
              maxWidth: '42rem',
              marginTop: '1.1rem',
            }}
          >
            RepoLens reconstructs cross-layer AST dependency graphs between client API calls and backend route schemas — computing PR blast radius and generating 12-check verified security patches.
          </p>

          {/* Hero CTAs */}
          <div
            style={{
              position: 'relative',
              zIndex: 1,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: '1rem',
              marginTop: '1.75rem',
              flexWrap: 'wrap',
            }}
          >
            <Link href="/scan">
              <Button variant="glow" size="lg" rightIcon={<ArrowRight size={16} />}>
                Start Repository Scan
              </Button>
            </Link>

            <Link href="/findings">
              <Button variant="secondary" size="lg" leftIcon={<ShieldAlert size={16} />}>
                Explore Sample Findings
              </Button>
            </Link>

            <Link href="/change-analysis">
              <Button variant="outline" size="lg" leftIcon={<GitPullRequest size={16} />}>
                PR Blast Radius
              </Button>
            </Link>
          </div>

          {/* Quick URL Bar Form */}
          <div
            style={{
              position: 'relative',
              zIndex: 1,
              width: '100%',
              maxWidth: '36rem',
              marginTop: '1.75rem',
            }}
          >
            <form
              onSubmit={handleQuickScan}
              style={{
                display: 'flex',
                alignItems: 'center',
                padding: '0.3rem 0.4rem',
                borderRadius: 'var(--radius-md)',
                background: 'rgba(9, 13, 26, 0.85)',
                border: '1px solid var(--border-glass)',
                boxShadow: '0 4px 20px rgba(0, 0, 0, 0.35), var(--shadow-inner-glow)',
                gap: '0.4rem',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', paddingLeft: '0.6rem', color: 'var(--text-muted)' }}>
                <Search size={15} />
              </div>
              <input
                type="url"
                value={quickRepoInput}
                onChange={(e) => setQuickRepoInput(e.target.value)}
                placeholder="https://github.com/owner/repository"
                style={{
                  flex: 1,
                  background: 'transparent',
                  border: 'none',
                  outline: 'none',
                  color: 'var(--text-primary)',
                  fontSize: '0.8125rem',
                  fontFamily: 'var(--font-mono)',
                  padding: '0.4rem 0.25rem',
                }}
              />
              <Button type="submit" variant="accent-cyan" size="sm">
                Scan
              </Button>
            </form>
          </div>
        </section>

        {/* ========================================================================= */}
        {/* 2. AUTHENTIC 2026 PRODUCT PREVIEW WORKSPACE                                */}
        {/* ========================================================================= */}
        <section
          style={{
            maxWidth: '78rem',
            margin: '0 auto',
            padding: '1rem 1.5rem 3.5rem 1.5rem',
          }}
        >
          <div
            className="glass-panel"
            style={{
              borderRadius: 'var(--radius-xl)',
              border: '1px solid var(--border-glass-hover)',
              overflow: 'hidden',
              boxShadow: 'var(--shadow-xl), 0 0 50px rgba(99, 102, 241, 0.12)',
              background: 'rgba(7, 10, 22, 0.95)',
            }}
          >
            {/* Window Frame Bar */}
            <div
              style={{
                padding: '0.75rem 1.25rem',
                borderBottom: '1px solid var(--border-subtle)',
                background: 'rgba(4, 7, 15, 0.9)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                flexWrap: 'wrap',
                gap: '0.75rem',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <div style={{ width: '0.65rem', height: '0.65rem', borderRadius: '50%', background: '#ef4444' }} />
                <div style={{ width: '0.65rem', height: '0.65rem', borderRadius: '50%', background: '#f59e0b' }} />
                <div style={{ width: '0.65rem', height: '0.65rem', borderRadius: '50%', background: '#10b981' }} />
                <span style={{ fontSize: '0.75rem', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)', marginLeft: '0.5rem' }}>
                  repolens://workspace/investigation/demo-ast-01
                </span>
              </div>

              {/* Interactive Preview Tabs */}
              <div style={{ display: 'flex', gap: '0.35rem' }}>
                <button
                  type="button"
                  onClick={() => setActivePreviewTab('architecture')}
                  style={{
                    padding: '0.3rem 0.75rem',
                    fontSize: '0.75rem',
                    fontWeight: 600,
                    borderRadius: 'var(--radius-sm)',
                    border: 'none',
                    background: activePreviewTab === 'architecture' ? 'var(--accent-primary)' : 'rgba(255, 255, 255, 0.05)',
                    color: activePreviewTab === 'architecture' ? '#ffffff' : 'var(--text-secondary)',
                    cursor: 'pointer',
                    transition: 'all var(--transition-fast)',
                  }}
                >
                  Cross-Layer Graph
                </button>
                <button
                  type="button"
                  onClick={() => setActivePreviewTab('blast_radius')}
                  style={{
                    padding: '0.3rem 0.75rem',
                    fontSize: '0.75rem',
                    fontWeight: 600,
                    borderRadius: 'var(--radius-sm)',
                    border: 'none',
                    background: activePreviewTab === 'blast_radius' ? 'var(--accent-primary)' : 'rgba(255, 255, 255, 0.05)',
                    color: activePreviewTab === 'blast_radius' ? '#ffffff' : 'var(--text-secondary)',
                    cursor: 'pointer',
                    transition: 'all var(--transition-fast)',
                  }}
                >
                  PR Blast Radius
                </button>
                <button
                  type="button"
                  onClick={() => setActivePreviewTab('patch_verification')}
                  style={{
                    padding: '0.3rem 0.75rem',
                    fontSize: '0.75rem',
                    fontWeight: 600,
                    borderRadius: 'var(--radius-sm)',
                    border: 'none',
                    background: activePreviewTab === 'patch_verification' ? 'var(--accent-primary)' : 'rgba(255, 255, 255, 0.05)',
                    color: activePreviewTab === 'patch_verification' ? '#ffffff' : 'var(--text-secondary)',
                    cursor: 'pointer',
                    transition: 'all var(--transition-fast)',
                  }}
                >
                  12-Check Verification
                </button>
              </div>
            </div>

            {/* Window Content */}
            <div style={{ padding: '1.25rem' }}>
              {activePreviewTab === 'architecture' && (
                <ArchitectureGraph />
              )}

              {activePreviewTab === 'blast_radius' && (
                <div
                  style={{
                    display: 'grid',
                    gridTemplateColumns: 'minmax(260px, 320px) 1fr',
                    gap: '1rem',
                    minHeight: '22rem',
                  }}
                >
                  {/* Left: Changed Symbols Tree */}
                  <div
                    style={{
                      padding: '1rem',
                      borderRadius: 'var(--radius-md)',
                      background: 'rgba(4, 7, 17, 0.8)',
                      border: '1px solid var(--border-subtle)',
                      display: 'flex',
                      flexDirection: 'column',
                      gap: '0.6rem',
                    }}
                  >
                    <span style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-secondary)', textTransform: 'uppercase' }}>
                      Changed AST Symbols (PR #42)
                    </span>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.4rem', fontFamily: 'var(--font-mono)', fontSize: '0.8125rem' }}>
                      <div style={{ padding: '0.45rem 0.65rem', borderRadius: 'var(--radius-xs)', background: 'rgba(239, 68, 68, 0.12)', border: '1px solid rgba(239, 68, 68, 0.3)', color: '#f87171' }}>
                        Δ func: update_user_role()
                      </div>
                      <div style={{ padding: '0.45rem 0.65rem', borderRadius: 'var(--radius-xs)', background: 'rgba(249, 115, 22, 0.12)', border: '1px solid rgba(249, 115, 22, 0.3)', color: '#fb923c' }}>
                        Δ schema: UserUpdatePayload
                      </div>
                      <div style={{ padding: '0.45rem 0.65rem', borderRadius: 'var(--radius-xs)', background: 'rgba(56, 189, 248, 0.12)', border: '1px solid rgba(56, 189, 248, 0.3)', color: '#38bdf8' }}>
                        Δ route: POST /api/v1/users
                      </div>
                    </div>
                  </div>

                  {/* Right: Blast Radius Call Graph Hierarchy */}
                  <div
                    style={{
                      padding: '1.25rem',
                      borderRadius: 'var(--radius-md)',
                      background: 'rgba(4, 7, 17, 0.8)',
                      border: '1px solid var(--border-subtle)',
                      display: 'flex',
                      flexDirection: 'column',
                      gap: '0.85rem',
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <span style={{ fontSize: '0.875rem', fontWeight: 700, color: '#ffffff' }}>
                        Upstream Callers at Risk (3 impacted endpoints)
                      </span>
                      <Badge variant="high" size="sm">HIGH BLAST RADIUS</Badge>
                    </div>

                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', fontFamily: 'var(--font-mono)', fontSize: '0.8125rem' }}>
                      <div style={{ padding: '0.65rem', borderRadius: 'var(--radius-sm)', background: 'rgba(255, 255, 255, 0.03)', border: '1px solid var(--border-subtle)', display: 'flex', justifyContent: 'space-between' }}>
                        <span style={{ color: 'var(--text-light)' }}>frontend/src/features/admin/UserManagement.tsx</span>
                        <span style={{ color: 'var(--error-text)' }}>BREAKING CHANGE</span>
                      </div>
                      <div style={{ padding: '0.65rem', borderRadius: 'var(--radius-sm)', background: 'rgba(255, 255, 255, 0.03)', border: '1px solid var(--border-subtle)', display: 'flex', justifyContent: 'space-between' }}>
                        <span style={{ color: 'var(--text-light)' }}>backend/app/api/v1/endpoints/admin.py:promote_user</span>
                        <span style={{ color: 'var(--warning-text)' }}>PARAM MISMATCH</span>
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {activePreviewTab === 'patch_verification' && (
                <div
                  style={{
                    display: 'grid',
                    gridTemplateColumns: '1fr 1fr',
                    gap: '1rem',
                    minHeight: '22rem',
                  }}
                >
                  {/* Unified Diff */}
                  <div
                    style={{
                      borderRadius: 'var(--radius-md)',
                      background: '#030611',
                      border: '1px solid var(--border-glass)',
                      overflow: 'hidden',
                    }}
                  >
                    <div style={{ padding: '0.5rem 0.85rem', borderBottom: '1px solid var(--border-subtle)', fontSize: '0.75rem', fontFamily: 'var(--font-mono)', color: 'var(--accent-cyan)' }}>
                      candidate_patch.diff (backend/app/services/user_service.py)
                    </div>
                    <pre style={{ padding: '1rem', margin: 0, fontFamily: 'var(--font-mono)', fontSize: '0.8125rem', color: 'var(--text-code)', lineHeight: 1.5 }}>
                      <code>{`@@ -84,6 +84,9 @@ async def update_user(user_id: str, payload: UserUpdate):
+    if payload.role is not None and payload.role != user.role:
+        if not current_user.is_operator:
+            raise HTTPException(status_code=403, detail="Operator role required")
     user.role = payload.role
     await db.commit()`}</code>
                    </pre>
                  </div>

                  {/* 12-Check Invariants */}
                  <div
                    style={{
                      padding: '1rem',
                      borderRadius: 'var(--radius-md)',
                      background: 'rgba(4, 7, 17, 0.8)',
                      border: '1px solid var(--border-subtle)',
                      display: 'flex',
                      flexDirection: 'column',
                      gap: '0.5rem',
                    }}
                  >
                    <span style={{ fontSize: '0.8125rem', fontWeight: 700, color: '#ffffff' }}>
                      Automated 12-Check Verification Status
                    </span>
                    {[
                      'Tree-sitter Syntax Validation',
                      'Target Line Scope Confinement',
                      'Zero Unchecked Imports Added',
                      'No Hardcoded Secret Regressions',
                      'Deterministic Line Citation Match',
                    ].map((checkName) => (
                      <div
                        key={checkName}
                        style={{
                          padding: '0.5rem 0.75rem',
                          borderRadius: 'var(--radius-sm)',
                          background: 'rgba(16, 185, 129, 0.08)',
                          border: '1px solid rgba(16, 185, 129, 0.25)',
                          display: 'flex',
                          justifyContent: 'space-between',
                          alignItems: 'center',
                          fontSize: '0.75rem',
                        }}
                      >
                        <span style={{ color: 'var(--text-light)' }}>{checkName}</span>
                        <Badge variant="success" size="sm">PASS</Badge>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        </section>

        {/* ========================================================================= */}
        {/* 3. FOUR CORE CAPABILITIES GRID                                            */}
        {/* ========================================================================= */}
        <section
          style={{
            maxWidth: '78rem',
            margin: '0 auto',
            padding: '2.5rem 1.5rem',
          }}
        >
          <div style={{ textAlign: 'center', marginBottom: '2.5rem' }}>
            <span style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--accent-cyan)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>
              Engine Capabilities
            </span>
            <h2
              style={{
                fontSize: '1.875rem',
                fontWeight: 800,
                fontFamily: 'var(--font-display)',
                color: '#ffffff',
                marginTop: '0.4rem',
                letterSpacing: '-0.02em',
              }}
            >
              Built for Engineering Teams Managing Complex Repositories
            </h2>
          </div>

          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
              gap: '1.25rem',
            }}
          >
            {/* Capability 1 */}
            <div
              className="glass-panel"
              style={{
                padding: '1.75rem',
                display: 'flex',
                flexDirection: 'column',
                gap: '0.85rem',
              }}
            >
              <div
                style={{
                  width: '2.5rem',
                  height: '2.5rem',
                  borderRadius: 'var(--radius-md)',
                  background: 'rgba(56, 189, 248, 0.12)',
                  border: '1px solid rgba(56, 189, 248, 0.3)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  color: 'var(--accent-cyan)',
                }}
              >
                <Code2 size={20} />
              </div>
              <h3 style={{ fontSize: '1.125rem', fontWeight: 700, fontFamily: 'var(--font-display)', color: '#ffffff' }}>
                Cross-Layer Contract Matching
              </h3>
              <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', lineHeight: 1.55 }}>
                Statically reconstructs call graphs between client TypeScript endpoints (`fetch`/`axios`) and backend route handlers, identifying breaking changes before deploy.
              </p>
            </div>

            {/* Capability 2 */}
            <div
              className="glass-panel"
              style={{
                padding: '1.75rem',
                display: 'flex',
                flexDirection: 'column',
                gap: '0.85rem',
              }}
            >
              <div
                style={{
                  width: '2.5rem',
                  height: '2.5rem',
                  borderRadius: 'var(--radius-md)',
                  background: 'rgba(99, 102, 241, 0.12)',
                  border: '1px solid rgba(99, 102, 241, 0.3)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  color: 'var(--accent-primary)',
                }}
              >
                <GitPullRequest size={20} />
              </div>
              <h3 style={{ fontSize: '1.125rem', fontWeight: 700, fontFamily: 'var(--font-display)', color: '#ffffff' }}>
                Pull Request Blast Radius
              </h3>
              <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', lineHeight: 1.55 }}>
                Analyzes dual-revision AST diffs across commit ranges, computing upstream caller risk and transitive blast radius with NetworkX graph traversal.
              </p>
            </div>

            {/* Capability 3 */}
            <div
              className="glass-panel"
              style={{
                padding: '1.75rem',
                display: 'flex',
                flexDirection: 'column',
                gap: '0.85rem',
              }}
            >
              <div
                style={{
                  width: '2.5rem',
                  height: '2.5rem',
                  borderRadius: 'var(--radius-md)',
                  background: 'rgba(16, 185, 129, 0.12)',
                  border: '1px solid rgba(16, 185, 129, 0.3)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  color: 'var(--success-text)',
                }}
              >
                <ShieldCheck size={20} />
              </div>
              <h3 style={{ fontSize: '1.125rem', fontWeight: 700, fontFamily: 'var(--font-display)', color: '#ffffff' }}>
                12-Check AST Verification
              </h3>
              <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', lineHeight: 1.55 }}>
                Candidate security patches undergo Tree-sitter syntax validation, scope confinement, and regression checks before being presented for human review.
              </p>
            </div>

            {/* Capability 4 */}
            <div
              className="glass-panel"
              style={{
                padding: '1.75rem',
                display: 'flex',
                flexDirection: 'column',
                gap: '0.85rem',
              }}
            >
              <div
                style={{
                  width: '2.5rem',
                  height: '2.5rem',
                  borderRadius: 'var(--radius-md)',
                  background: 'rgba(168, 85, 247, 0.12)',
                  border: '1px solid rgba(168, 85, 247, 0.3)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  color: 'var(--accent-purple)',
                }}
              >
                <Lock size={20} />
              </div>
              <h3 style={{ fontSize: '1.125rem', fontWeight: 700, fontFamily: 'var(--font-display)', color: '#ffffff' }}>
                Guarded Delivery Boundary
              </h3>
              <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', lineHeight: 1.55 }}>
                Remote GitHub writes require authenticated OPERATOR credentials, resource ownership, and explicit human confirmation before isolated branch PR publication.
              </p>
            </div>
          </div>
        </section>

        {/* ========================================================================= */}
        {/* 4. SECURITY & CONFINEMENT GUARANTEES                                       */}
        {/* ========================================================================= */}
        <section
          style={{
            maxWidth: '78rem',
            margin: '0 auto',
            padding: '2.5rem 1.5rem 5rem 1.5rem',
          }}
        >
          <div
            className="glass-panel"
            style={{
              padding: '2.5rem',
              borderRadius: 'var(--radius-xl)',
              background: 'linear-gradient(135deg, rgba(99, 102, 241, 0.08) 0%, rgba(5, 8, 18, 0.85) 100%)',
              border: '1px solid var(--border-glass)',
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))',
              gap: '2rem',
            }}
          >
            <div>
              <span style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--accent-cyan)', textTransform: 'uppercase' }}>
                Hostile Repository Confinement
              </span>
              <h4 style={{ fontSize: '1.125rem', fontWeight: 700, color: '#ffffff', marginTop: '0.35rem' }}>
                Zero Untrusted Execution
              </h4>
              <p style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', marginTop: '0.35rem', lineHeight: 1.55 }}>
                RepoLens never executes repository test suites, never runs arbitrary makefiles or scripts, and never imports untrusted code during analysis.
              </p>
            </div>

            <div>
              <span style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--accent-primary)', textTransform: 'uppercase' }}>
                Tenant Isolation
              </span>
              <h4 style={{ fontSize: '1.125rem', fontWeight: 700, color: '#ffffff', marginTop: '0.35rem' }}>
                Strict Multi-Tenant Scoping
              </h4>
              <p style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', marginTop: '0.35rem', lineHeight: 1.55 }}>
                Every database query enforces strict user ownership (`user_id == current_user.id`). Unauthorized access fails closed with a 404 response.
              </p>
            </div>

            <div>
              <span style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--success-text)', textTransform: 'uppercase' }}>
                CSRF & Session Defense
              </span>
              <h4 style={{ fontSize: '1.125rem', fontWeight: 700, color: '#ffffff', marginTop: '0.35rem' }}>
                Opaque Token Digest Protection
              </h4>
              <p style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', marginTop: '0.35rem', lineHeight: 1.55 }}>
                256-bit entropy session tokens stored as SHA-256 digests in DB; transmitted via HttpOnly, SameSite=Lax cookies with double-submit CSRF checks.
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
