'use client';

import React, { useState } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { LandingNav } from '@/components/layout/LandingNav';
import { LandingFooter } from '@/components/layout/LandingFooter';
import { AuthModal } from '@/components/auth/AuthModal';
import { Button } from '@/components/ui/Button';
import { Badge } from '@/components/ui/Badge';
import { ArchitectureGraph } from '@/components/visualization/ArchitectureGraph';
import {
  ArrowRight,
  ShieldCheck,
  Search,
  Lock,
  GitPullRequest,
  Code2,
  CheckCircle2,
  FileCode,
  Shield,
  Layers,
} from 'lucide-react';

const PRESET_REPOS = [
  { label: 'RepoLens', url: 'https://github.com/yashaskn8/RepoLens' },
  { label: 'FastAPI', url: 'https://github.com/tiangolo/fastapi' },
  { label: 'Express', url: 'https://github.com/expressjs/express' },
];

export default function LandingPage() {
  const [isAuthModalOpen, setIsAuthModalOpen] = useState(false);
  const [activePreviewTab, setActivePreviewTab] = useState<'relationships' | 'impact' | 'fixes'>('relationships');
  const [repoUrl, setRepoUrl] = useState('https://github.com/yashaskn8/RepoLens');
  const router = useRouter();

  const handleAnalyze = (e: React.FormEvent) => {
    e.preventDefault();
    if (!repoUrl.trim()) return;
    router.push(`/scan?repo=${encodeURIComponent(repoUrl.trim())}&branch=main`);
  };

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column', backgroundColor: 'var(--bg-base)' }}>
      {/* Navigation Header */}
      <LandingNav onOpenAuthModal={() => setIsAuthModalOpen(true)} />

      {/* Auth Modal */}
      <AuthModal isOpen={isAuthModalOpen} onClose={() => setIsAuthModalOpen(false)} />

      <main style={{ flex: 1 }}>
        {/* ========================================================================= */}
        {/* 1. SIMPLIFIED HERO SECTION                                                */}
        {/* ========================================================================= */}
        <section
          style={{
            position: 'relative',
            padding: '5rem 1.5rem 3.5rem 1.5rem',
            maxWidth: '56rem',
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
              top: '5%',
              left: '50%',
              transform: 'translateX(-50%)',
              width: '38rem',
              height: '18rem',
              background: 'radial-gradient(ellipse at center, rgba(99, 102, 241, 0.12) 0%, rgba(56, 189, 248, 0.03) 50%, transparent 80%)',
              filter: 'blur(50px)',
              pointerEvents: 'none',
              zIndex: 0,
            }}
          />

          {/* Clean Eyebrow Tag */}
          <div style={{ position: 'relative', zIndex: 1, marginBottom: '1.25rem' }}>
            <div
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '0.5rem',
                padding: '0.35rem 0.9rem',
                borderRadius: 'var(--radius-full)',
                background: 'rgba(255, 255, 255, 0.04)',
                border: '1px solid var(--border-glass)',
              }}
            >
              <span style={{ display: 'inline-block', width: '0.45rem', height: '0.45rem', borderRadius: '50%', background: 'var(--accent-cyan)' }} />
              <span style={{ fontSize: '0.8125rem', fontWeight: 600, color: 'var(--text-light)' }}>
                RepoLens
              </span>
              <span style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>•</span>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>Read-Only Repository Intelligence</span>
            </div>
          </div>

          {/* Main Headline */}
          <h1
            style={{
              position: 'relative',
              zIndex: 1,
              fontSize: 'clamp(2.4rem, 4.8vw, 3.8rem)',
              fontWeight: 800,
              fontFamily: 'var(--font-display)',
              letterSpacing: '-0.03em',
              lineHeight: 1.15,
              color: '#ffffff',
              maxWidth: '48rem',
            }}
          >
            Understand any GitHub repository.
          </h1>

          {/* Supporting Subtitle */}
          <p
            style={{
              position: 'relative',
              zIndex: 1,
              fontSize: '1.125rem',
              color: 'var(--text-secondary)',
              lineHeight: 1.6,
              maxWidth: '42rem',
              marginTop: '1.25rem',
            }}
          >
            Scan code, find important risks, understand dependencies, and review changes without running untrusted repository code.
          </p>

          {/* Prominent URL Search & Action */}
          <div
            style={{
              position: 'relative',
              zIndex: 1,
              width: '100%',
              maxWidth: '38rem',
              marginTop: '2.25rem',
            }}
          >
            <form
              onSubmit={handleAnalyze}
              style={{
                display: 'flex',
                alignItems: 'center',
                padding: '0.4rem 0.5rem',
                borderRadius: 'var(--radius-lg)',
                background: 'rgba(9, 13, 26, 0.9)',
                border: '1px solid var(--border-glass-hover)',
                boxShadow: '0 8px 30px rgba(0, 0, 0, 0.45), var(--shadow-inner-glow)',
                gap: '0.5rem',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', paddingLeft: '0.85rem', color: 'var(--text-muted)' }}>
                <Search size={18} />
              </div>
              <input
                type="url"
                required
                value={repoUrl}
                onChange={(e) => setRepoUrl(e.target.value)}
                placeholder="https://github.com/owner/repository"
                style={{
                  flex: 1,
                  background: 'transparent',
                  border: 'none',
                  outline: 'none',
                  color: 'var(--text-primary)',
                  fontSize: '0.9375rem',
                  fontFamily: 'var(--font-mono)',
                  padding: '0.5rem 0.25rem',
                }}
              />
              <Button type="submit" variant="glow" size="md" rightIcon={<ArrowRight size={16} />}>
                Analyze Repository
              </Button>
            </form>

            {/* Presets & Secondary Action */}
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                flexWrap: 'wrap',
                gap: '0.75rem',
                marginTop: '1rem',
                padding: '0 0.5rem',
                fontSize: '0.8125rem',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', color: 'var(--text-muted)' }}>
                <span>Try an example:</span>
                {PRESET_REPOS.map((preset) => (
                  <button
                    key={preset.label}
                    type="button"
                    onClick={() => setRepoUrl(preset.url)}
                    style={{
                      background: 'rgba(255, 255, 255, 0.05)',
                      border: '1px solid var(--border-subtle)',
                      borderRadius: 'var(--radius-sm)',
                      color: 'var(--text-light)',
                      padding: '0.2rem 0.5rem',
                      fontSize: '0.75rem',
                      cursor: 'pointer',
                      transition: 'all var(--transition-fast)',
                    }}
                  >
                    {preset.label}
                  </button>
                ))}
              </div>

              <Link
                href="/change-analysis"
                style={{
                  color: 'var(--accent-cyan)',
                  textDecoration: 'none',
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '0.35rem',
                  fontWeight: 500,
                }}
              >
                <span>Analyze Pull Request</span>
                <ArrowRight size={14} />
              </Link>
            </div>
          </div>
        </section>

        {/* ========================================================================= */}
        {/* 2. SIMPLIFIED PRODUCT PREVIEW                                             */}
        {/* ========================================================================= */}
        <section
          style={{
            maxWidth: '72rem',
            margin: '0 auto',
            padding: '1rem 1.5rem 4rem 1.5rem',
          }}
        >
          <div
            className="glass-panel"
            style={{
              borderRadius: 'var(--radius-xl)',
              border: '1px solid var(--border-glass-hover)',
              overflow: 'hidden',
              boxShadow: 'var(--shadow-xl), 0 0 40px rgba(99, 102, 241, 0.08)',
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
                  repolens://results/yashaskn8/RepoLens
                </span>
              </div>

              {/* Clean Preview Tabs */}
              <div style={{ display: 'flex', gap: '0.35rem' }}>
                <button
                  type="button"
                  onClick={() => setActivePreviewTab('relationships')}
                  style={{
                    padding: '0.35rem 0.85rem',
                    fontSize: '0.75rem',
                    fontWeight: 600,
                    borderRadius: 'var(--radius-sm)',
                    border: 'none',
                    background: activePreviewTab === 'relationships' ? 'var(--accent-primary)' : 'rgba(255, 255, 255, 0.05)',
                    color: activePreviewTab === 'relationships' ? '#ffffff' : 'var(--text-secondary)',
                    cursor: 'pointer',
                    transition: 'all var(--transition-fast)',
                  }}
                >
                  Code Relationships
                </button>
                <button
                  type="button"
                  onClick={() => setActivePreviewTab('impact')}
                  style={{
                    padding: '0.35rem 0.85rem',
                    fontSize: '0.75rem',
                    fontWeight: 600,
                    borderRadius: 'var(--radius-sm)',
                    border: 'none',
                    background: activePreviewTab === 'impact' ? 'var(--accent-primary)' : 'rgba(255, 255, 255, 0.05)',
                    color: activePreviewTab === 'impact' ? '#ffffff' : 'var(--text-secondary)',
                    cursor: 'pointer',
                    transition: 'all var(--transition-fast)',
                  }}
                >
                  PR Impact
                </button>
                <button
                  type="button"
                  onClick={() => setActivePreviewTab('fixes')}
                  style={{
                    padding: '0.35rem 0.85rem',
                    fontSize: '0.75rem',
                    fontWeight: 600,
                    borderRadius: 'var(--radius-sm)',
                    border: 'none',
                    background: activePreviewTab === 'fixes' ? 'var(--accent-primary)' : 'rgba(255, 255, 255, 0.05)',
                    color: activePreviewTab === 'fixes' ? '#ffffff' : 'var(--text-secondary)',
                    cursor: 'pointer',
                    transition: 'all var(--transition-fast)',
                  }}
                >
                  Suggested Fixes
                </button>
              </div>
            </div>

            {/* Window Content */}
            <div style={{ padding: '1.5rem' }}>
              {activePreviewTab === 'relationships' && (
                <div>
                  <div style={{ marginBottom: '1rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)' }}>
                      Interactive dependency map connecting frontend API calls to backend route handlers
                    </span>
                    <Badge variant="cyan" size="sm">Deterministic Map</Badge>
                  </div>
                  <ArchitectureGraph />
                </div>
              )}

              {activePreviewTab === 'impact' && (
                <div
                  style={{
                    display: 'grid',
                    gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
                    gap: '1rem',
                    minHeight: '20rem',
                  }}
                >
                  {/* Left: Changed Code */}
                  <div
                    style={{
                      padding: '1.25rem',
                      borderRadius: 'var(--radius-md)',
                      background: 'rgba(4, 7, 17, 0.8)',
                      border: '1px solid var(--border-subtle)',
                      display: 'flex',
                      flexDirection: 'column',
                      gap: '0.75rem',
                    }}
                  >
                    <span style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                      Changed Code in PR #42
                    </span>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', fontFamily: 'var(--font-mono)', fontSize: '0.8125rem' }}>
                      <div style={{ padding: '0.5rem 0.75rem', borderRadius: 'var(--radius-sm)', background: 'rgba(239, 68, 68, 0.1)', border: '1px solid rgba(239, 68, 68, 0.25)', color: '#f87171' }}>
                        modified: update_user_role()
                      </div>
                      <div style={{ padding: '0.5rem 0.75rem', borderRadius: 'var(--radius-sm)', background: 'rgba(249, 115, 22, 0.1)', border: '1px solid rgba(249, 115, 22, 0.25)', color: '#fb923c' }}>
                        modified: UserUpdatePayload
                      </div>
                      <div style={{ padding: '0.5rem 0.75rem', borderRadius: 'var(--radius-sm)', background: 'rgba(56, 189, 248, 0.1)', border: '1px solid rgba(56, 189, 248, 0.25)', color: '#38bdf8' }}>
                        route: POST /api/v1/users
                      </div>
                    </div>
                  </div>

                  {/* Right: Impacted Areas */}
                  <div
                    style={{
                      padding: '1.25rem',
                      borderRadius: 'var(--radius-md)',
                      background: 'rgba(4, 7, 17, 0.8)',
                      border: '1px solid var(--border-subtle)',
                      display: 'flex',
                      flexDirection: 'column',
                      gap: '0.75rem',
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <span style={{ fontSize: '0.875rem', fontWeight: 700, color: '#ffffff' }}>
                        Affected Callers (2 locations)
                      </span>
                      <Badge variant="high" size="sm">Action Recommended</Badge>
                    </div>

                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', fontFamily: 'var(--font-mono)', fontSize: '0.8125rem' }}>
                      <div style={{ padding: '0.75rem', borderRadius: 'var(--radius-sm)', background: 'rgba(255, 255, 255, 0.03)', border: '1px solid var(--border-subtle)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <span style={{ color: 'var(--text-light)' }}>frontend/src/features/admin/UserManagement.tsx</span>
                        <Badge variant="error" size="sm">Breaking Change</Badge>
                      </div>
                      <div style={{ padding: '0.75rem', borderRadius: 'var(--radius-sm)', background: 'rgba(255, 255, 255, 0.03)', border: '1px solid var(--border-subtle)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <span style={{ color: 'var(--text-light)' }}>backend/app/api/v1/endpoints/admin.py</span>
                        <Badge variant="warning" size="sm">Parameter Update</Badge>
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {activePreviewTab === 'fixes' && (
                <div
                  style={{
                    display: 'grid',
                    gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))',
                    gap: '1rem',
                    minHeight: '20rem',
                  }}
                >
                  {/* Diff Box */}
                  <div
                    style={{
                      borderRadius: 'var(--radius-md)',
                      background: '#030611',
                      border: '1px solid var(--border-glass)',
                      overflow: 'hidden',
                    }}
                  >
                    <div style={{ padding: '0.65rem 1rem', borderBottom: '1px solid var(--border-subtle)', fontSize: '0.75rem', fontFamily: 'var(--font-mono)', color: 'var(--accent-cyan)' }}>
                      Suggested Fix: Add permission check before updating role
                    </div>
                    <pre style={{ padding: '1rem', margin: 0, fontFamily: 'var(--font-mono)', fontSize: '0.8125rem', color: 'var(--text-code)', lineHeight: 1.6 }}>
                      <code>{`@@ -84,6 +84,9 @@ async def update_user(user_id: str, payload: UserUpdate):
+    if payload.role is not None and payload.role != user.role:
+        if not current_user.is_operator:
+            raise HTTPException(status_code=403, detail="Operator role required")
     user.role = payload.role
     await db.commit()`}</code>
                    </pre>
                  </div>

                  {/* Verification Checks */}
                  <div
                    style={{
                      padding: '1.25rem',
                      borderRadius: 'var(--radius-md)',
                      background: 'rgba(4, 7, 17, 0.8)',
                      border: '1px solid var(--border-subtle)',
                      display: 'flex',
                      flexDirection: 'column',
                      gap: '0.65rem',
                    }}
                  >
                    <span style={{ fontSize: '0.8125rem', fontWeight: 700, color: '#ffffff' }}>
                      Patch Verification (5 Checks Passed)
                    </span>
                    {[
                      'Syntax tree remains valid',
                      'Changes confined to target scope',
                      'No unchecked external imports',
                      'No hardcoded credentials introduced',
                      'Deterministic line citations preserved',
                    ].map((checkName) => (
                      <div
                        key={checkName}
                        style={{
                          padding: '0.5rem 0.75rem',
                          borderRadius: 'var(--radius-sm)',
                          background: 'rgba(16, 185, 129, 0.08)',
                          border: '1px solid rgba(16, 185, 129, 0.2)',
                          display: 'flex',
                          justifyContent: 'space-between',
                          alignItems: 'center',
                          fontSize: '0.75rem',
                        }}
                      >
                        <span style={{ color: 'var(--text-light)' }}>{checkName}</span>
                        <CheckCircle2 size={14} style={{ color: 'var(--success-text)' }} />
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        </section>

        {/* ========================================================================= */}
        {/* 3. SIMPLIFIED CAPABILITIES                                                */}
        {/* ========================================================================= */}
        <section
          style={{
            maxWidth: '72rem',
            margin: '0 auto',
            padding: '2rem 1.5rem 4rem 1.5rem',
          }}
        >
          <div style={{ textAlign: 'center', marginBottom: '2.5rem' }}>
            <h2
              style={{
                fontSize: '1.75rem',
                fontWeight: 800,
                fontFamily: 'var(--font-display)',
                color: '#ffffff',
                letterSpacing: '-0.02em',
              }}
            >
              How RepoLens Helps You Understand Code
            </h2>
          </div>

          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))',
              gap: '1.25rem',
            }}
          >
            {/* Capability 1 */}
            <div
              className="glass-panel"
              style={{
                padding: '1.5rem',
                display: 'flex',
                flexDirection: 'column',
                gap: '0.75rem',
              }}
            >
              <div
                style={{
                  width: '2.25rem',
                  height: '2.25rem',
                  borderRadius: 'var(--radius-md)',
                  background: 'rgba(56, 189, 248, 0.12)',
                  border: '1px solid rgba(56, 189, 248, 0.25)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  color: 'var(--accent-cyan)',
                }}
              >
                <Code2 size={18} />
              </div>
              <h3 style={{ fontSize: '1.05rem', fontWeight: 700, color: '#ffffff' }}>
                Code Relationships
              </h3>
              <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', lineHeight: 1.55 }}>
                See how client fetch calls connect directly to backend routes and schemas across your repository.
              </p>
            </div>

            {/* Capability 2 */}
            <div
              className="glass-panel"
              style={{
                padding: '1.5rem',
                display: 'flex',
                flexDirection: 'column',
                gap: '0.75rem',
              }}
            >
              <div
                style={{
                  width: '2.25rem',
                  height: '2.25rem',
                  borderRadius: 'var(--radius-md)',
                  background: 'rgba(99, 102, 241, 0.12)',
                  border: '1px solid rgba(99, 102, 241, 0.25)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  color: 'var(--accent-primary)',
                }}
              >
                <GitPullRequest size={18} />
              </div>
              <h3 style={{ fontSize: '1.05rem', fontWeight: 700, color: '#ffffff' }}>
                PR Impact Analysis
              </h3>
              <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', lineHeight: 1.55 }}>
                Know exactly which files, functions, and endpoints are affected by a pull request before merging.
              </p>
            </div>

            {/* Capability 3 */}
            <div
              className="glass-panel"
              style={{
                padding: '1.5rem',
                display: 'flex',
                flexDirection: 'column',
                gap: '0.75rem',
              }}
            >
              <div
                style={{
                  width: '2.25rem',
                  height: '2.25rem',
                  borderRadius: 'var(--radius-md)',
                  background: 'rgba(16, 185, 129, 0.12)',
                  border: '1px solid rgba(16, 185, 129, 0.25)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  color: 'var(--success-text)',
                }}
              >
                <ShieldCheck size={18} />
              </div>
              <h3 style={{ fontSize: '1.05rem', fontWeight: 700, color: '#ffffff' }}>
                Suggested Fixes
              </h3>
              <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', lineHeight: 1.55 }}>
                Review verified code patches with line citations and syntax checks ready for human approval.
              </p>
            </div>

            {/* Capability 4 */}
            <div
              className="glass-panel"
              style={{
                padding: '1.5rem',
                display: 'flex',
                flexDirection: 'column',
                gap: '0.75rem',
              }}
            >
              <div
                style={{
                  width: '2.25rem',
                  height: '2.25rem',
                  borderRadius: 'var(--radius-md)',
                  background: 'rgba(168, 85, 247, 0.12)',
                  border: '1px solid rgba(168, 85, 247, 0.25)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  color: 'var(--accent-purple)',
                }}
              >
                <Lock size={18} />
              </div>
              <h3 style={{ fontSize: '1.05rem', fontWeight: 700, color: '#ffffff' }}>
                Safe &amp; Passive
              </h3>
              <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', lineHeight: 1.55 }}>
                Zero untrusted execution. RepoLens never runs test scripts, binaries, or container commands.
              </p>
            </div>
          </div>
        </section>

        {/* ========================================================================= */}
        {/* 4. CLEAR SAFETY GUARANTEES                                                */}
        {/* ========================================================================= */}
        <section
          style={{
            maxWidth: '72rem',
            margin: '0 auto',
            padding: '1rem 1.5rem 5rem 1.5rem',
          }}
        >
          <div
            className="glass-panel"
            style={{
              padding: '2rem 2.5rem',
              borderRadius: 'var(--radius-xl)',
              background: 'linear-gradient(135deg, rgba(99, 102, 241, 0.06) 0%, rgba(5, 8, 18, 0.85) 100%)',
              border: '1px solid var(--border-glass)',
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))',
              gap: '2rem',
            }}
          >
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.5rem' }}>
                <Shield size={16} style={{ color: 'var(--accent-cyan)' }} />
                <h4 style={{ fontSize: '1rem', fontWeight: 700, color: '#ffffff' }}>
                  Zero Untrusted Execution
                </h4>
              </div>
              <p style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', lineHeight: 1.55 }}>
                RepoLens parses repository code passively. It never runs arbitrary scripts, tests, or makefiles.
              </p>
            </div>

            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.5rem' }}>
                <Lock size={16} style={{ color: 'var(--accent-primary)' }} />
                <h4 style={{ fontSize: '1rem', fontWeight: 700, color: '#ffffff' }}>
                  Tenant Isolation
                </h4>
              </div>
              <p style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', lineHeight: 1.55 }}>
                All findings and scan history are scoped strictly to the authenticated user.
              </p>
            </div>

            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.5rem' }}>
                <CheckCircle2 size={16} style={{ color: 'var(--success-text)' }} />
                <h4 style={{ fontSize: '1rem', fontWeight: 700, color: '#ffffff' }}>
                  Human In The Loop
                </h4>
              </div>
              <p style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', lineHeight: 1.55 }}>
                Suggested fixes are never committed or merged automatically; every action requires explicit operator approval.
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
