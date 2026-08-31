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
      {/* Navigation */}
      <LandingNav onOpenAuthModal={() => setIsAuthModalOpen(true)} />

      {/* Auth Modal */}
      <AuthModal isOpen={isAuthModalOpen} onClose={() => setIsAuthModalOpen(false)} />

      <main style={{ flex: 1 }}>
        {/* ========================================================================= */}
        {/* HERO SECTION                                                             */}
        {/* ========================================================================= */}
        <section
          style={{
            position: 'relative',
            padding: '5rem 1.5rem 4rem 1.5rem',
            maxWidth: '75rem',
            margin: '0 auto',
            textAlign: 'center',
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
          }}
        >
          {/* Subtle Ambient Top Glow */}
          <div
            style={{
              position: 'absolute',
              top: '10%',
              left: '50%',
              transform: 'translateX(-50%)',
              width: '40rem',
              height: '20rem',
              background: 'radial-gradient(circle, rgba(99, 102, 241, 0.18) 0%, rgba(56, 189, 248, 0.08) 50%, transparent 80%)',
              filter: 'blur(60px)',
              pointerEvents: 'none',
              zIndex: 0,
            }}
          />

          {/* Badge */}
          <div style={{ position: 'relative', zIndex: 1, marginBottom: '1.25rem' }}>
            <Badge variant="cyan" size="md" icon={<Sparkles size={13} />}>
              Evidence-First Repository Intelligence
            </Badge>
          </div>

          {/* Hero Headline */}
          <h1
            style={{
              position: 'relative',
              zIndex: 1,
              fontSize: 'clamp(2.4rem, 5vw, 4.25rem)',
              fontWeight: 900,
              fontFamily: 'var(--font-display)',
              letterSpacing: '-0.035em',
              lineHeight: 1.12,
              color: '#ffffff',
              maxWidth: '56rem',
              marginBottom: '1.5rem',
            }}
          >
            Deterministic Code Graphs.{' '}
            <span className="gradient-text">Zero-Hallucination</span> Findings.
          </h1>

          {/* Subtitle */}
          <p
            style={{
              position: 'relative',
              zIndex: 1,
              fontSize: 'clamp(1rem, 2vw, 1.25rem)',
              color: 'var(--text-secondary)',
              maxWidth: '44rem',
              lineHeight: 1.6,
              marginBottom: '2.5rem',
            }}
          >
            RepoLens traces full cross-layer contracts from frontend components to database schemas,
            validating AI reasoning with deterministic AST evidence before proposing human-authorized fixes.
          </p>

          {/* Live Repository Quick Scanner Box */}
          <div
            className="glass-panel"
            style={{
              position: 'relative',
              zIndex: 2,
              width: '100%',
              maxWidth: '48rem',
              padding: '1.5rem',
              background: 'rgba(10, 15, 30, 0.85)',
              border: '1px solid var(--border-glass-hover)',
              boxShadow: '0 20px 50px rgba(0, 0, 0, 0.6), 0 0 30px rgba(99, 102, 241, 0.15)',
              marginBottom: '1.5rem',
            }}
          >
            <form onSubmit={handleStartScan} style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}>
                <div style={{ flex: '1 1 20rem', position: 'relative', display: 'flex', alignItems: 'center' }}>
                  <Terminal size={16} style={{ position: 'absolute', left: '0.9rem', color: 'var(--text-muted)' }} />
                  <input
                    type="text"
                    required
                    value={repoInput}
                    onChange={(e) => setRepoInput(e.target.value)}
                    placeholder="https://github.com/owner/repository"
                    style={{
                      width: '100%',
                      height: '3rem',
                      paddingLeft: '2.6rem',
                      paddingRight: '1rem',
                      borderRadius: 'var(--radius-md)',
                      backgroundColor: 'rgba(5, 8, 18, 0.9)',
                      border: '1px solid var(--border-glass)',
                      color: '#ffffff',
                      fontSize: '0.9375rem',
                      fontFamily: 'var(--font-mono)',
                      outline: 'none',
                    }}
                  />
                </div>

                <div style={{ flex: '0 0 8.5rem', position: 'relative', display: 'flex', alignItems: 'center' }}>
                  <GitBranch size={15} style={{ position: 'absolute', left: '0.9rem', color: 'var(--text-muted)' }} />
                  <input
                    type="text"
                    value={branchInput}
                    onChange={(e) => setBranchInput(e.target.value)}
                    placeholder="main"
                    style={{
                      width: '100%',
                      height: '3rem',
                      paddingLeft: '2.4rem',
                      paddingRight: '0.75rem',
                      borderRadius: 'var(--radius-md)',
                      backgroundColor: 'rgba(5, 8, 18, 0.9)',
                      border: '1px solid var(--border-glass)',
                      color: '#ffffff',
                      fontSize: '0.875rem',
                      fontFamily: 'var(--font-mono)',
                      outline: 'none',
                    }}
                  />
                </div>

                <Button
                  type="submit"
                  variant="glow"
                  size="lg"
                  rightIcon={<ArrowRight size={16} />}
                  style={{ height: '3rem', padding: '0 1.75rem' }}
                >
                  Inspect Repo
                </Button>
              </div>

              {/* Preset Selector */}
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Quick Presets:</span>
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
            </form>
          </div>

          {/* Trust Guarantees */}
          <div
            style={{
              position: 'relative',
              zIndex: 1,
              display: 'flex',
              alignItems: 'center',
              gap: '1.75rem',
              flexWrap: 'wrap',
              justifyContent: 'center',
              fontSize: '0.8125rem',
              color: 'var(--text-muted)',
            }}
          >
            <span style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
              <ShieldCheck size={15} style={{ color: 'var(--success-text)' }} /> Read-Only Sandbox Execution
            </span>
            <span style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
              <Lock size={15} style={{ color: 'var(--accent-cyan)' }} /> Strict Human Authorization Gates
            </span>
            <span style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
              <Zap size={15} style={{ color: 'var(--accent-purple)' }} /> Zero Unverified Hallucinations
            </span>
          </div>
        </section>

        {/* ========================================================================= */}
        {/* INTERACTIVE ARCHITECTURE GRAPH SECTION                                   */}
        {/* ========================================================================= */}
        <section
          id="architecture"
          style={{
            padding: '3rem 1.5rem 5rem 1.5rem',
            maxWidth: '75rem',
            margin: '0 auto',
          }}
        >
          <div style={{ textAlign: 'center', marginBottom: '2.5rem' }}>
            <Badge variant="purple" size="sm" style={{ marginBottom: '0.75rem' }}>
              Deep Cross-Layer Tracing
            </Badge>
            <h2
              style={{
                fontSize: 'clamp(1.75rem, 3.5vw, 2.5rem)',
                fontWeight: 800,
                fontFamily: 'var(--font-display)',
                letterSpacing: '-0.025em',
                color: '#ffffff',
                marginBottom: '0.75rem',
              }}
            >
              See Every Connection from Client to Database
            </h2>
            <p style={{ fontSize: '1rem', color: 'var(--text-secondary)', maxWidth: '38rem', margin: '0 auto' }}>
              RepoLens constructs a live AST graph mapping UI components, network calls, server routes,
              Pydantic schemas, and SQLAlchemy models.
            </p>
          </div>

          {/* Interactive Graph Component */}
          <ArchitectureGraph />
        </section>

        {/* ========================================================================= */}
        {/* EVIDENCE-FIRST WORKFLOW PIPELINE                                          */}
        {/* ========================================================================= */}
        <section
          id="pipeline"
          style={{
            padding: '4rem 1.5rem 5rem 1.5rem',
            maxWidth: '75rem',
            margin: '0 auto',
            borderTop: '1px solid var(--border-subtle)',
          }}
        >
          <div style={{ textAlign: 'center', marginBottom: '3.5rem' }}>
            <Badge variant="cyan" size="sm" style={{ marginBottom: '0.75rem' }}>
              Deterministic Execution Flow
            </Badge>
            <h2
              style={{
                fontSize: 'clamp(1.75rem, 3.5vw, 2.5rem)',
                fontWeight: 800,
                fontFamily: 'var(--font-display)',
                letterSpacing: '-0.025em',
                color: '#ffffff',
                marginBottom: '0.75rem',
              }}
            >
              The 7-Step Evidence-First Pipeline
            </h2>
            <p style={{ fontSize: '1rem', color: 'var(--text-secondary)', maxWidth: '38rem', margin: '0 auto' }}>
              How RepoLens turns complex codebases into verifiable, actionable engineering intelligence.
            </p>
          </div>

          {/* 7-Step Visual Pipeline Cards */}
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))',
              gap: '1rem',
            }}
          >
            {[
              {
                step: '01',
                title: 'Clone & AST Parse',
                desc: 'Sandboxed Git clone followed by parser extraction of symbols, routes, and frameworks.',
                tag: 'Deterministic',
              },
              {
                step: '02',
                title: 'Static Tool Scan',
                desc: 'Semgrep, Bandit, and custom AST rules execute concurrently with timeout guarantees.',
                tag: 'Multi-Tool',
              },
              {
                step: '03',
                title: 'Evidence Graph',
                desc: 'Constructs cross-layer relationships and traces contract dependencies across stack layers.',
                tag: 'Graph AST',
              },
              {
                step: '04',
                title: 'Agentic Verification',
                desc: 'LLM reasons ONLY over extracted AST evidence. Rejects unproven or hallucinated findings.',
                tag: 'Zero-Hallucination',
              },
              {
                step: '05',
                title: 'Targeted Fix Plan',
                desc: 'Produces isolated, syntactically valid patches scoped strictly to the affected line range.',
                tag: 'Patch Proposal',
              },
              {
                step: '06',
                title: 'Human Review Gate',
                desc: 'Operators inspect proposed diffs and can approve, reject, or request iterative revision.',
                tag: 'HITL Gate',
              },
              {
                step: '07',
                title: 'Safe Git Delivery',
                desc: 'Optionally opens PR on GitHub with cryptographic digest confirmation. Never writes silently.',
                tag: 'Operator Only',
              },
            ].map((item) => (
              <Card
                key={item.step}
                variant="interactive"
                style={{
                  padding: '1.25rem',
                  display: 'flex',
                  flexDirection: 'column',
                  justifyContent: 'space-between',
                  gap: '0.75rem',
                }}
              >
                <div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem' }}>
                    <span
                      style={{
                        fontSize: '1.25rem',
                        fontWeight: 800,
                        fontFamily: 'var(--font-mono)',
                        color: 'var(--accent-cyan)',
                      }}
                    >
                      {item.step}
                    </span>
                    <Badge variant="default" size="sm">
                      {item.tag}
                    </Badge>
                  </div>
                  <h4 style={{ fontSize: '1rem', fontWeight: 700, color: 'var(--text-primary)', marginBottom: '0.35rem' }}>
                    {item.title}
                  </h4>
                  <p style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
                    {item.desc}
                  </p>
                </div>
              </Card>
            ))}
          </div>
        </section>

        {/* ========================================================================= */}
        {/* CORE DIFFERENTIATION BENTO GRID                                          */}
        {/* ========================================================================= */}
        <section
          id="safety"
          style={{
            padding: '4rem 1.5rem 5rem 1.5rem',
            maxWidth: '75rem',
            margin: '0 auto',
            borderTop: '1px solid var(--border-subtle)',
          }}
        >
          <div style={{ textAlign: 'center', marginBottom: '3.5rem' }}>
            <Badge variant="purple" size="sm" style={{ marginBottom: '0.75rem' }}>
              Architectural Defense
            </Badge>
            <h2
              style={{
                fontSize: 'clamp(1.75rem, 3.5vw, 2.5rem)',
                fontWeight: 800,
                fontFamily: 'var(--font-display)',
                letterSpacing: '-0.025em',
                color: '#ffffff',
                marginBottom: '0.75rem',
              }}
            >
              Built for Serious Engineering Teams
            </h2>
          </div>

          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))',
              gap: '1.5rem',
            }}
          >
            {/* Bento Card 1 */}
            <Card variant="bento" glow="indigo" style={{ padding: '2rem' }}>
              <div
                style={{
                  width: '2.5rem',
                  height: '2.5rem',
                  borderRadius: 'var(--radius-md)',
                  background: 'rgba(99, 102, 241, 0.15)',
                  border: '1px solid var(--border-glass-hover)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  color: 'var(--accent-primary)',
                  marginBottom: '1.25rem',
                }}
              >
                <Layers size={20} />
              </div>
              <h3 style={{ fontSize: '1.25rem', fontWeight: 700, color: '#ffffff', marginBottom: '0.5rem' }}>
                Full-Stack Contract Intelligence
              </h3>
              <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
                Detect breaking API changes before they reach staging. When a backend model or route parameter
                changes, RepoLens traces all affected frontend fetch calls and UI components automatically.
              </p>
            </Card>

            {/* Bento Card 2 */}
            <Card variant="bento" glow="cyan" style={{ padding: '2rem' }}>
              <div
                style={{
                  width: '2.5rem',
                  height: '2.5rem',
                  borderRadius: 'var(--radius-md)',
                  background: 'rgba(56, 189, 248, 0.15)',
                  border: '1px solid var(--border-glass-hover)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  color: 'var(--accent-cyan)',
                  marginBottom: '1.25rem',
                }}
              >
                <Lock size={20} />
              </div>
              <h3 style={{ fontSize: '1.25rem', fontWeight: 700, color: '#ffffff', marginBottom: '0.5rem' }}>
                Role-Based Safety & Permissions
              </h3>
              <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
                Clear distinction between <strong style={{ color: '#ffffff' }}>USER</strong> (read & research) and{' '}
                <strong style={{ color: '#ffffff' }}>OPERATOR</strong> (patch approval and PR publication) roles.
                GitHub write access is never assumed and strictly requires cryptographic digest matching.
              </p>
            </Card>

            {/* Bento Card 3 */}
            <Card variant="bento" glow="purple" style={{ padding: '2rem' }}>
              <div
                style={{
                  width: '2.5rem',
                  height: '2.5rem',
                  borderRadius: 'var(--radius-md)',
                  background: 'rgba(168, 85, 247, 0.15)',
                  border: '1px solid var(--border-glass-hover)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  color: 'var(--accent-purple)',
                  marginBottom: '1.25rem',
                }}
              >
                <GitPullRequest size={20} />
              </div>
              <h3 style={{ fontSize: '1.25rem', fontWeight: 700, color: '#ffffff', marginBottom: '0.5rem' }}>
                PR Blast Radius & Impact Analysis
              </h3>
              <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
                Analyze pull requests in real time. RepoLens computes transitive impact graphs, config deltas,
                and route mutations, delivering high-confidence review findings directly to reviewers.
              </p>
            </Card>
          </div>
        </section>

        {/* ========================================================================= */}
        {/* FINAL CTA SECTION                                                        */}
        {/* ========================================================================= */}
        <section
          style={{
            padding: '5rem 1.5rem 6rem 1.5rem',
            maxWidth: '65rem',
            margin: '0 auto',
            textAlign: 'center',
          }}
        >
          <div
            className="glass-panel"
            style={{
              padding: '4rem 2rem',
              background: 'radial-gradient(circle at 50% 0%, rgba(99, 102, 241, 0.22) 0%, rgba(8, 12, 24, 0.95) 75%)',
              border: '1px solid var(--border-glass-hover)',
              boxShadow: '0 25px 60px rgba(0, 0, 0, 0.7), 0 0 35px rgba(99, 102, 241, 0.25)',
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
            }}
          >
            <h2
              style={{
                fontSize: 'clamp(2rem, 4vw, 3rem)',
                fontWeight: 900,
                fontFamily: 'var(--font-display)',
                letterSpacing: '-0.03em',
                color: '#ffffff',
                marginBottom: '1rem',
              }}
            >
              Start Inspecting Your Repository Now
            </h2>
            <p
              style={{
                fontSize: '1.0625rem',
                color: 'var(--text-secondary)',
                maxWidth: '36rem',
                lineHeight: 1.6,
                marginBottom: '2rem',
              }}
            >
              Scan local or remote repositories with full AST evidence graphs, zero setup, and zero data leakage.
            </p>

            <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap', justifyContent: 'center' }}>
              <Link href="/scan">
                <Button variant="glow" size="lg" rightIcon={<ArrowRight size={16} />}>
                  Launch Repository Scan
                </Button>
              </Link>
              <Link href="/change-analysis">
                <Button variant="secondary" size="lg" leftIcon={<GitPullRequest size={16} />}>
                  Analyze Pull Request
                </Button>
              </Link>
            </div>
          </div>
        </section>
      </main>

      {/* Footer */}
      <LandingFooter health={health} />
    </div>
  );
}
