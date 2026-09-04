'use client';

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { AppShell } from '@/components/layout/AppShell';
import { StatCard, Card } from '@/components/ui/Card';
import { Button } from '@/components/ui/Button';
import { Badge } from '@/components/ui/Badge';
import { Skeleton } from '@/components/ui/Skeleton';
import { EmptyState } from '@/components/ui/EmptyState';
import { useAuth } from '@/context/AuthContext';
import { listChangeAnalyses, fetchHealth, listScans } from '@/lib/api';
import { ChangeAnalysisSummary, HealthResponse, Scan } from '@/types/domain';
import {
  Scan as ScanIcon,
  GitPullRequest,
  ShieldAlert,
  Wrench,
  ArrowRight,
  Sparkles,
  Server,
  Layers,
  Clock,
  ExternalLink,
  ChevronRight,
  CheckCircle2,
  AlertTriangle,
  FileCode,
  Lock,
  Activity,
  Cpu,
  ShieldCheck,
} from 'lucide-react';

export default function DashboardPage() {
  const { user, isOperator } = useAuth();
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [changeAnalyses, setChangeAnalyses] = useState<ChangeAnalysisSummary[]>([]);
  const [recentScans, setRecentScans] = useState<Scan[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const router = useRouter();

  useEffect(() => {
    async function loadDashboardData() {
      try {
        const [healthRes, changesRes, scansRes] = await Promise.allSettled([
          fetchHealth(),
          listChangeAnalyses(undefined, 10, 0),
          listScans(10),
        ]);

        if (healthRes.status === 'fulfilled') setHealth(healthRes.value);
        if (changesRes.status === 'fulfilled') setChangeAnalyses(changesRes.value || []);
        if (scansRes.status === 'fulfilled') setRecentScans(scansRes.value || []);
      } finally {
        setIsLoading(false);
      }
    }

    loadDashboardData();
  }, []);

  return (
    <AppShell breadcrumbs={[{ label: 'Dashboard' }]} title="Product Overview">
      <div style={{ display: 'flex', flexDirection: 'column', gap: '1.75rem' }}>
        {/* ========================================================================= */}
        {/* HERO COCKPIT BANNER                                                       */}
        {/* ========================================================================= */}
        <div
          className="glass-panel"
          style={{
            padding: '1.75rem 2rem',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            flexWrap: 'wrap',
            gap: '1.5rem',
            background: 'linear-gradient(135deg, rgba(99, 102, 241, 0.12) 0%, rgba(56, 189, 248, 0.04) 50%, rgba(13, 19, 36, 0.85) 100%)',
            border: '1px solid var(--border-glass-hover)',
            boxShadow: '0 8px 32px rgba(0, 0, 0, 0.35), var(--shadow-inner-glow)',
          }}
        >
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem', marginBottom: '0.35rem' }}>
              <h2
                style={{
                  fontSize: '1.5rem',
                  fontWeight: 800,
                  fontFamily: 'var(--font-display)',
                  letterSpacing: '-0.02em',
                  color: '#ffffff',
                }}
              >
                Welcome{user ? `, ${user.email.split('@')[0]}` : ''}
              </h2>
              <Badge variant={isOperator ? 'operator' : 'user'} size="sm">
                {isOperator ? 'OPERATOR MODE' : 'USER MODE'}
              </Badge>
              {health?.status === 'healthy' && (
                <Badge variant="success" size="sm" icon={<Activity size={12} />}>
                  Engine Online
                </Badge>
              )}
            </div>
            <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)' }}>
              Deterministic AST dependency graphs, cross-layer contract tracing, and human-authorized remediation workspace.
            </p>
          </div>

          <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}>
            <Link href="/scan">
              <Button variant="glow" size="md" leftIcon={<ScanIcon size={16} />}>
                New Repository Scan
              </Button>
            </Link>
            <Link href="/change-analysis">
              <Button variant="secondary" size="md" leftIcon={<GitPullRequest size={16} />}>
                Analyze Pull Request
              </Button>
            </Link>
          </div>
        </div>

        {/* ========================================================================= */}
        {/* 4 ASYMMETRIC METRIC BLOCKS                                                */}
        {/* ========================================================================= */}
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
            gap: '1.25rem',
          }}
        >
          <StatCard
            label="AST Graph Engine"
            value="Active"
            subtext="FastAPI + Semgrep + Tree-sitter"
            icon={<Cpu size={18} />}
            badge={
              <Badge variant={health?.status === 'healthy' ? 'success' : 'warning'} size="sm">
                {health?.status || 'Unavailable'}
              </Badge>
            }
          />
          <StatCard
            label="PR Blast Radius Reports"
            value={changeAnalyses.length}
            subtext="Cross-layer impact analyses"
            icon={<GitPullRequest size={18} />}
            glow="cyan"
            onClick={() => router.push('/change-analysis')}
          />
          <StatCard
            label="Verified Findings"
            value={recentScans.reduce((total, scan) => total + scan.findings_count, 0)}
            subtext="Grounded findings in recent scans"
            icon={<ShieldCheck size={18} />}
            badge={<Badge variant="cyan" size="sm">Evidence required</Badge>}
            onClick={() => router.push('/findings')}
          />
          <StatCard
            label="Remediation Gates"
            value="HITL"
            subtext="Human review required for patches"
            icon={<Wrench size={18} />}
            glow="indigo"
            onClick={() => router.push('/remediation')}
          />
        </div>

        {/* ========================================================================= */}
        {/* 2-COLUMN SPLIT COCKPIT                                                    */}
        {/* ========================================================================= */}
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'minmax(0, 1.4fr) minmax(0, 1fr)',
            gap: '1.5rem',
          }}
        >
          {/* Left Column: Recent Change Analyses Workspace */}
          <div
            className="glass-panel"
            style={{
              padding: '1.5rem',
              display: 'flex',
              flexDirection: 'column',
              gap: '1.25rem',
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <GitPullRequest size={18} style={{ color: 'var(--accent-cyan)' }} />
                <h3 style={{ fontSize: '1.125rem', fontWeight: 700, fontFamily: 'var(--font-display)', color: '#ffffff' }}>
                  Pull Request & Blast Radius Intelligence
                </h3>
              </div>
              <Link href="/change-analysis" style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
                View All <ChevronRight size={14} />
              </Link>
            </div>

            {isLoading ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                <Skeleton height="4rem" />
                <Skeleton height="4rem" />
                <Skeleton height="4rem" />
              </div>
            ) : changeAnalyses.length === 0 ? (
              <EmptyState
                icon={<GitPullRequest size={24} />}
                title="No PR analyses yet"
                description="Analyze your first pull request or commit diff to discover breaking contract changes and blast radius."
                actionLabel="Analyze Pull Request"
                onAction={() => router.push('/change-analysis')}
              />
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.65rem' }}>
                {changeAnalyses.map((analysis) => (
                  <Link
                    key={analysis.id}
                    href={`/changes/${analysis.id}`}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      padding: '1rem 1.15rem',
                      borderRadius: 'var(--radius-md)',
                      backgroundColor: 'rgba(5, 8, 18, 0.7)',
                      border: '1px solid var(--border-subtle)',
                      transition: 'border-color var(--transition-fast), background-color var(--transition-fast)',
                    }}
                    className="glass-panel-interactive"
                  >
                    <div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.25rem' }}>
                        <span style={{ fontSize: '0.875rem', fontWeight: 600, color: '#ffffff' }}>
                          {analysis.repository_owner}/{analysis.repository_name}
                        </span>
                        <Badge variant="default" size="sm">
                          {analysis.status}
                        </Badge>
                      </div>
                      <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                        {analysis.base_commit_sha?.slice(0, 7)} → {analysis.head_commit_sha?.slice(0, 7)} ({analysis.changed_files_count || 0} files)
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
                      <ChevronRight size={15} style={{ color: 'var(--text-muted)' }} />
                    </div>
                  </Link>
                ))}
              </div>
            )}
          </div>

          {/* Right Column: Repository Scan & Security Cockpit */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
            {/* Quick Launcher Card */}
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
                <ScanIcon size={18} style={{ color: 'var(--accent-primary)' }} />
                <h3 style={{ fontSize: '1.125rem', fontWeight: 700, fontFamily: 'var(--font-display)', color: '#ffffff' }}>
                  Repository AST Scanner
                </h3>
              </div>

              <p style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', lineHeight: 1.55 }}>
                Tree-sitter syntactic analysis and cross-layer call graph construction across frontend and backend boundaries.
              </p>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                <Button
                  variant="secondary"
                  size="sm"
                  onClick={() => router.push('/scan?repo=https://github.com/yashaskn8/RepoLens&branch=main')}
                  style={{ justifyContent: 'flex-start' }}
                >
                  Scan RepoLens Repository (Self-Scan)
                </Button>
                <Button
                  variant="secondary"
                  size="sm"
                  onClick={() => router.push('/scan?repo=https://github.com/tiangolo/fastapi&branch=master')}
                  style={{ justifyContent: 'flex-start' }}
                >
                  Scan FastAPI Microservice
                </Button>
              </div>

              <Link href="/scan">
                <Button variant="glow" size="md" rightIcon={<ArrowRight size={14} />} style={{ width: '100%' }}>
                  Open Scan Workspace
                </Button>
              </Link>
            </div>

            {/* Quick Investigation Links */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.85rem' }}>
              <Link
                href="/findings"
                style={{
                  padding: '1.15rem',
                  borderRadius: 'var(--radius-md)',
                  background: 'rgba(255, 255, 255, 0.03)',
                  border: '1px solid var(--border-subtle)',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '0.35rem',
                }}
                className="glass-panel-interactive"
              >
                <ShieldAlert size={20} style={{ color: 'var(--high-text)' }} />
                <span style={{ fontSize: '0.875rem', fontWeight: 700, color: '#ffffff' }}>Findings Explorer</span>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Verified rules & AST evidence</span>
              </Link>

              <Link
                href="/remediation"
                style={{
                  padding: '1.15rem',
                  borderRadius: 'var(--radius-md)',
                  background: 'rgba(255, 255, 255, 0.03)',
                  border: '1px solid var(--border-subtle)',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '0.35rem',
                }}
                className="glass-panel-interactive"
              >
                <Wrench size={20} style={{ color: 'var(--accent-purple)' }} />
                <span style={{ fontSize: '0.875rem', fontWeight: 700, color: '#ffffff' }}>7-Step Remediation</span>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Human-in-the-loop patches</span>
              </Link>
            </div>
          </div>
        </div>
      </div>
    </AppShell>
  );
}
