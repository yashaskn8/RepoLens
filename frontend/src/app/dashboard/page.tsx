'use client';

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { AppShell } from '@/components/layout/AppShell';
import { StatCard, Card } from '@/components/ui/Card';
import { Button } from '@/components/ui/Button';
import { Badge } from '@/components/ui/Badge';
import { StatusIndicator } from '@/components/ui/StatusIndicator';
import { Skeleton } from '@/components/ui/Skeleton';
import { EmptyState } from '@/components/ui/EmptyState';
import { useAuth } from '@/context/AuthContext';
import { listChangeAnalyses, fetchHealth } from '@/lib/api';
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
        const [healthRes, changesRes] = await Promise.allSettled([
          fetchHealth(),
          listChangeAnalyses(undefined, 10, 0),
        ]);

        if (healthRes.status === 'fulfilled') setHealth(healthRes.value);
        if (changesRes.status === 'fulfilled') setChangeAnalyses(changesRes.value || []);

        // Load any saved scans from session / local storage if available
        if (typeof window !== 'undefined') {
          const savedScans = localStorage.getItem('repolens_recent_scans');
          if (savedScans) {
            try {
              setRecentScans(JSON.parse(savedScans));
            } catch {
              // ignore
            }
          }
        }
      } finally {
        setIsLoading(false);
      }
    }

    loadDashboardData();
  }, []);

  return (
    <AppShell breadcrumbs={[{ label: 'Dashboard' }]} title="Product Overview">
      <div style={{ display: 'flex', flexDirection: 'column', gap: '2rem' }}>
        {/* Top Welcome / System Status Banner */}
        <div
          className="glass-panel"
          style={{
            padding: '1.75rem 2rem',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            flexWrap: 'wrap',
            gap: '1.5rem',
            background: 'linear-gradient(135deg, rgba(99, 102, 241, 0.12) 0%, rgba(13, 19, 36, 0.8) 100%)',
            border: '1px solid var(--border-glass-hover)',
          }}
        >
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem', marginBottom: '0.4rem' }}>
              <h2
                style={{
                  fontSize: '1.5rem',
                  fontWeight: 800,
                  fontFamily: 'var(--font-display)',
                  color: '#ffffff',
                }}
              >
                Welcome{user ? `, ${user.email.split('@')[0]}` : ''}
              </h2>
              <Badge variant={isOperator ? 'operator' : 'user'} size="sm">
                {isOperator ? 'OPERATOR MODE' : 'USER MODE'}
              </Badge>
            </div>
            <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)' }}>
              Deterministic AST graphs, cross-layer contract tracing, and human-authorized remediation workspace.
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

        {/* 4 Stat Cards */}
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
            subtext="FastAPI + Semgrep + AST Engine"
            icon={<Server size={18} />}
            badge={
              <Badge variant={health?.status === 'healthy' ? 'success' : 'warning'} size="sm">
                {health?.status || 'Online'}
              </Badge>
            }
          />
          <StatCard
            label="Recent PR Analyses"
            value={changeAnalyses.length}
            subtext="Cross-layer impact reports"
            icon={<GitPullRequest size={18} />}
            glow="cyan"
            onClick={() => router.push('/change-analysis')}
          />
          <StatCard
            label="Verified Evidence"
            value="100%"
            subtext="Strict AST citations required"
            icon={<CheckCircle2 size={18} />}
            badge={<Badge variant="cyan" size="sm">Zero Hallucinations</Badge>}
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

        {/* 2-Column Split: Recent Change Analyses & Recent Scans */}
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(400px, 1fr))',
            gap: '1.5rem',
          }}
        >
          {/* Left Column: Recent Change Analyses */}
          <Card style={{ display: 'flex', flexDirection: 'column', gap: '1rem', padding: '1.5rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <GitPullRequest size={18} style={{ color: 'var(--accent-cyan)' }} />
                <h3 style={{ fontSize: '1.125rem', fontWeight: 700, fontFamily: 'var(--font-display)', color: '#ffffff' }}>
                  Recent Change Analyses
                </h3>
              </div>
              <Link href="/change-analysis" style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
                View All <ChevronRight size={14} />
              </Link>
            </div>

            {isLoading ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                <Skeleton height="3.5rem" />
                <Skeleton height="3.5rem" />
                <Skeleton height="3.5rem" />
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
                      padding: '0.85rem 1rem',
                      borderRadius: 'var(--radius-md)',
                      backgroundColor: 'rgba(5, 8, 18, 0.7)',
                      border: '1px solid var(--border-subtle)',
                      transition: 'border-color var(--transition-fast), background-color var(--transition-fast)',
                    }}
                    className="glass-panel-interactive"
                  >
                    <div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.2rem' }}>
                        <span style={{ fontSize: '0.875rem', fontWeight: 600, color: 'var(--text-primary)' }}>
                          {analysis.repository_owner}/{analysis.repository_name}
                        </span>
                        <Badge variant="default" size="sm">
                          {analysis.status}
                        </Badge>
                      </div>
                      <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                        {analysis.base_commit_sha?.slice(0, 7)} → {analysis.head_commit_sha?.slice(0, 7)}
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
                          {analysis.risk_level}
                        </Badge>
                      )}
                      <ChevronRight size={15} style={{ color: 'var(--text-muted)' }} />
                    </div>
                  </Link>
                ))}
              </div>
            )}
          </Card>

          {/* Right Column: Repository Scan Workspace Launcher */}
          <Card style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem', padding: '1.5rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <ScanIcon size={18} style={{ color: 'var(--accent-primary)' }} />
                <h3 style={{ fontSize: '1.125rem', fontWeight: 700, fontFamily: 'var(--font-display)', color: '#ffffff' }}>
                  Repository Intelligence Launcher
                </h3>
              </div>
              <Link href="/scan" style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
                Scan Workspace <ChevronRight size={14} />
              </Link>
            </div>

            <div
              style={{
                padding: '1.25rem',
                borderRadius: 'var(--radius-md)',
                background: 'rgba(5, 8, 18, 0.8)',
                border: '1px solid var(--border-glass)',
                display: 'flex',
                flexDirection: 'column',
                gap: '0.75rem',
              }}
            >
              <div style={{ fontSize: '0.875rem', fontWeight: 600, color: 'var(--text-primary)' }}>
                Inspect Any Git Repository
              </div>
              <p style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
                Run full-stack AST extraction, discover cross-layer call relationships, and review verified security findings.
              </p>
              <div style={{ display: 'flex', gap: '0.5rem', marginTop: '0.5rem', flexWrap: 'wrap' }}>
                <Button
                  variant="secondary"
                  size="sm"
                  onClick={() => router.push('/scan?repo=https://github.com/yashaskn8/RepoLens&branch=main')}
                >
                  Scan RepoLens
                </Button>
                <Button
                  variant="secondary"
                  size="sm"
                  onClick={() => router.push('/scan?repo=https://github.com/tiangolo/fastapi&branch=master')}
                >
                  Scan FastAPI
                </Button>
                <Button
                  variant="glow"
                  size="sm"
                  onClick={() => router.push('/scan')}
                  rightIcon={<ArrowRight size={14} />}
                >
                  Custom URL
                </Button>
              </div>
            </div>

            {/* Quick Links Card */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
              <Link
                href="/findings"
                style={{
                  padding: '1rem',
                  borderRadius: 'var(--radius-md)',
                  background: 'rgba(255, 255, 255, 0.03)',
                  border: '1px solid var(--border-subtle)',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '0.35rem',
                }}
                className="glass-panel-interactive"
              >
                <ShieldAlert size={18} style={{ color: 'var(--high-text)' }} />
                <span style={{ fontSize: '0.875rem', fontWeight: 600, color: '#ffffff' }}>Findings</span>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Explore all rules</span>
              </Link>

              <Link
                href="/remediation"
                style={{
                  padding: '1rem',
                  borderRadius: 'var(--radius-md)',
                  background: 'rgba(255, 255, 255, 0.03)',
                  border: '1px solid var(--border-subtle)',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '0.35rem',
                }}
                className="glass-panel-interactive"
              >
                <Wrench size={18} style={{ color: 'var(--accent-purple)' }} />
                <span style={{ fontSize: '0.875rem', fontWeight: 600, color: '#ffffff' }}>Remediation</span>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>7-step HITL flow</span>
              </Link>
            </div>
          </Card>
        </div>
      </div>
    </AppShell>
  );
}
