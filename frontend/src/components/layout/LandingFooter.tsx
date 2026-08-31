'use client';

import React from 'react';
import Link from 'next/link';
import { Layers, GitBranch, Shield, Heart } from 'lucide-react';
import { Badge } from '@/components/ui/Badge';
import { HealthResponse } from '@/types/domain';
import { StatusIndicator } from '@/components/ui/StatusIndicator';

export interface LandingFooterProps {
  health?: HealthResponse | null;
}

export function LandingFooter({ health }: LandingFooterProps) {
  return (
    <footer
      style={{
        borderTop: '1px solid var(--border-subtle)',
        background: 'rgba(4, 6, 14, 0.95)',
        padding: '3.5rem 2rem 2rem 2rem',
      }}
    >
      <div style={{ maxWidth: '75rem', margin: '0 auto', display: 'flex', flexDirection: 'column', gap: '2.5rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', flexWrap: 'wrap', gap: '2rem' }}>
          {/* Brand Col */}
          <div style={{ maxWidth: '22rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '0.75rem' }}>
              <div
                style={{
                  width: '1.75rem',
                  height: '1.75rem',
                  borderRadius: 'var(--radius-sm)',
                  background: 'var(--accent-gradient)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                }}
              >
                <Layers size={14} color="#ffffff" />
              </div>
              <span style={{ fontSize: '1.125rem', fontWeight: 800, fontFamily: 'var(--font-display)', color: '#ffffff' }}>
                RepoLens
              </span>
            </div>
            <p style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
              Evidence-first repository intelligence. Deterministic AST graphs, cross-layer contract tracing, and human-in-the-loop remediation.
            </p>
          </div>

          {/* Links 1 */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.6rem', minWidth: '8rem' }}>
            <span style={{ fontSize: '0.8125rem', fontWeight: 600, color: 'var(--text-primary)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Platform
            </span>
            <Link href="/scan" style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)' }}>
              Scan Workspace
            </Link>
            <Link href="/change-analysis" style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)' }}>
              Change Intelligence
            </Link>
            <Link href="/findings" style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)' }}>
              Findings Explorer
            </Link>
            <Link href="/remediation" style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)' }}>
              Remediation Engine
            </Link>
          </div>

          {/* Links 2 */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.6rem', minWidth: '8rem' }}>
            <span style={{ fontSize: '0.8125rem', fontWeight: 600, color: 'var(--text-primary)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Integrations
            </span>
            <Link href="https://github.com/yashaskn8/RepoLens" target="_blank" style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)' }}>
              GitHub CI/CD
            </Link>
            <Link href="/account" style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)' }}>
              Role Policies
            </Link>
            <Link href="#architecture" style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)' }}>
              AST Specification
            </Link>
          </div>

          {/* System Status */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.6rem', minWidth: '12rem' }}>
            <span style={{ fontSize: '0.8125rem', fontWeight: 600, color: 'var(--text-primary)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              System Integrity
            </span>
            <div
              style={{
                padding: '0.75rem',
                borderRadius: 'var(--radius-md)',
                background: 'rgba(255, 255, 255, 0.03)',
                border: '1px solid var(--border-subtle)',
                display: 'flex',
                flexDirection: 'column',
                gap: '0.4rem',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Backend Engine</span>
                <StatusIndicator
                  status={health?.status === 'healthy' ? 'healthy' : 'degraded'}
                  label={health?.status || 'Active'}
                  size="sm"
                />
              </div>
              <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                Database: {health?.database || 'SQLite / PostgreSQL'}
              </div>
              <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                Engine Version: {health?.version || '1.0.1-2026'}
              </div>
            </div>
          </div>
        </div>

        {/* Bottom bar */}
        <div
          style={{
            borderTop: '1px solid var(--border-subtle)',
            paddingTop: '1.5rem',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            flexWrap: 'wrap',
            gap: '1rem',
            fontSize: '0.75rem',
            color: 'var(--text-muted)',
          }}
        >
          <div>
            © {new Date().getFullYear()} RepoLens. Evidence-First Architecture. All rights reserved.
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
            <span>Zero-hallucination guarantee</span>
            <span>•</span>
            <span>Human-authorized writes only</span>
          </div>
        </div>
      </div>
    </footer>
  );
}
