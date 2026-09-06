'use client';

import React from 'react';
import Link from 'next/link';
import { Layers, ArrowRight, GitBranch, LogIn } from 'lucide-react';
import { Button } from '@/components/ui/Button';
import { Badge } from '@/components/ui/Badge';
import { useAuth } from '@/context/AuthContext';

export interface LandingNavProps {
  onOpenAuthModal: () => void;
}

export function LandingNav({ onOpenAuthModal }: LandingNavProps) {
  const { isAuthenticated } = useAuth();

  return (
    <header
      className="glass-header"
      style={{
        position: 'sticky',
        top: 0,
        zIndex: 50,
        padding: '0.75rem 2rem',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
      }}
    >
      {/* Brand */}
      <Link href="/" style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
        <div
          style={{
            width: '2.25rem',
            height: '2.25rem',
            borderRadius: 'var(--radius-md)',
            background: 'var(--accent-gradient)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            boxShadow: '0 0 20px rgba(99, 102, 241, 0.45)',
          }}
        >
          <Layers size={18} color="#ffffff" />
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <span
            style={{
              fontSize: '1.25rem',
              fontWeight: 800,
              fontFamily: 'var(--font-display)',
              letterSpacing: '-0.03em',
              color: '#ffffff',
            }}
          >
            RepoLens
          </span>
        </div>
      </Link>

      {/* Nav Links */}
      <nav
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: '1.75rem',
        }}
        className="hidden md:flex"
      >
        <Link
          href="/scan"
          style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', transition: 'color var(--transition-fast)' }}
        >
          Scan Repository
        </Link>
        <Link
          href="/change-analysis"
          style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', transition: 'color var(--transition-fast)' }}
        >
          PR Analysis
        </Link>
        <Link
          href="/findings"
          style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', transition: 'color var(--transition-fast)' }}
        >
          Findings
        </Link>
        <Link
          href="/remediation"
          style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', transition: 'color var(--transition-fast)' }}
        >
          Suggested Fixes
        </Link>
      </nav>

      {/* Action Buttons */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.85rem' }}>
        <Link
          href="https://github.com/yashaskn8/RepoLens"
          target="_blank"
          rel="noopener noreferrer"
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '0.4rem',
            color: 'var(--text-secondary)',
            padding: '0.4rem',
          }}
          aria-label="GitHub Repository"
        >
          <GitBranch size={16} />
          <span style={{ fontSize: '0.8125rem' }}>GitHub</span>
        </Link>

        {isAuthenticated ? (
          <Link href="/dashboard">
            <Button variant="glow" size="sm" rightIcon={<ArrowRight size={14} />}>
              Dashboard
            </Button>
          </Link>
        ) : (
          <>
            <Button
              variant="ghost"
              size="sm"
              onClick={onOpenAuthModal}
              leftIcon={<LogIn size={14} />}
              className="hidden sm:inline-flex"
            >
              Sign In
            </Button>
            <Link href="/scan">
              <Button variant="glow" size="sm" rightIcon={<ArrowRight size={14} />}>
                Analyze Repository
              </Button>
            </Link>
          </>
        )}
      </div>
    </header>
  );
}
