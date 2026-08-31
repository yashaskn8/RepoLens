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
          <Badge variant="cyan" size="sm">
            2026 Engine
          </Badge>
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
          href="#architecture"
          style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', transition: 'color var(--transition-fast)' }}
        >
          Architecture
        </Link>
        <Link
          href="#pipeline"
          style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', transition: 'color var(--transition-fast)' }}
        >
          Evidence Flow
        </Link>
        <Link
          href="#safety"
          style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', transition: 'color var(--transition-fast)' }}
        >
          Safety & Contracts
        </Link>
        <Link
          href="/findings"
          style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', transition: 'color var(--transition-fast)' }}
        >
          Explorer
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
          <GitBranch size={18} />
          <span style={{ fontSize: '0.75rem', fontFamily: 'var(--font-mono)' }}>GitHub</span>
        </Link>

        {isAuthenticated ? (
          <Link href="/dashboard">
            <Button variant="glow" size="sm" rightIcon={<ArrowRight size={14} />}>
              Open Dashboard
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
                Launch Workspace
              </Button>
            </Link>
          </>
        )}
      </div>
    </header>
  );
}
