'use client';

import React from 'react';
import Link from 'next/link';
import { useAuth } from '@/context/AuthContext';
import { HealthResponse } from '@/types/domain';
import { StatusIndicator } from '@/components/ui/StatusIndicator';
import { Badge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import {
  Search,
  Shield,
  User,
  LogOut,
  LogIn,
  Menu,
  Sparkles,
} from 'lucide-react';

export interface AppHeaderProps {
  health?: HealthResponse | null;
  onOpenAuthModal: () => void;
  onToggleSidebar?: () => void;
  title?: string;
  breadcrumbs?: { label: string; href?: string }[];
}

export function AppHeader({
  health,
  onOpenAuthModal,
  onToggleSidebar,
  title,
  breadcrumbs = [],
}: AppHeaderProps) {
  const { user, isAuthenticated, isOperator, logout } = useAuth();

  return (
    <header
      className="glass-header"
      style={{
        height: '4rem',
        padding: '0 1.5rem',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        position: 'sticky',
        top: 0,
        zIndex: 40,
      }}
    >
      {/* Left: Mobile Toggle & Title/Breadcrumbs */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
        {onToggleSidebar && (
          <button
            type="button"
            onClick={onToggleSidebar}
            style={{
              background: 'transparent',
              border: 'none',
              color: 'var(--text-secondary)',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              padding: '0.4rem',
            }}
            className="md:hidden"
            aria-label="Toggle navigation"
          >
            <Menu size={20} />
          </button>
        )}

        {breadcrumbs.length > 0 ? (
          <nav aria-label="Breadcrumb" style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.875rem' }}>
            {breadcrumbs.map((crumb, idx) => (
              <React.Fragment key={idx}>
                {idx > 0 && <span style={{ color: 'var(--text-muted)' }}>/</span>}
                {crumb.href ? (
                  <Link
                    href={crumb.href}
                    style={{ color: 'var(--text-secondary)', transition: 'color var(--transition-fast)' }}
                    onMouseEnter={(e) => (e.currentTarget.style.color = 'var(--text-primary)')}
                    onMouseLeave={(e) => (e.currentTarget.style.color = 'var(--text-secondary)')}
                  >
                    {crumb.label}
                  </Link>
                ) : (
                  <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{crumb.label}</span>
                )}
              </React.Fragment>
            ))}
          </nav>
        ) : (
          <h1
            style={{
              fontSize: '1rem',
              fontWeight: 600,
              fontFamily: 'var(--font-display)',
              color: 'var(--text-primary)',
            }}
          >
            {title || 'RepoLens Workspace'}
          </h1>
        )}
      </div>

      {/* Right: Quick Search + Health Status + User / Operator Pill */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.85rem' }}>
        {/* Quick Command Trigger Button */}
        <button
          type="button"
          onClick={() => {
            const event = new KeyboardEvent('keydown', { key: 'k', metaKey: true, bubbles: true });
            window.dispatchEvent(event);
          }}
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '0.5rem',
            padding: '0.35rem 0.75rem',
            background: 'rgba(255, 255, 255, 0.04)',
            border: '1px solid var(--border-glass)',
            borderRadius: 'var(--radius-md)',
            color: 'var(--text-muted)',
            fontSize: '0.75rem',
            fontFamily: 'var(--font-sans)',
            cursor: 'pointer',
            transition: 'all var(--transition-fast)',
          }}
          className="hidden md:inline-flex"
        >
          <Search size={13} />
          <span>Quick Find...</span>
          <span
            style={{
              fontFamily: 'var(--font-mono)',
              fontSize: '0.65rem',
              padding: '0.1rem 0.35rem',
              borderRadius: 'var(--radius-xs)',
              background: 'rgba(255, 255, 255, 0.08)',
            }}
          >
            ⌘K
          </span>
        </button>

        {/* Backend Health Pill */}
        <div
          style={{
            padding: '0.25rem 0.65rem',
            borderRadius: 'var(--radius-full)',
            background: 'rgba(255, 255, 255, 0.03)',
            border: '1px solid var(--border-subtle)',
            display: 'flex',
            alignItems: 'center',
            gap: '0.4rem',
          }}
          className="hidden md:flex"
        >
          <StatusIndicator
            status={health?.status === 'healthy' ? 'healthy' : health?.status === 'degraded' ? 'degraded' : 'running'}
            size="sm"
          />
          <span style={{ fontSize: '0.7rem', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)' }}>
            {health?.database || 'engine:connected'}
          </span>
        </div>

        {/* Auth / Role Indicator */}
        {isAuthenticated && user ? (
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Link
              href="/account"
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '0.5rem',
                padding: '0.3rem 0.65rem',
                borderRadius: 'var(--radius-md)',
                background: 'rgba(255, 255, 255, 0.04)',
                border: '1px solid var(--border-glass)',
                transition: 'border-color var(--transition-fast)',
              }}
            >
              <User size={14} style={{ color: isOperator ? 'var(--operator-text)' : 'var(--user-text)' }} />
              <span style={{ fontSize: '0.8125rem', fontWeight: 500, color: 'var(--text-primary)' }}>
                {user.email.split('@')[0]}
              </span>
              <Badge variant={isOperator ? 'operator' : 'user'} size="sm">
                {user.role}
              </Badge>
            </Link>
            <Button
              variant="ghost"
              size="sm"
              onClick={logout}
              title="Sign Out"
              style={{ padding: '0.4rem' }}
            >
              <LogOut size={15} />
            </Button>
          </div>
        ) : (
          <Button
            variant="secondary"
            size="sm"
            onClick={onOpenAuthModal}
            leftIcon={<LogIn size={14} />}
          >
            Sign In
          </Button>
        )}
      </div>
    </header>
  );
}
