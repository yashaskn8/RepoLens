'use client';

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { useAuth } from '@/context/AuthContext';
import { HealthResponse } from '@/types/domain';
import { fetchHealth } from '@/lib/api';
import { AppHeader } from './AppHeader';
import { AuthModal } from '@/components/auth/AuthModal';
import { CommandPalette } from '@/components/ui/CommandPalette';
import {
  LayoutDashboard,
  Scan,
  GitPullRequest,
  ShieldAlert,
  Wrench,
  User,
  ChevronLeft,
  ChevronRight,
  Layers,
  Sparkles,
} from 'lucide-react';
import { Badge } from '@/components/ui/Badge';

export interface AppShellProps {
  children: React.ReactNode;
  breadcrumbs?: { label: string; href?: string }[];
  title?: string;
}

export function AppShell({ children, breadcrumbs = [], title }: AppShellProps) {
  const [isCollapsed, setIsCollapsed] = useState(false);
  const [isMobileOpen, setIsMobileOpen] = useState(false);
  const [isAuthModalOpen, setIsAuthModalOpen] = useState(false);
  const [health, setHealth] = useState<HealthResponse | null>(null);

  const pathname = usePathname();
  const { user, isOperator } = useAuth();

  useEffect(() => {
    fetchHealth()
      .then(setHealth)
      .catch(() => setHealth(null));
  }, []);

  const navItems = [
    {
      label: 'Overview',
      href: '/dashboard',
      icon: <LayoutDashboard size={18} />,
      badge: undefined,
    },
    {
      label: 'Repository Scan',
      href: '/scan',
      icon: <Scan size={18} />,
      badge: 'AST',
    },
    {
      label: 'Change Intelligence',
      href: '/change-analysis',
      icon: <GitPullRequest size={18} />,
      badge: 'PRs',
    },
    {
      label: 'Findings Explorer',
      href: '/findings',
      icon: <ShieldAlert size={18} />,
      badge: undefined,
    },
    {
      label: 'Remediation',
      href: '/remediation',
      icon: <Wrench size={18} />,
      badge: 'HITL',
    },
  ];

  return (
    <div style={{ display: 'flex', minHeight: '100vh', backgroundColor: 'var(--bg-base)' }}>
      {/* Global Command Palette */}
      <CommandPalette />

      {/* Auth Modal */}
      <AuthModal isOpen={isAuthModalOpen} onClose={() => setIsAuthModalOpen(false)} />

      {/* Desktop Collapsible Sidebar */}
      <aside
        className="glass-sidebar hidden md:flex"
        style={{
          width: isCollapsed ? '4.5rem' : '16rem',
          flexDirection: 'column',
          justifyContent: 'space-between',
          transition: 'width var(--transition-normal)',
          position: 'sticky',
          top: 0,
          height: '100vh',
          zIndex: 45,
          padding: '1.25rem 0.75rem',
        }}
      >
        {/* Brand / Logo */}
        <div>
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: isCollapsed ? 'center' : 'space-between',
              padding: '0 0.5rem 1.25rem 0.5rem',
              borderBottom: '1px solid var(--border-subtle)',
              marginBottom: '1rem',
            }}
          >
            <Link href="/" style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
              <div
                style={{
                  width: '2rem',
                  height: '2rem',
                  borderRadius: 'var(--radius-md)',
                  background: 'var(--accent-gradient)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  boxShadow: '0 0 15px rgba(99, 102, 241, 0.4)',
                }}
              >
                <Layers size={16} color="#ffffff" />
              </div>
              {!isCollapsed && (
                <span
                  style={{
                    fontSize: '1.125rem',
                    fontWeight: 800,
                    fontFamily: 'var(--font-display)',
                    letterSpacing: '-0.02em',
                    color: '#ffffff',
                  }}
                >
                  RepoLens
                </span>
              )}
            </Link>

            {!isCollapsed && (
              <button
                type="button"
                onClick={() => setIsCollapsed(!isCollapsed)}
                style={{
                  background: 'transparent',
                  border: 'none',
                  color: 'var(--text-muted)',
                  cursor: 'pointer',
                  padding: '0.2rem',
                }}
                aria-label="Collapse sidebar"
              >
                <ChevronLeft size={16} />
              </button>
            )}
          </div>

          {/* Navigation Links */}
          <nav style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
            {navItems.map((item) => {
              const isActive = pathname === item.href || (item.href !== '/dashboard' && pathname.startsWith(item.href));
              return (
                <Link
                  key={item.href}
                  href={item.href}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: isCollapsed ? 'center' : 'space-between',
                    padding: isCollapsed ? '0.65rem' : '0.65rem 0.85rem',
                    borderRadius: 'var(--radius-md)',
                    color: isActive ? '#ffffff' : 'var(--text-secondary)',
                    backgroundColor: isActive ? 'rgba(99, 102, 241, 0.18)' : 'transparent',
                    border: isActive ? '1px solid var(--border-glass-hover)' : '1px solid transparent',
                    transition: 'all var(--transition-fast)',
                    textDecoration: 'none',
                  }}
                  title={isCollapsed ? item.label : undefined}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                    <span style={{ color: isActive ? 'var(--accent-cyan)' : 'inherit', display: 'flex' }}>
                      {item.icon}
                    </span>
                    {!isCollapsed && (
                      <span style={{ fontSize: '0.875rem', fontWeight: isActive ? 600 : 500 }}>
                        {item.label}
                      </span>
                    )}
                  </div>

                  {!isCollapsed && item.badge && (
                    <Badge variant="cyan" size="sm">
                      {item.badge}
                    </Badge>
                  )}
                </Link>
              );
            })}
          </nav>
        </div>

        {/* Sidebar Footer */}
        <div>
          <div style={{ borderTop: '1px solid var(--border-subtle)', paddingTop: '0.85rem', display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
            <Link
              href="/account"
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: isCollapsed ? 'center' : 'flex-start',
                gap: '0.75rem',
                padding: '0.65rem 0.85rem',
                borderRadius: 'var(--radius-md)',
                color: pathname === '/account' ? '#ffffff' : 'var(--text-secondary)',
                backgroundColor: pathname === '/account' ? 'rgba(99, 102, 241, 0.18)' : 'transparent',
                transition: 'all var(--transition-fast)',
              }}
              title={isCollapsed ? 'Account' : undefined}
            >
              <User size={18} />
              {!isCollapsed && <span style={{ fontSize: '0.875rem', fontWeight: 500 }}>Account & Role</span>}
            </Link>

            {isCollapsed && (
              <button
                type="button"
                onClick={() => setIsCollapsed(false)}
                style={{
                  background: 'transparent',
                  border: 'none',
                  color: 'var(--text-muted)',
                  cursor: 'pointer',
                  display: 'flex',
                  justifyContent: 'center',
                  padding: '0.4rem',
                }}
                aria-label="Expand sidebar"
              >
                <ChevronRight size={16} />
              </button>
            )}
          </div>
        </div>
      </aside>

      {/* Main Workspace Body */}
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', minWidth: 0 }}>
        <AppHeader
          health={health}
          onOpenAuthModal={() => setIsAuthModalOpen(true)}
          onToggleSidebar={() => setIsMobileOpen(!isMobileOpen)}
          breadcrumbs={breadcrumbs}
          title={title}
        />

        <main style={{ flex: 1, padding: '1.5rem', width: '100%', maxWidth: '90rem', margin: '0 auto' }}>
          {children}
        </main>
      </div>
    </div>
  );
}
