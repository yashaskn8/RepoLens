'use client';

import React, { useState, useEffect, useCallback } from 'react';
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
  X,
} from 'lucide-react';
import { Badge } from '@/components/ui/Badge';

export interface AppShellProps {
  children: React.ReactNode;
  breadcrumbs?: { label: string; href?: string }[];
  title?: string;
}

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

  // Close mobile drawer on route change
  useEffect(() => {
    setIsMobileOpen(false);
  }, [pathname]);

  const closeMobile = useCallback(() => setIsMobileOpen(false), []);

  const renderNavLinks = (collapsed: boolean) => (
    <nav style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem' }}>
      {navItems.map((item) => {
        const isActive = pathname === item.href || (item.href !== '/dashboard' && pathname.startsWith(item.href));
        return (
          <Link
            key={item.href}
            href={item.href}
            className={`nav-link ${isActive ? 'nav-link-active' : ''}`}
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: collapsed ? 'center' : 'space-between',
              padding: collapsed ? '0.65rem' : '0.6rem 0.85rem',
              borderRadius: 'var(--radius-sm)',
              color: isActive ? '#ffffff' : 'var(--text-secondary)',
              border: '1px solid transparent',
              textDecoration: 'none',
              fontSize: '0.875rem',
            }}
            title={collapsed ? item.label : undefined}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.7rem' }}>
              <span style={{ color: isActive ? 'var(--accent-cyan)' : 'inherit', display: 'flex', flexShrink: 0 }}>
                {item.icon}
              </span>
              {!collapsed && (
                <span style={{ fontWeight: isActive ? 600 : 500 }}>
                  {item.label}
                </span>
              )}
            </div>

            {!collapsed && item.badge && (
              <Badge variant="cyan" size="sm">
                {item.badge}
              </Badge>
            )}
          </Link>
        );
      })}
    </nav>
  );

  const renderSidebarFooter = (collapsed: boolean) => (
    <div style={{ borderTop: '1px solid var(--border-subtle)', paddingTop: '0.75rem', display: 'flex', flexDirection: 'column', gap: '0.25rem' }}>
      <Link
        href="/account"
        className={`nav-link ${pathname === '/account' ? 'nav-link-active' : ''}`}
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: collapsed ? 'center' : 'flex-start',
          gap: '0.7rem',
          padding: '0.6rem 0.85rem',
          borderRadius: 'var(--radius-sm)',
          color: pathname === '/account' ? '#ffffff' : 'var(--text-secondary)',
          border: '1px solid transparent',
          fontSize: '0.875rem',
        }}
        title={collapsed ? 'Account' : undefined}
      >
        <User size={18} />
        {!collapsed && <span style={{ fontWeight: pathname === '/account' ? 600 : 500 }}>Account & Role</span>}
      </Link>

      {collapsed && (
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
  );

  return (
    <div style={{ display: 'flex', minHeight: '100vh', backgroundColor: 'var(--bg-base)' }}>
      {/* Global Command Palette */}
      <CommandPalette />

      {/* Auth Modal */}
      <AuthModal isOpen={isAuthModalOpen} onClose={() => setIsAuthModalOpen(false)} />

      {/* Mobile Sidebar Drawer */}
      {isMobileOpen && (
        <>
          <div className="mobile-drawer-overlay fade-in-backdrop" onClick={closeMobile} />
          <aside
            className="glass-sidebar mobile-sidebar"
            style={{
              display: 'flex',
              flexDirection: 'column',
              justifyContent: 'space-between',
              padding: '1.25rem 0.75rem',
            }}
          >
            <div>
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
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
                      boxShadow: '0 0 12px rgba(99, 102, 241, 0.35)',
                    }}
                  >
                    <Layers size={16} color="#ffffff" />
                  </div>
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
                </Link>
                <button
                  type="button"
                  onClick={closeMobile}
                  style={{
                    background: 'rgba(255, 255, 255, 0.05)',
                    border: '1px solid var(--border-glass)',
                    borderRadius: 'var(--radius-sm)',
                    color: 'var(--text-muted)',
                    cursor: 'pointer',
                    padding: '0.3rem',
                    display: 'flex',
                  }}
                  aria-label="Close menu"
                >
                  <X size={16} />
                </button>
              </div>
              {renderNavLinks(false)}
            </div>
            {renderSidebarFooter(false)}
          </aside>
        </>
      )}

      {/* Desktop Collapsible Sidebar */}
      <aside
        className="glass-sidebar hidden md:flex"
        style={{
          width: isCollapsed ? '4.5rem' : '15.5rem',
          flexDirection: 'column',
          justifyContent: 'space-between',
          transition: 'width var(--transition-smooth)',
          position: 'sticky',
          top: 0,
          height: '100vh',
          zIndex: 45,
          padding: '1.25rem 0.75rem',
        }}
        aria-hidden={isMobileOpen}
      >

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
                  boxShadow: '0 0 12px rgba(99, 102, 241, 0.35)',
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
                className="interactive-btn"
                style={{
                  background: 'rgba(255, 255, 255, 0.04)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: 'var(--radius-sm)',
                  color: 'var(--text-muted)',
                  cursor: 'pointer',
                  padding: '0.25rem',
                  display: 'flex',
                }}
                aria-label="Collapse sidebar"
              >
                <ChevronLeft size={14} />
              </button>
            )}
          </div>

          {renderNavLinks(isCollapsed)}
        </div>

        {renderSidebarFooter(isCollapsed)}
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

        <main
          className="page-enter"
          style={{ flex: 1, padding: '1.5rem', width: '100%', maxWidth: '88rem', margin: '0 auto' }}
        >
          {children}
        </main>
      </div>
    </div>
  );
}
