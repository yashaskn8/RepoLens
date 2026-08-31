'use client';

import React, { useState } from 'react';
import { AppShell } from '@/components/layout/AppShell';
import { Card } from '@/components/ui/Card';
import { Button } from '@/components/ui/Button';
import { Badge } from '@/components/ui/Badge';
import { AuthModal } from '@/components/auth/AuthModal';
import { useAuth } from '@/context/AuthContext';
import { getCsrfToken } from '@/lib/api';
import {
  User,
  Shield,
  ShieldCheck,
  Lock,
  Key,
  LogOut,
  LogIn,
  CheckCircle2,
  XCircle,
  Database,
  Trash2,
} from 'lucide-react';

export default function AccountPage() {
  const { user, isAuthenticated, isOperator, logout, refreshUser } = useAuth();
  const [isAuthModalOpen, setIsAuthModalOpen] = useState(false);
  const [clearMessage, setClearMessage] = useState<string | null>(null);

  const csrfToken = typeof window !== 'undefined' ? getCsrfToken() : null;

  const handleClearLocalCache = () => {
    if (typeof window !== 'undefined') {
      localStorage.removeItem('repolens_recent_scans');
      setClearMessage('Local workspace cache cleared.');
      setTimeout(() => setClearMessage(null), 3000);
    }
  };

  return (
    <AppShell breadcrumbs={[{ label: 'Account & Permissions' }]} title="Account & Roles">
      <AuthModal isOpen={isAuthModalOpen} onClose={() => setIsAuthModalOpen(false)} />

      <div style={{ display: 'flex', flexDirection: 'column', gap: '2rem' }}>
        {/* Top Header */}
        <div>
          <h1
            style={{
              fontSize: '1.75rem',
              fontWeight: 800,
              fontFamily: 'var(--font-display)',
              color: '#ffffff',
              marginBottom: '0.4rem',
            }}
          >
            User Session & Role Permissions
          </h1>
          <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)' }}>
            Manage your session identity, inspect CSRF security status, and review role capabilities.
          </p>
        </div>

        {/* User Identity Card */}
        <Card glow="indigo" style={{ padding: '2rem', display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
              <div
                style={{
                  width: '3.5rem',
                  height: '3.5rem',
                  borderRadius: 'var(--radius-lg)',
                  background: isOperator ? 'var(--operator-bg)' : 'var(--user-bg)',
                  border: isOperator ? '1px solid var(--operator-border)' : '1px solid var(--user-border)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  color: isOperator ? 'var(--operator-text)' : 'var(--user-text)',
                }}
              >
                <User size={24} />
              </div>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem', marginBottom: '0.25rem' }}>
                  <h2 style={{ fontSize: '1.25rem', fontWeight: 700, color: '#ffffff' }}>
                    {isAuthenticated && user ? user.email : 'Anonymous Session'}
                  </h2>
                  <Badge variant={isOperator ? 'operator' : 'user'} size="sm">
                    {isAuthenticated && user ? user.role : 'GUEST'}
                  </Badge>
                </div>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                  User ID: {user?.id || 'session-ephemeral'}
                </div>
              </div>
            </div>

            <div style={{ display: 'flex', gap: '0.75rem' }}>
              {isAuthenticated ? (
                <Button variant="danger" size="md" onClick={logout} leftIcon={<LogOut size={16} />}>
                  Sign Out
                </Button>
              ) : (
                <Button variant="glow" size="md" onClick={() => setIsAuthModalOpen(true)} leftIcon={<LogIn size={16} />}>
                  Sign In / Register
                </Button>
              )}
            </div>
          </div>
        </Card>

        {/* Role Capabilities Matrix (USER vs OPERATOR) */}
        <Card style={{ padding: '2rem', display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
          <h3 style={{ fontSize: '1.125rem', fontWeight: 700, fontFamily: 'var(--font-display)', color: '#ffffff' }}>
            Role Permissions & Authorization Boundaries
          </h3>

          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
              gap: '1.25rem',
            }}
          >
            {/* USER Column */}
            <div
              style={{
                padding: '1.25rem',
                borderRadius: 'var(--radius-lg)',
                background: 'rgba(5, 8, 18, 0.75)',
                border: '1px solid var(--user-border)',
                display: 'flex',
                flexDirection: 'column',
                gap: '0.75rem',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <span style={{ fontSize: '1rem', fontWeight: 700, color: 'var(--user-text)' }}>
                  USER Role
                </span>
                <Badge variant="user" size="sm">Standard</Badge>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', fontSize: '0.8125rem' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: 'var(--text-light)' }}>
                  <CheckCircle2 size={15} style={{ color: 'var(--success-text)' }} /> Launch Repository AST Scans
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: 'var(--text-light)' }}>
                  <CheckCircle2 size={15} style={{ color: 'var(--success-text)' }} /> Analyze PR & Commit Impacts
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: 'var(--text-light)' }}>
                  <CheckCircle2 size={15} style={{ color: 'var(--success-text)' }} /> View Verified AST Evidence
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: 'var(--text-light)' }}>
                  <CheckCircle2 size={15} style={{ color: 'var(--success-text)' }} /> Request Research & Fix Plans
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: 'var(--text-muted)' }}>
                  <XCircle size={15} style={{ color: 'var(--error-text)' }} /> Cannot approve patches for delivery
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: 'var(--text-muted)' }}>
                  <XCircle size={15} style={{ color: 'var(--error-text)' }} /> Cannot publish GitHub PR reviews
                </div>
              </div>
            </div>

            {/* OPERATOR Column */}
            <div
              style={{
                padding: '1.25rem',
                borderRadius: 'var(--radius-lg)',
                background: 'rgba(5, 8, 18, 0.75)',
                border: '1px solid var(--operator-border)',
                display: 'flex',
                flexDirection: 'column',
                gap: '0.75rem',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <span style={{ fontSize: '1rem', fontWeight: 700, color: 'var(--operator-text)' }}>
                  OPERATOR Role
                </span>
                <Badge variant="operator" size="sm">Elevated</Badge>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', fontSize: '0.8125rem' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: 'var(--text-light)' }}>
                  <CheckCircle2 size={15} style={{ color: 'var(--success-text)' }} /> All Standard User Capabilities
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: 'var(--text-light)' }}>
                  <CheckCircle2 size={15} style={{ color: 'var(--success-text)' }} /> Approve Patch Remediation Diffs
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: 'var(--text-light)' }}>
                  <CheckCircle2 size={15} style={{ color: 'var(--success-text)' }} /> Authorize GitHub Pull Request Creation
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: 'var(--text-light)' }}>
                  <CheckCircle2 size={15} style={{ color: 'var(--success-text)' }} /> Approve & Publish Inline PR Reviews
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: 'var(--text-light)' }}>
                  <CheckCircle2 size={15} style={{ color: 'var(--success-text)' }} /> Manage Backend Security Policies
                </div>
              </div>
            </div>
          </div>
        </Card>

        {/* CSRF & Security State */}
        <Card style={{ padding: '2rem', display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
          <h3 style={{ fontSize: '1.125rem', fontWeight: 700, fontFamily: 'var(--font-display)', color: '#ffffff' }}>
            CSRF & Sandbox Security Inspection
          </h3>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '1rem' }}>
            <div style={{ padding: '1rem', background: 'rgba(5, 8, 18, 0.7)', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-subtle)' }}>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>CSRF Protection</div>
              <div style={{ fontSize: '1rem', fontWeight: 600, color: 'var(--success-text)', marginTop: '0.2rem', display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                <ShieldCheck size={16} /> Active (Cookie Token)
              </div>
            </div>

            <div style={{ padding: '1rem', background: 'rgba(5, 8, 18, 0.7)', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-subtle)' }}>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Session Storage</div>
              <div style={{ fontSize: '1rem', fontWeight: 600, color: '#ffffff', marginTop: '0.2rem' }}>
                HttpOnly Secure Cookie
              </div>
            </div>

            <div style={{ padding: '1rem', background: 'rgba(5, 8, 18, 0.7)', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-subtle)' }}>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Local Cache</div>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginTop: '0.2rem' }}>
                <span style={{ fontSize: '0.875rem', color: 'var(--text-light)' }}>Recent scans & history</span>
                <Button variant="ghost" size="sm" onClick={handleClearLocalCache} leftIcon={<Trash2 size={13} />}>
                  Clear
                </Button>
              </div>
              {clearMessage && <div style={{ fontSize: '0.7rem', color: 'var(--accent-cyan)', marginTop: '0.2rem' }}>{clearMessage}</div>}
            </div>
          </div>
        </Card>
      </div>
    </AppShell>
  );
}
