'use client';

import React from 'react';

export interface CardProps extends Omit<React.HTMLAttributes<HTMLDivElement>, 'title'> {
  variant?: 'default' | 'interactive' | 'subtle' | 'bento';
  glow?: 'none' | 'indigo' | 'cyan' | 'purple';
  title?: React.ReactNode;
  badge?: React.ReactNode;
  action?: React.ReactNode;
  children: React.ReactNode;
}

export function Card({
  variant = 'default',
  glow = 'none',
  title,
  badge,
  action,
  children,
  className = '',
  style,
  ...props
}: CardProps) {
  const getVariantClass = () => {
    switch (variant) {
      case 'interactive':
        return 'glass-panel glass-panel-interactive';
      case 'subtle':
        return 'glass-panel-subtle';
      case 'bento':
        return 'glass-panel bento-card';
      default:
        return 'glass-panel';
    }
  };

  const getGlowStyle = (): React.CSSProperties => {
    switch (glow) {
      case 'indigo':
        return { boxShadow: '0 0 25px rgba(99, 102, 241, 0.12), var(--shadow-inner-glow)' };
      case 'cyan':
        return { boxShadow: '0 0 25px rgba(56, 189, 248, 0.12), var(--shadow-inner-glow)' };
      case 'purple':
        return { boxShadow: '0 0 25px rgba(168, 85, 247, 0.12), var(--shadow-inner-glow)' };
      default:
        return {};
    }
  };

  return (
    <div
      className={`${getVariantClass()} ${className}`}
      style={{
        padding: '1.5rem',
        position: 'relative',
        overflow: 'hidden',
        ...getGlowStyle(),
        ...style,
      }}
      {...props}
    >
      {(title || badge || action) && (
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.1rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
            {typeof title === 'string' ? (
              <h3 style={{ fontSize: '1.0625rem', fontWeight: 700, fontFamily: 'var(--font-display)', color: '#ffffff', letterSpacing: '-0.01em' }}>
                {title}
              </h3>
            ) : (
              title
            )}
            {badge}
          </div>
          {action}
        </div>
      )}
      {children}
    </div>
  );
}

export interface StatCardProps {
  label: string;
  value: string | number;
  subtext?: string;
  icon?: React.ReactNode;
  trend?: { value: string; positive?: boolean };
  badge?: React.ReactNode;
  glow?: 'none' | 'indigo' | 'cyan' | 'purple';
  className?: string;
  onClick?: () => void;
}

export function StatCard({
  label,
  value,
  subtext,
  icon,
  trend,
  badge,
  glow = 'none',
  className = '',
  onClick,
}: StatCardProps) {
  return (
    <Card
      variant={onClick ? 'interactive' : 'default'}
      glow={glow}
      className={className}
      onClick={onClick}
      style={{ cursor: onClick ? 'pointer' : 'default', padding: '1.25rem 1.35rem' }}
    >
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '0.65rem' }}>
        <span style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
          {label}
        </span>
        {icon && (
          <div style={{ color: 'var(--text-muted)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            {icon}
          </div>
        )}
      </div>

      <div style={{ display: 'flex', alignItems: 'baseline', gap: '0.65rem', marginBottom: subtext ? '0.35rem' : 0 }}>
        <div style={{ fontSize: '1.875rem', fontWeight: 800, fontFamily: 'var(--font-display)', color: 'var(--text-primary)', lineHeight: 1.1, letterSpacing: '-0.02em' }}>
          {value}
        </div>
        {badge}
      </div>

      {(subtext || trend) && (
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginTop: '0.25rem' }}>
          {trend && (
            <span
              style={{
                fontSize: '0.75rem',
                fontWeight: 600,
                color: trend.positive ? 'var(--success-text)' : 'var(--error-text)',
              }}
            >
              {trend.value}
            </span>
          )}
          {subtext && (
            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
              {subtext}
            </span>
          )}
        </div>
      )}
    </Card>
  );
}
