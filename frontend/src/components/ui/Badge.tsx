'use client';

import React from 'react';
import { Severity } from '@/types/domain';

export type BadgeVariant =
  | 'default'
  | 'critical'
  | 'high'
  | 'medium'
  | 'low'
  | 'info'
  | 'success'
  | 'warning'
  | 'error'
  | 'operator'
  | 'user'
  | 'cyan'
  | 'purple'
  | 'tag'
  | string;

export interface BadgeProps {
  variant?: BadgeVariant | Severity;
  severity?: Severity | string;
  children: React.ReactNode;
  icon?: React.ReactNode;
  className?: string;
  size?: 'sm' | 'md';
  title?: string;
  style?: React.CSSProperties;
}

export function Badge({
  variant,
  severity,
  children,
  icon,
  className = '',
  size = 'md',
  title,
  style,
}: BadgeProps) {
  const rawVariant = severity || variant || 'default';
  const normVariant = typeof rawVariant === 'string' ? rawVariant.toLowerCase() : 'default';

  const getVariantStyles = (): { bg: string; border: string; text: string } => {
    switch (normVariant) {
      case 'critical':
        return { bg: 'var(--critical-bg)', border: 'var(--critical-border)', text: 'var(--critical-text)' };
      case 'high':
        return { bg: 'var(--high-bg)', border: 'var(--high-border)', text: 'var(--high-text)' };
      case 'medium':
        return { bg: 'var(--medium-bg)', border: 'var(--medium-border)', text: 'var(--medium-text)' };
      case 'low':
      case 'info':
        return { bg: 'var(--low-bg)', border: 'var(--low-border)', text: 'var(--low-text)' };
      case 'success':
        return { bg: 'var(--success-bg)', border: 'var(--success-border)', text: 'var(--success-text)' };
      case 'warning':
        return { bg: 'var(--warning-bg)', border: 'var(--warning-border)', text: 'var(--warning-text)' };
      case 'error':
        return { bg: 'var(--error-bg)', border: 'var(--error-border)', text: 'var(--error-text)' };
      case 'operator':
        return { bg: 'var(--operator-bg)', border: 'var(--operator-border)', text: 'var(--operator-text)' };
      case 'user':
        return { bg: 'var(--user-bg)', border: 'var(--user-border)', text: 'var(--user-text)' };
      case 'cyan':
        return { bg: 'rgba(56, 189, 248, 0.12)', border: 'rgba(56, 189, 248, 0.35)', text: '#38bdf8' };
      case 'purple':
        return { bg: 'rgba(168, 85, 247, 0.12)', border: 'rgba(168, 85, 247, 0.35)', text: '#c084fc' };
      case 'tag':
        return { bg: 'rgba(255, 255, 255, 0.06)', border: 'rgba(255, 255, 255, 0.12)', text: 'var(--text-light)' };
      default:
        return { bg: 'var(--badge-bg)', border: 'var(--badge-border)', text: 'var(--badge-text)' };
    }
  };

  const { bg, border, text } = getVariantStyles();

  return (
    <span
      title={title}
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: '0.35rem',
        padding: size === 'sm' ? '0.15rem 0.5rem' : '0.25rem 0.65rem',
        fontSize: size === 'sm' ? '0.7rem' : '0.75rem',
        fontWeight: 600,
        fontFamily: 'var(--font-mono)',
        borderRadius: 'var(--radius-full)',
        backgroundColor: bg,
        borderColor: border,
        borderWidth: '1px',
        borderStyle: 'solid',
        color: text,
        letterSpacing: '0.02em',
        lineHeight: 1.2,
        ...style,
      }}
      className={className}
    >
      {icon && <span style={{ display: 'inline-flex', alignItems: 'center' }}>{icon}</span>}
      {children}
    </span>
  );
}
