'use client';

import React, { ButtonHTMLAttributes, forwardRef } from 'react';
import { Loader2 } from 'lucide-react';

export type ButtonVariant =
  | 'primary'
  | 'secondary'
  | 'outline'
  | 'ghost'
  | 'danger'
  | 'glow'
  | 'accent-cyan'
  | 'filter'
  | 'filter-active'
  | string;

export type ButtonSize = 'sm' | 'md' | 'lg' | 'icon';

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: ButtonSize;
  isLoading?: boolean;
  leftIcon?: React.ReactNode;
  rightIcon?: React.ReactNode;
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  (
    {
      className = '',
      variant = 'primary',
      size = 'md',
      isLoading = false,
      leftIcon,
      rightIcon,
      children,
      disabled,
      ...props
    },
    ref
  ) => {
    const baseStyle: React.CSSProperties = {
      display: 'inline-flex',
      alignItems: 'center',
      justifyContent: 'center',
      gap: '0.5rem',
      fontWeight: 500,
      fontFamily: 'var(--font-sans)',
      borderRadius: 'var(--radius-md)',
      transition: 'all var(--transition-fast)',
      cursor: disabled || isLoading ? 'not-allowed' : 'pointer',
      opacity: disabled ? 0.5 : 1,
      outline: 'none',
      border: '1px solid transparent',
      textDecoration: 'none',
      whiteSpace: 'nowrap',
      userSelect: 'none',
    };

    const sizeStyles: Record<ButtonSize, React.CSSProperties> = {
      sm: { padding: '0.35rem 0.75rem', fontSize: '0.8125rem', height: '2rem' },
      md: { padding: '0.5rem 1.1rem', fontSize: '0.875rem', height: '2.5rem' },
      lg: { padding: '0.75rem 1.6rem', fontSize: '1rem', height: '3rem', borderRadius: 'var(--radius-lg)' },
      icon: { padding: '0.5rem', width: '2.5rem', height: '2.5rem', borderRadius: 'var(--radius-md)' },
    };

    const getVariantStyle = (v: string): React.CSSProperties => {
      switch (v) {
        case 'glow':
          return {
            background: 'var(--accent-gradient)',
            color: '#ffffff',
            borderColor: 'rgba(255, 255, 255, 0.25)',
            boxShadow: '0 0 20px rgba(99, 102, 241, 0.45)',
          };
        case 'accent-cyan':
          return {
            background: 'var(--cyan-gradient)',
            color: '#040711',
            fontWeight: 600,
            borderColor: 'rgba(255, 255, 255, 0.3)',
            boxShadow: '0 0 20px rgba(56, 189, 248, 0.35)',
          };
        case 'secondary':
          return {
            background: 'rgba(255, 255, 255, 0.06)',
            color: 'var(--text-primary)',
            borderColor: 'var(--border-glass)',
            backdropFilter: 'blur(8px)',
          };
        case 'outline':
          return {
            background: 'transparent',
            color: 'var(--text-light)',
            borderColor: 'var(--border-glass)',
          };
        case 'ghost':
          return {
            background: 'transparent',
            color: 'var(--text-secondary)',
            borderColor: 'transparent',
          };
        case 'danger':
          return {
            background: 'rgba(239, 68, 68, 0.15)',
            color: 'var(--error-text)',
            borderColor: 'var(--error-border)',
          };
        case 'filter':
          return {
            background: 'rgba(255, 255, 255, 0.04)',
            color: 'var(--text-secondary)',
            borderColor: 'var(--border-subtle)',
            fontSize: '0.75rem',
            padding: '0.3rem 0.65rem',
          };
        case 'filter-active':
          return {
            background: 'rgba(99, 102, 241, 0.25)',
            color: '#ffffff',
            borderColor: 'var(--border-glass-hover)',
            fontSize: '0.75rem',
            padding: '0.3rem 0.65rem',
            boxShadow: '0 0 10px rgba(99, 102, 241, 0.3)',
          };
        default:
          return {
            background: 'var(--accent-primary)',
            color: '#ffffff',
            borderColor: 'rgba(255, 255, 255, 0.15)',
            boxShadow: '0 2px 10px rgba(99, 102, 241, 0.35)',
          };
      }
    };

    return (
      <button
        ref={ref}
        disabled={disabled || isLoading}
        style={{ ...baseStyle, ...sizeStyles[size], ...getVariantStyle(variant) }}
        className={`interactive-btn ${className}`}
        {...props}
      >
        {isLoading ? <Loader2 className="animate-spin" size={16} /> : leftIcon}
        {children}
        {!isLoading && rightIcon}
      </button>
    );
  }
);

Button.displayName = 'Button';
