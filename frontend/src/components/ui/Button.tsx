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
      cursor: disabled || isLoading ? 'not-allowed' : 'pointer',
      opacity: disabled ? 0.5 : 1,
      outline: 'none',
      border: '1px solid transparent',
      textDecoration: 'none',
      whiteSpace: 'nowrap',
      userSelect: 'none',
      position: 'relative',
      letterSpacing: '0.01em',
      backdropFilter: 'blur(12px)',
      WebkitBackdropFilter: 'blur(12px)',
    };

    const sizeStyles: Record<ButtonSize, React.CSSProperties> = {
      sm: { padding: '0.375rem 0.85rem', fontSize: '0.8125rem', height: '2rem' },
      md: { padding: '0.5rem 1.15rem', fontSize: '0.875rem', height: '2.5rem' },
      lg: { padding: '0.75rem 1.65rem', fontSize: '0.9375rem', height: '2.875rem', borderRadius: 'var(--radius-lg)', fontWeight: 600 },
      icon: { padding: '0.5rem', width: '2.5rem', height: '2.5rem', borderRadius: 'var(--radius-md)' },
    };

    const getVariantStyle = (v: string): React.CSSProperties => {
      switch (v) {
        case 'glow':
          return {
            background: 'var(--accent-gradient)',
            color: '#ffffff',
            borderColor: 'rgba(255, 255, 255, 0.28)',
            borderTopColor: 'rgba(255, 255, 255, 0.45)',
            boxShadow: '0 0 20px rgba(99, 102, 241, 0.45), var(--shadow-inner-glow)',
            fontWeight: 600,
          };
        case 'accent-cyan':
          return {
            background: 'var(--cyan-gradient)',
            color: '#040711',
            fontWeight: 600,
            borderColor: 'rgba(255, 255, 255, 0.35)',
            borderTopColor: 'rgba(255, 255, 255, 0.5)',
            boxShadow: '0 0 20px rgba(56, 189, 248, 0.35), var(--shadow-inner-glow)',
          };
        case 'secondary':
          return {
            background: 'linear-gradient(135deg, rgba(255, 255, 255, 0.08) 0%, rgba(255, 255, 255, 0.02) 100%), rgba(14, 20, 42, 0.65)',
            color: 'var(--text-primary)',
            borderColor: 'var(--border-glass)',
            borderTopColor: 'var(--border-glass-top)',
            boxShadow: 'var(--shadow-inner-glow), 0 4px 12px rgba(0, 0, 0, 0.2)',
          };
        case 'outline':
          return {
            background: 'transparent',
            color: 'var(--text-light)',
            borderColor: 'var(--border-glass)',
            borderTopColor: 'rgba(255, 255, 255, 0.2)',
          };
        case 'ghost':
          return {
            background: 'transparent',
            color: 'var(--text-secondary)',
            borderColor: 'transparent',
          };
        case 'danger':
          return {
            background: 'linear-gradient(135deg, rgba(239, 68, 68, 0.18) 0%, rgba(239, 68, 68, 0.08) 100%)',
            color: 'var(--error-text)',
            borderColor: 'var(--error-border)',
            borderTopColor: 'rgba(239, 68, 68, 0.5)',
            boxShadow: 'var(--shadow-inner-glow), 0 0 12px rgba(239, 68, 68, 0.2)',
          };
        case 'filter':
          return {
            background: 'rgba(255, 255, 255, 0.04)',
            color: 'var(--text-secondary)',
            borderColor: 'var(--border-subtle)',
            fontSize: '0.75rem',
            padding: '0.3rem 0.65rem',
            height: '1.75rem',
          };
        case 'filter-active':
          return {
            background: 'rgba(99, 102, 241, 0.22)',
            color: '#ffffff',
            borderColor: 'var(--border-glass-hover)',
            borderTopColor: 'rgba(99, 102, 241, 0.6)',
            fontSize: '0.75rem',
            padding: '0.3rem 0.65rem',
            height: '1.75rem',
            boxShadow: '0 0 10px rgba(99, 102, 241, 0.3), var(--shadow-inner-glow)',
          };
        default:
          return {
            background: 'var(--accent-primary)',
            color: '#ffffff',
            borderColor: 'rgba(255, 255, 255, 0.18)',
            borderTopColor: 'rgba(255, 255, 255, 0.35)',
            boxShadow: '0 2px 12px rgba(99, 102, 241, 0.35), var(--shadow-inner-glow)',
            fontWeight: 600,
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
