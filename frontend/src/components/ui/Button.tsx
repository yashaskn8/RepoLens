import React from 'react';
import { Spinner } from './Spinner';

export type ButtonVariant = 'primary' | 'filter' | 'filter-active' | 'ghost' | 'outline' | 'danger';
export type ButtonSize = 'sm' | 'md' | 'lg';

export interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: ButtonSize;
  isLoading?: boolean;
  leftIcon?: React.ReactNode;
  rightIcon?: React.ReactNode;
}

export const Button: React.FC<ButtonProps> = ({
  children,
  variant = 'primary',
  size = 'md',
  isLoading = false,
  leftIcon,
  rightIcon,
  className = '',
  disabled,
  type = 'button',
  ...props
}) => {
  const getVariantClass = () => {
    switch (variant) {
      case 'primary':
        return 'btn-primary';
      case 'filter':
        return 'filter-btn';
      case 'filter-active':
        return 'filter-btn filter-btn-active';
      case 'outline':
        return 'filter-btn';
      case 'danger':
        return 'filter-btn bg-red-950/40 text-red-300 border-red-800/80 hover:bg-red-900/60';
      case 'ghost':
        return 'bg-transparent border-none text-slate-400 hover:text-slate-200 cursor-pointer';
      default:
        return 'btn-primary';
    }
  };

  const getSizeStyle = (): React.CSSProperties => {
    if (variant === 'filter' || variant === 'filter-active') {
      if (size === 'sm') return { padding: '0.25rem 0.6rem', fontSize: '0.75rem' };
      if (size === 'lg') return { padding: '0.65rem 1.25rem', fontSize: '0.95rem' };
      return {};
    }
    if (size === 'sm') return { padding: '0.4rem 0.85rem', fontSize: '0.8rem' };
    if (size === 'lg') return { padding: '0.85rem 1.75rem', fontSize: '1rem' };
    return {};
  };

  return (
    <button
      type={type}
      disabled={disabled || isLoading}
      className={`${getVariantClass()} ${className}`}
      style={getSizeStyle()}
      {...props}
    >
      {isLoading && <Spinner size="sm" />}
      {!isLoading && leftIcon && <span className="shrink-0">{leftIcon}</span>}
      <span>{children}</span>
      {!isLoading && rightIcon && <span className="shrink-0">{rightIcon}</span>}
    </button>
  );
};
