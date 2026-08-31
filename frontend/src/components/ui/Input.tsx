'use client';

import React, { forwardRef, InputHTMLAttributes, SelectHTMLAttributes } from 'react';
import { Search, X } from 'lucide-react';

export interface InputProps extends InputHTMLAttributes<HTMLInputElement> {
  label?: string;
  error?: string;
  helperText?: string;
  leftIcon?: React.ReactNode;
  rightElement?: React.ReactNode;
}

export const Input = forwardRef<HTMLInputElement, InputProps>(
  (
    {
      label,
      error,
      helperText,
      leftIcon,
      rightElement,
      className = '',
      style,
      disabled,
      ...props
    },
    ref
  ) => {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem', width: '100%' }}>
        {label && (
          <label style={{ fontSize: '0.8125rem', fontWeight: 500, color: 'var(--text-light)' }}>
            {label}
          </label>
        )}
        <div style={{ position: 'relative', display: 'flex', alignItems: 'center', width: '100%' }}>
          {leftIcon && (
            <div
              style={{
                position: 'absolute',
                left: '0.875rem',
                display: 'flex',
                alignItems: 'center',
                color: 'var(--text-muted)',
                pointerEvents: 'none',
              }}
            >
              {leftIcon}
            </div>
          )}
          <input
            ref={ref}
            disabled={disabled}
            style={{
              width: '100%',
              height: '2.5rem',
              paddingLeft: leftIcon ? '2.5rem' : '0.875rem',
              paddingRight: rightElement ? '2.5rem' : '0.875rem',
              fontSize: '0.875rem',
              fontFamily: 'var(--font-sans)',
              color: 'var(--text-primary)',
              backgroundColor: 'var(--bg-input)',
              border: error ? '1px solid var(--error-border)' : '1px solid var(--border-glass)',
              borderRadius: 'var(--radius-md)',
              outline: 'none',
              transition: 'border-color var(--transition-fast), box-shadow var(--transition-fast)',
              opacity: disabled ? 0.6 : 1,
              ...style,
            }}
            className={`glass-input ${className}`}
            {...props}
          />
          {rightElement && (
            <div
              style={{
                position: 'absolute',
                right: '0.75rem',
                display: 'flex',
                alignItems: 'center',
              }}
            >
              {rightElement}
            </div>
          )}
        </div>
        {error ? (
          <span style={{ fontSize: '0.75rem', color: 'var(--error-text)' }}>{error}</span>
        ) : helperText ? (
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>{helperText}</span>
        ) : null}
      </div>
    );
  }
);

Input.displayName = 'Input';

export interface SearchInputProps extends InputHTMLAttributes<HTMLInputElement> {
  onClear?: () => void;
}

export function SearchInput({ value, onChange, onClear, placeholder = 'Search...', className = '', ...props }: SearchInputProps) {
  return (
    <Input
      leftIcon={<Search size={15} />}
      value={value}
      onChange={onChange}
      placeholder={placeholder}
      rightElement={
        value && onClear ? (
          <button
            type="button"
            onClick={onClear}
            style={{
              background: 'transparent',
              border: 'none',
              color: 'var(--text-muted)',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              padding: '0.2rem',
            }}
          >
            <X size={14} />
          </button>
        ) : undefined
      }
      className={className}
      {...props}
    />
  );
}

export interface SelectProps extends SelectHTMLAttributes<HTMLSelectElement> {
  label?: string;
  error?: string;
  options: { label: string; value: string }[];
}

export const Select = forwardRef<HTMLSelectElement, SelectProps>(
  ({ label, error, options, className = '', style, ...props }, ref) => {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem', width: '100%' }}>
        {label && (
          <label style={{ fontSize: '0.8125rem', fontWeight: 500, color: 'var(--text-light)' }}>
            {label}
          </label>
        )}
        <select
          ref={ref}
          style={{
            width: '100%',
            height: '2.5rem',
            padding: '0 0.875rem',
            fontSize: '0.875rem',
            fontFamily: 'var(--font-sans)',
            color: 'var(--text-primary)',
            backgroundColor: 'var(--bg-surface)',
            border: error ? '1px solid var(--error-border)' : '1px solid var(--border-glass)',
            borderRadius: 'var(--radius-md)',
            outline: 'none',
            cursor: 'pointer',
            ...style,
          }}
          className={className}
          {...props}
        >
          {options.map((opt) => (
            <option key={opt.value} value={opt.value} style={{ background: '#090d18', color: '#f8fafc' }}>
              {opt.label}
            </option>
          ))}
        </select>
        {error && <span style={{ fontSize: '0.75rem', color: 'var(--error-text)' }}>{error}</span>}
      </div>
    );
  }
);

Select.displayName = 'Select';
