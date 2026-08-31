import React from 'react';

export interface InputProps extends React.InputHTMLAttributes<HTMLInputElement> {
  label?: string;
  error?: string | null;
  helperText?: string;
}

export const Input = React.forwardRef<HTMLInputElement, InputProps>(
  ({ label, error, helperText, className = '', id, required, ...props }, ref) => {
    const inputId = id || (label ? `input-${label.toLowerCase().replace(/\s+/g, '-')}` : undefined);

    return (
      <div className="flex flex-col gap-1 w-full">
        {label && (
          <label htmlFor={inputId} className="text-xs font-medium text-slate-300">
            {label}
            {required && <span className="text-red-400 ml-0.5">*</span>}
          </label>
        )}
        <input
          ref={ref}
          id={inputId}
          required={required}
          className={`search-input ${error ? 'border-red-500/80 focus:ring-red-500/40' : ''} ${className}`}
          aria-invalid={error ? 'true' : 'false'}
          aria-describedby={error && inputId ? `${inputId}-error` : undefined}
          {...props}
        />
        {error && (
          <span id={inputId ? `${inputId}-error` : undefined} className="text-xs text-red-400">
            {error}
          </span>
        )}
        {!error && helperText && (
          <span className="text-xs text-slate-500">
            {helperText}
          </span>
        )}
      </div>
    );
  }
);

Input.displayName = 'Input';
