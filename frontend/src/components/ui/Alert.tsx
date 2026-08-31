import React from 'react';

export type AlertVariant = 'error' | 'warning' | 'info' | 'success';

export interface AlertProps {
  variant?: AlertVariant;
  title?: string;
  children: React.ReactNode;
  className?: string;
  icon?: React.ReactNode;
}

const defaultIcons: Record<AlertVariant, string> = {
  error: '⚠️',
  warning: '⚡',
  info: 'ℹ️',
  success: '✅',
};

export const Alert: React.FC<AlertProps> = ({
  variant = 'info',
  title,
  children,
  className = '',
  icon,
}) => {
  const iconToRender = icon !== undefined ? icon : defaultIcons[variant];

  return (
    <div
      role={variant === 'error' ? 'alert' : 'status'}
      aria-live={variant === 'error' ? 'assertive' : 'polite'}
      className={`alert alert-${variant} ${className}`}
    >
      {iconToRender && <span className="shrink-0 text-sm select-none">{iconToRender}</span>}
      <div className="flex-1">
        {title && <div className="font-semibold text-sm mb-0.5">{title}</div>}
        <div className="text-xs leading-relaxed">{children}</div>
      </div>
    </div>
  );
};
