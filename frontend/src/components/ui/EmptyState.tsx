import React from 'react';

export interface EmptyStateProps {
  icon?: string | React.ReactNode;
  title?: string;
  description?: string | React.ReactNode;
  action?: React.ReactNode;
  className?: string;
}

export const EmptyState: React.FC<EmptyStateProps> = ({
  icon = '🔍',
  title,
  description,
  action,
  className = '',
}) => {
  return (
    <div className={`empty-state ${className}`}>
      {icon && (
        <div className="empty-state-icon" aria-hidden="true">
          {icon}
        </div>
      )}
      {title && (
        <h4 className="text-base font-semibold text-slate-200 mb-1">
          {title}
        </h4>
      )}
      {description && (
        <div className="text-xs text-slate-400 max-w-md mx-auto leading-relaxed">
          {description}
        </div>
      )}
      {action && <div className="mt-4">{action}</div>}
    </div>
  );
};
