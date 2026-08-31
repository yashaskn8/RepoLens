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
  | 'tag'
  | 'pill';

export interface BadgeProps {
  variant?: BadgeVariant;
  severity?: Severity;
  children: React.ReactNode;
  className?: string;
  style?: React.CSSProperties;
}

export const Badge: React.FC<BadgeProps> = ({
  variant,
  severity,
  children,
  className = '',
  style,
}) => {
  let resolvedVariant = variant || 'default';

  if (severity) {
    switch (severity) {
      case 'CRITICAL':
        resolvedVariant = 'critical';
        break;
      case 'HIGH':
        resolvedVariant = 'high';
        break;
      case 'MEDIUM':
        resolvedVariant = 'medium';
        break;
      case 'LOW':
        resolvedVariant = 'low';
        break;
      default:
        resolvedVariant = 'info';
    }
  }

  const getVariantClass = () => {
    switch (resolvedVariant) {
      case 'critical':
        return 'badge badge-critical';
      case 'high':
        return 'badge badge-high';
      case 'medium':
        return 'badge badge-medium';
      case 'low':
        return 'badge badge-low';
      case 'info':
        return 'badge badge-info';
      case 'success':
        return 'badge badge-success';
      case 'tag':
        return 'badge-tag';
      case 'pill':
        return 'pill-tag';
      default:
        return 'badge badge-info';
    }
  };

  return (
    <span className={`${getVariantClass()} ${className}`} style={style}>
      {children}
    </span>
  );
};
