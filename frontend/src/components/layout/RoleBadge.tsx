import React from 'react';
import { UserRole } from '@/types/domain';

export interface RoleBadgeProps {
  role?: UserRole | string;
  className?: string;
}

export const RoleBadge: React.FC<RoleBadgeProps> = ({ role, className = '' }) => {
  if (!role) return null;

  if (role === 'OPERATOR') {
    return (
      <span
        aria-label="User role: OPERATOR"
        className={`role-badge-operator ${className}`}
      >
        OPERATOR
      </span>
    );
  }

  return (
    <span
      aria-label="User role: USER"
      className={`role-badge-user ${className}`}
    >
      USER
    </span>
  );
};
