import React from 'react';
import { HealthResponse } from '@/types/domain';

export interface ServiceStatusProps {
  health: HealthResponse | null;
  isLoading?: boolean;
}

export const ServiceStatus: React.FC<ServiceStatusProps> = ({ health, isLoading = false }) => {
  if (isLoading) {
    return (
      <span className="status-badge" role="status" aria-label="Connecting to backend">
        <span className="w-2 h-2 rounded-full bg-amber-400 animate-pulse" />
        Connecting...
      </span>
    );
  }

  if (health) {
    return (
      <span className="status-badge" role="status" aria-label={`Backend service ${health.service} version ${health.version} online, database ${health.database}`}>
        <span className="status-dot" aria-hidden="true" />
        {health.service} v{health.version} ({health.database})
      </span>
    );
  }

  return (
    <span className="status-badge status-badge-offline" role="status" aria-label="Backend offline">
      <span className="w-2 h-2 rounded-full bg-red-400" aria-hidden="true" />
      Backend offline
    </span>
  );
};
