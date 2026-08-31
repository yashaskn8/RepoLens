'use client';

import React from 'react';

export interface SkeletonProps extends React.HTMLAttributes<HTMLDivElement> {
  width?: string | number;
  height?: string | number;
  borderRadius?: string;
}

export function Skeleton({
  width = '100%',
  height = '1.25rem',
  borderRadius = 'var(--radius-sm)',
  className = '',
  style,
  ...props
}: SkeletonProps) {
  return (
    <div
      className={`animate-shimmer ${className}`}
      style={{
        width,
        height,
        borderRadius,
        backgroundColor: 'rgba(255, 255, 255, 0.05)',
        border: '1px solid rgba(255, 255, 255, 0.03)',
        ...style,
      }}
      {...props}
    />
  );
}

export function CardSkeleton() {
  return (
    <div
      className="glass-panel"
      style={{
        padding: '1.5rem',
        display: 'flex',
        flexDirection: 'column',
        gap: '1rem',
      }}
    >
      <div style={{ display: 'flex', justifyContent: 'space-between' }}>
        <Skeleton width="40%" height="1rem" />
        <Skeleton width="20%" height="1.25rem" borderRadius="var(--radius-full)" />
      </div>
      <Skeleton width="85%" height="1.5rem" />
      <Skeleton width="100%" height="3rem" />
      <div style={{ display: 'flex', gap: '0.75rem', marginTop: '0.5rem' }}>
        <Skeleton width="30%" height="0.875rem" />
        <Skeleton width="25%" height="0.875rem" />
      </div>
    </div>
  );
}
