'use client';

import React from 'react';

export interface StatusIndicatorProps {
  status: 'healthy' | 'degraded' | 'running' | 'completed' | 'failed' | 'pending' | 'active';
  label?: string;
  pulse?: boolean;
  size?: 'sm' | 'md';
}

export function StatusIndicator({
  status,
  label,
  pulse = true,
  size = 'md',
}: StatusIndicatorProps) {
  const getColors = () => {
    switch (status) {
      case 'healthy':
      case 'completed':
        return { dot: 'var(--success)', glow: 'rgba(16, 185, 129, 0.4)', text: 'var(--success-text)' };
      case 'degraded':
      case 'pending':
        return { dot: 'var(--warning)', glow: 'rgba(245, 158, 11, 0.4)', text: 'var(--warning-text)' };
      case 'failed':
        return { dot: 'var(--error)', glow: 'rgba(239, 68, 68, 0.4)', text: 'var(--error-text)' };
      case 'running':
      case 'active':
        return { dot: 'var(--accent-cyan)', glow: 'rgba(56, 189, 248, 0.5)', text: '#38bdf8' };
      default:
        return { dot: 'var(--text-muted)', glow: 'rgba(255, 255, 255, 0.1)', text: 'var(--text-muted)' };
    }
  };

  const { dot, glow, text } = getColors();
  const dotSize = size === 'sm' ? '6px' : '8px';

  return (
    <span
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: '0.45rem',
        fontSize: size === 'sm' ? '0.75rem' : '0.8125rem',
        fontWeight: 500,
        fontFamily: 'var(--font-mono)',
        color: text,
      }}
    >
      <span
        style={{
          width: dotSize,
          height: dotSize,
          borderRadius: '50%',
          backgroundColor: dot,
          boxShadow: pulse ? `0 0 10px ${glow}` : 'none',
          animation: pulse ? 'pulse-glow 2s infinite' : 'none',
          flexShrink: 0,
        }}
      />
      {label && <span>{label}</span>}
    </span>
  );
}
