'use client';

import React from 'react';

export interface TabItem {
  id: string;
  label: string;
  count?: number;
  icon?: React.ReactNode;
}

export interface TabsProps {
  tabs: TabItem[];
  activeTab: string;
  onChange: (id: string) => void;
  className?: string;
  variant?: 'pill' | 'underline' | 'boxed';
}

export function Tabs({ tabs, activeTab, onChange, className = '', variant = 'boxed' }: TabsProps) {
  if (variant === 'underline') {
    return (
      <div
        style={{
          display: 'flex',
          gap: '1.25rem',
          borderBottom: '1px solid var(--border-subtle)',
          overflowX: 'auto',
        }}
        className={className}
      >
        {tabs.map((tab) => {
          const isActive = tab.id === activeTab;
          return (
            <button
              key={tab.id}
              type="button"
              onClick={() => onChange(tab.id)}
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '0.45rem',
                padding: '0.75rem 0.25rem',
                fontSize: '0.875rem',
                fontWeight: isActive ? 600 : 500,
                color: isActive ? '#ffffff' : 'var(--text-secondary)',
                background: 'transparent',
                border: 'none',
                borderBottom: isActive ? '2px solid var(--accent-primary)' : '2px solid transparent',
                marginBottom: '-1px',
                cursor: 'pointer',
                transition: 'all var(--transition-fast)',
                whiteSpace: 'nowrap',
              }}
            >
              {tab.icon && <span style={{ display: 'inline-flex', alignItems: 'center' }}>{tab.icon}</span>}
              {tab.label}
              {tab.count !== undefined && (
                <span
                  style={{
                    fontSize: '0.7rem',
                    padding: '0.1rem 0.45rem',
                    borderRadius: 'var(--radius-full)',
                    background: isActive ? 'rgba(99, 102, 241, 0.25)' : 'rgba(255, 255, 255, 0.08)',
                    color: isActive ? 'var(--accent-cyan)' : 'var(--text-muted)',
                    fontWeight: 600,
                  }}
                >
                  {tab.count}
                </span>
              )}
            </button>
          );
        })}
      </div>
    );
  }

  return (
    <div
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        padding: '0.2rem',
        background: 'rgba(9, 13, 24, 0.85)',
        border: '1px solid var(--border-glass)',
        borderRadius: 'var(--radius-md)',
        gap: '0.2rem',
        overflowX: 'auto',
        maxWidth: '100%',
        boxShadow: 'var(--shadow-inner-glow)',
      }}
      className={className}
    >
      {tabs.map((tab) => {
        const isActive = tab.id === activeTab;
        return (
          <button
            key={tab.id}
            type="button"
            onClick={() => onChange(tab.id)}
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '0.45rem',
              padding: '0.4rem 0.85rem',
              fontSize: '0.8125rem',
              fontWeight: isActive ? 600 : 500,
              fontFamily: 'var(--font-sans)',
              color: isActive ? '#ffffff' : 'var(--text-secondary)',
              background: isActive ? 'var(--accent-primary)' : 'transparent',
              borderRadius: 'calc(var(--radius-md) - 2px)',
              border: 'none',
              cursor: 'pointer',
              transition: 'all var(--transition-fast)',
              boxShadow: isActive ? '0 2px 8px rgba(99, 102, 241, 0.4), var(--shadow-inner-glow)' : 'none',
              whiteSpace: 'nowrap',
            }}
          >
            {tab.icon && <span style={{ display: 'inline-flex', alignItems: 'center' }}>{tab.icon}</span>}
            {tab.label}
            {tab.count !== undefined && (
              <span
                style={{
                  fontSize: '0.7rem',
                  padding: '0.1rem 0.45rem',
                  borderRadius: 'var(--radius-full)',
                  background: isActive ? 'rgba(255, 255, 255, 0.22)' : 'rgba(255, 255, 255, 0.08)',
                  color: isActive ? '#ffffff' : 'var(--text-muted)',
                  fontWeight: 600,
                }}
              >
                {tab.count}
              </span>
            )}
          </button>
        );
      })}
    </div>
  );
}
