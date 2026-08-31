'use client';

import React, { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import {
  Search,
  Scan,
  GitPullRequest,
  ShieldAlert,
  Wrench,
  User,
  LayoutDashboard,
  ExternalLink,
  Layers,
  ArrowRight,
} from 'lucide-react';

interface CommandItem {
  id: string;
  title: string;
  category: string;
  icon: React.ReactNode;
  action: () => void;
  shortcut?: string;
}

export function CommandPalette() {
  const [isOpen, setIsOpen] = useState(false);
  const [search, setSearch] = useState('');
  const [selectedIndex, setSelectedIndex] = useState(0);
  const router = useRouter();

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        setIsOpen((prev) => !prev);
      } else if (e.key === 'Escape' && isOpen) {
        setIsOpen(false);
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen]);

  const items: CommandItem[] = [
    {
      id: 'dashboard',
      title: 'Go to Dashboard',
      category: 'Navigation',
      icon: <LayoutDashboard size={16} />,
      action: () => {
        router.push('/dashboard');
        setIsOpen(false);
      },
      shortcut: 'G D',
    },
    {
      id: 'scan',
      title: 'Repository Scan Workspace',
      category: 'Navigation',
      icon: <Scan size={16} />,
      action: () => {
        router.push('/scan');
        setIsOpen(false);
      },
      shortcut: 'G S',
    },
    {
      id: 'change-analysis',
      title: 'Change & PR Impact Intelligence',
      category: 'Navigation',
      icon: <GitPullRequest size={16} />,
      action: () => {
        router.push('/change-analysis');
        setIsOpen(false);
      },
      shortcut: 'G C',
    },
    {
      id: 'findings',
      title: 'Findings & Vulnerabilities Explorer',
      category: 'Navigation',
      icon: <ShieldAlert size={16} />,
      action: () => {
        router.push('/findings');
        setIsOpen(false);
      },
      shortcut: 'G F',
    },
    {
      id: 'remediation',
      title: 'Human-in-the-Loop Remediation',
      category: 'Navigation',
      icon: <Wrench size={16} />,
      action: () => {
        router.push('/remediation');
        setIsOpen(false);
      },
      shortcut: 'G R',
    },
    {
      id: 'account',
      title: 'User Profile & Permissions',
      category: 'Account',
      icon: <User size={16} />,
      action: () => {
        router.push('/account');
        setIsOpen(false);
      },
    },
    {
      id: 'landing',
      title: 'Landing Page & Architecture Overview',
      category: 'Explore',
      icon: <Layers size={16} />,
      action: () => {
        router.push('/');
        setIsOpen(false);
      },
    },
  ];

  const filteredItems = items.filter((item) =>
    item.title.toLowerCase().includes(search.toLowerCase()) ||
    item.category.toLowerCase().includes(search.toLowerCase())
  );

  useEffect(() => {
    setSelectedIndex(0);
  }, [search]);

  if (!isOpen) return null;

  return (
    <div
      style={{
        position: 'fixed',
        inset: 0,
        zIndex: 100,
        display: 'flex',
        alignItems: 'flex-start',
        justifyContent: 'center',
        paddingTop: '15vh',
        paddingLeft: '1rem',
        paddingRight: '1rem',
      }}
      role="dialog"
      aria-modal="true"
    >
      {/* Backdrop */}
      <div
        style={{
          position: 'fixed',
          inset: 0,
          backgroundColor: 'rgba(3, 5, 12, 0.85)',
          backdropFilter: 'blur(10px)',
          WebkitBackdropFilter: 'blur(10px)',
        }}
        onClick={() => setIsOpen(false)}
      />

      {/* Palette Box */}
      <div
        className="glass-modal page-enter"
        style={{
          position: 'relative',
          width: '100%',
          maxWidth: '38rem',
          backgroundColor: 'rgba(10, 15, 30, 0.96)',
          border: '1px solid var(--border-glass)',
          borderRadius: 'var(--radius-xl)',
          overflow: 'hidden',
          boxShadow: '0 25px 60px rgba(0, 0, 0, 0.8), 0 0 30px rgba(99, 102, 241, 0.2)',
          zIndex: 101,
        }}
      >
        {/* Search Header */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '0.75rem',
            padding: '1rem 1.25rem',
            borderBottom: '1px solid var(--border-subtle)',
          }}
        >
          <Search size={18} style={{ color: 'var(--text-muted)' }} />
          <input
            type="text"
            autoFocus
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Type a command or jump to page..."
            style={{
              flex: 1,
              background: 'transparent',
              border: 'none',
              outline: 'none',
              fontSize: '1rem',
              fontFamily: 'var(--font-sans)',
              color: 'var(--text-primary)',
            }}
          />
          <span
            style={{
              fontSize: '0.7rem',
              fontFamily: 'var(--font-mono)',
              padding: '0.2rem 0.5rem',
              borderRadius: 'var(--radius-sm)',
              background: 'rgba(255, 255, 255, 0.08)',
              color: 'var(--text-muted)',
            }}
          >
            ESC
          </span>
        </div>

        {/* Results List */}
        <div style={{ maxHeight: '22rem', overflowY: 'auto', padding: '0.5rem' }}>
          {filteredItems.length === 0 ? (
            <div style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-muted)', fontSize: '0.875rem' }}>
              No commands found for "{search}"
            </div>
          ) : (
            filteredItems.map((item, index) => {
              const isSelected = index === selectedIndex;
              return (
                <div
                  key={item.id}
                  onClick={item.action}
                  onMouseEnter={() => setSelectedIndex(index)}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    padding: '0.75rem 1rem',
                    borderRadius: 'var(--radius-md)',
                    cursor: 'pointer',
                    background: isSelected ? 'rgba(99, 102, 241, 0.16)' : 'transparent',
                    border: isSelected ? '1px solid var(--border-glass-hover)' : '1px solid transparent',
                    transition: 'all var(--transition-fast)',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.85rem' }}>
                    <div
                      style={{
                        color: isSelected ? 'var(--accent-cyan)' : 'var(--text-secondary)',
                        display: 'flex',
                        alignItems: 'center',
                      }}
                    >
                      {item.icon}
                    </div>
                    <div>
                      <div
                        style={{
                          fontSize: '0.875rem',
                          fontWeight: 500,
                          color: isSelected ? '#ffffff' : 'var(--text-primary)',
                        }}
                      >
                        {item.title}
                      </div>
                      <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>
                        {item.category}
                      </div>
                    </div>
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    {item.shortcut && (
                      <span
                        style={{
                          fontSize: '0.7rem',
                          fontFamily: 'var(--font-mono)',
                          color: 'var(--text-muted)',
                          padding: '0.15rem 0.4rem',
                          borderRadius: 'var(--radius-xs)',
                          background: 'rgba(255, 255, 255, 0.05)',
                        }}
                      >
                        {item.shortcut}
                      </span>
                    )}
                    {isSelected && <ArrowRight size={14} style={{ color: 'var(--accent-primary)' }} />}
                  </div>
                </div>
              );
            })
          )}
        </div>

        {/* Footer info */}
        <div
          style={{
            padding: '0.6rem 1.25rem',
            borderTop: '1px solid var(--border-subtle)',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            fontSize: '0.75rem',
            color: 'var(--text-muted)',
            background: 'rgba(5, 8, 18, 0.5)',
          }}
        >
          <span>Navigate with arrows, select with Enter</span>
          <span style={{ fontFamily: 'var(--font-mono)' }}>RepoLens Command v1.0</span>
        </div>
      </div>
    </div>
  );
}
