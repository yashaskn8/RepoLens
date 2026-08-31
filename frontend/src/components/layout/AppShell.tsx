import React from 'react';

export interface AppShellProps {
  children: React.ReactNode;
  className?: string;
}

export const AppShell: React.FC<AppShellProps> = ({ children, className = '' }) => {
  return (
    <>
      {/* Background Ambient Glow Orbs */}
      <div className="ambient-glow-wrapper" aria-hidden="true">
        <div className="ambient-orb ambient-orb-1" />
        <div className="ambient-orb ambient-orb-2" />
        <div className="ambient-orb ambient-orb-3" />
      </div>

      <main className={`container ${className}`} id="main-content">
        {children}
      </main>
    </>
  );
};

