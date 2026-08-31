import React from 'react';
import { useAuth } from '@/context/AuthContext';
import { HealthResponse } from '@/types/domain';
import { WorkspaceMode } from './WorkspaceNav';
import { ServiceStatus } from './ServiceStatus';
import { RoleBadge } from './RoleBadge';
import { Button } from '@/components/ui/Button';

export interface AppHeaderProps {
  health: HealthResponse | null;
  onOpenAuthModal: () => void;
  currentMode?: WorkspaceMode;
  onModeChange?: (mode: WorkspaceMode) => void;
}

export const AppHeader: React.FC<AppHeaderProps> = ({
  health,
  onOpenAuthModal,
  currentMode = 'LANDING',
  onModeChange,
}) => {
  const { user, isAuthenticated, logout } = useAuth();

  return (
    <header className="header" role="banner">
      {/* Brand Icon & Title (Clickable) */}
      <button
        type="button"
        className="brand text-left cursor-pointer bg-transparent border-0 p-0"
        onClick={() => onModeChange?.('LANDING')}
        title="RepoLens - Home"
        aria-label="RepoLens Home"
      >
        <div className="brand-icon" aria-hidden="true">
          RL
        </div>
        <div>
          <div className="brand-title">RepoLens</div>
          <div className="brand-subtitle">AI Code Intelligence &amp; Security</div>
        </div>
      </button>

      {/* Primary Navigation Tabs */}
      {onModeChange && (
        <nav className="header-nav" aria-label="Main Navigation">
          <button
            type="button"
            className={`header-nav-btn ${currentMode === 'LANDING' ? 'header-nav-btn-active' : ''}`}
            onClick={() => onModeChange('LANDING')}
            title="Platform Overview"
          >
            <span aria-hidden="true">🏠</span> Overview
          </button>
          <button
            type="button"
            className={`header-nav-btn ${currentMode === 'SCAN' ? 'header-nav-btn-active' : ''}`}
            onClick={() => onModeChange('SCAN')}
            title="Security & AST Scan"
          >
            <span aria-hidden="true">🛡️</span> Security Scan
          </button>
          <button
            type="button"
            className={`header-nav-btn ${currentMode === 'CHANGE_ANALYSIS' ? 'header-nav-btn-active' : ''}`}
            onClick={() => onModeChange('CHANGE_ANALYSIS')}
            title="PR Change Intelligence & Blast Radius"
          >
            <span aria-hidden="true">🔍</span> Change Intelligence
          </button>
          <button
            type="button"
            className={`header-nav-btn ${currentMode === 'ARCHITECTURE' ? 'header-nav-btn-active' : ''}`}
            onClick={() => onModeChange('ARCHITECTURE')}
            title="4-Stage Pipeline Architecture"
          >
            <span aria-hidden="true">🏗️</span> Architecture
          </button>
        </nav>
      )}

      {/* Status & Auth Area */}
      <div className="flex items-center gap-3 flex-wrap">
        <ServiceStatus health={health} />

        {isAuthenticated ? (
          <div className="flex items-center gap-2">
            <span className="status-badge status-badge-user">
              <span aria-hidden="true">👤</span>
              <span className="truncate max-w-[180px]">{user?.email}</span>
              <RoleBadge role={user?.role} />
            </span>
            <Button
              variant="filter"
              size="sm"
              onClick={() => logout()}
              aria-label="Sign Out"
            >
              Sign Out
            </Button>
          </div>
        ) : (
          <Button
            variant="filter-active"
            size="sm"
            onClick={onOpenAuthModal}
            aria-label="Sign In"
          >
            Sign In
          </Button>
        )}
      </div>
    </header>
  );
};

