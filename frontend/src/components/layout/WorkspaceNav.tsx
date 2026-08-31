import React from 'react';

export type WorkspaceMode = 'LANDING' | 'SCAN' | 'CHANGE_ANALYSIS' | 'ARCHITECTURE';

export interface WorkspaceNavProps {
  currentMode: WorkspaceMode;
  onModeChange: (mode: WorkspaceMode) => void;
}

export const WorkspaceNav: React.FC<WorkspaceNavProps> = ({ currentMode, onModeChange }) => {
  return (
    <nav className="workspace-nav" aria-label="Workspace Mode Navigation">
      <button
        type="button"
        role="tab"
        aria-selected={currentMode === 'LANDING'}
        className={`filter-btn workspace-nav-btn ${currentMode === 'LANDING' ? 'filter-btn-active' : ''}`}
        onClick={() => onModeChange('LANDING')}
      >
        <span aria-hidden="true">🏠</span> Overview
      </button>
      <button
        type="button"
        role="tab"
        aria-selected={currentMode === 'SCAN'}
        className={`filter-btn workspace-nav-btn ${currentMode === 'SCAN' ? 'filter-btn-active' : ''}`}
        onClick={() => onModeChange('SCAN')}
      >
        <span aria-hidden="true">🛡️</span> Security &amp; AST Scan
      </button>
      <button
        type="button"
        role="tab"
        aria-selected={currentMode === 'CHANGE_ANALYSIS'}
        className={`filter-btn workspace-nav-btn ${currentMode === 'CHANGE_ANALYSIS' ? 'filter-btn-active' : ''}`}
        onClick={() => onModeChange('CHANGE_ANALYSIS')}
      >
        <span aria-hidden="true">🔍</span> Change Intelligence &amp; PR
      </button>
      <button
        type="button"
        role="tab"
        aria-selected={currentMode === 'ARCHITECTURE'}
        className={`filter-btn workspace-nav-btn ${currentMode === 'ARCHITECTURE' ? 'filter-btn-active' : ''}`}
        onClick={() => onModeChange('ARCHITECTURE')}
      >
        <span aria-hidden="true">🏗️</span> Architecture Engine
      </button>
    </nav>
  );
};

