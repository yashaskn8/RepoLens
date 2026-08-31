'use client';

import React, { useEffect, useState } from 'react';
import { HealthResponse } from '@/types/domain';
import { fetchHealth } from '@/lib/api';
import { AppShell } from '@/components/layout/AppShell';
import { AppHeader } from '@/components/layout/AppHeader';
import { AppFooter } from '@/components/layout/AppFooter';
import { WorkspaceMode } from '@/components/layout/WorkspaceNav';
import { AuthModal } from '@/components/auth/AuthModal';
import { LandingHero } from '@/features/landing/LandingHero';
import { LandingFeatures } from '@/features/landing/LandingFeatures';
import { ArchitecturePipeline } from '@/features/landing/ArchitecturePipeline';
import { RepositoryScanWorkspace } from '@/features/scan/RepositoryScanWorkspace';
import { ChangeAnalysisExperience } from '@/components/ChangeAnalysisExperience';

export default function HomePage() {
  const [isAuthModalOpen, setIsAuthModalOpen] = useState<boolean>(false);
  const [appMode, setAppMode] = useState<WorkspaceMode>('LANDING');
  const [selectedRepoUrl, setSelectedRepoUrl] = useState<string>('https://github.com/yashaskn8/RepoLens');
  const [selectedBranch, setSelectedBranch] = useState<string>('main');
  const [health, setHealth] = useState<HealthResponse | null>(null);

  // Initial health check
  useEffect(() => {
    fetchHealth()
      .then((data) => setHealth(data))
      .catch(() => setHealth(null));
  }, []);

  const handleSelectPreset = (url: string, branch: string) => {
    setSelectedRepoUrl(url);
    setSelectedBranch(branch);
    setAppMode('SCAN');
    if (typeof window !== 'undefined') {
      window.scrollTo({ top: 0, behavior: 'smooth' });
    }
  };

  const handleNavigate = (mode: WorkspaceMode) => {
    setAppMode(mode);
    if (typeof window !== 'undefined') {
      window.scrollTo({ top: 0, behavior: 'smooth' });
    }
  };

  return (
    <AppShell>
      {/* Top Application Navigation & Auth Header */}
      <AppHeader
        health={health}
        onOpenAuthModal={() => setIsAuthModalOpen(true)}
        currentMode={appMode}
        onModeChange={handleNavigate}
      />

      {/* Dynamic Multi-View Workspace Router */}
      <main id="main-content" className="w-full transition-all duration-300">
        {appMode === 'LANDING' && (
          <div className="page-view-enter">
            {/* Hero Header & Value Proposition + Action CTAs */}
            <LandingHero
              onNavigate={handleNavigate}
              onSelectPreset={handleSelectPreset}
            />

            {/* Architectural Capabilities & Interactive Feature Matrix */}
            <LandingFeatures onNavigate={handleNavigate} />
          </div>
        )}

        {appMode === 'SCAN' && (
          <div className="page-view-enter">
            <RepositoryScanWorkspace
              initialRepoUrl={selectedRepoUrl}
              initialBranch={selectedBranch}
              onNavigate={handleNavigate}
              onOpenAuthModal={() => setIsAuthModalOpen(true)}
            />
          </div>
        )}

        {appMode === 'CHANGE_ANALYSIS' && (
          <div className="page-view-enter">
            <ChangeAnalysisExperience
              onNavigate={handleNavigate}
              onOpenAuthModal={() => setIsAuthModalOpen(true)}
            />
          </div>
        )}

        {appMode === 'ARCHITECTURE' && (
          <div className="page-view-enter">
            <ArchitecturePipeline
              onNavigate={handleNavigate}
              isStandalonePage={true}
            />
          </div>
        )}
      </main>

      {/* Glassmorphism System Footer */}
      <AppFooter health={health} />

      {/* Authentication Dialog Modal */}
      <AuthModal
        isOpen={isAuthModalOpen}
        onClose={() => setIsAuthModalOpen(false)}
      />
    </AppShell>
  );
}


