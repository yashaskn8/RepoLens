'use client';

import React, { useEffect, useState } from 'react';
import { Finding, Scan, ScanTelemetry } from '@/types/domain';
import { fetchScan, fetchScanFindings, fetchScanTelemetry, startScan } from '@/lib/api';
import { WorkspaceMode } from '@/components/layout/WorkspaceNav';
import { RepositoryScanForm } from './RepositoryScanForm';
import { ScanStatusPanel } from './ScanStatusPanel';
import { ScanOverview } from './ScanOverview';
import { ScanTelemetryPanel } from './ScanTelemetryPanel';
import { FindingsList } from '@/features/findings/FindingsList';
import { WorkflowTimeline } from '@/components/WorkflowTimeline';

export interface RepositoryScanWorkspaceProps {
  initialRepoUrl?: string;
  initialBranch?: string;
  onNavigate?: (mode: WorkspaceMode) => void;
}

export function RepositoryScanWorkspace({
  initialRepoUrl,
  initialBranch,
  onNavigate,
}: RepositoryScanWorkspaceProps) {
  const [repoUrl, setRepoUrl] = useState<string>(
    initialRepoUrl || 'https://github.com/yashaskn8/RepoLens'
  );
  const [branch, setBranch] = useState<string>(initialBranch || 'main');
  const [activeScan, setActiveScan] = useState<Scan | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [isSubmitting, setIsSubmitting] = useState<boolean>(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [expandedFindingId, setExpandedFindingId] = useState<string | null>(null);
  const [telemetry, setTelemetry] = useState<ScanTelemetry | null>(null);

  // Sync initialRepoUrl / initialBranch when changed externally (e.g. from preset click)
  useEffect(() => {
    if (initialRepoUrl) setRepoUrl(initialRepoUrl);
    if (initialBranch) setBranch(initialBranch);
  }, [initialRepoUrl, initialBranch]);

  // Poll active scan status every 2 seconds
  useEffect(() => {
    if (!activeScan || activeScan.status === 'COMPLETED' || activeScan.status === 'FAILED') {
      return;
    }

    const interval = setInterval(async () => {
      try {
        const updated = await fetchScan(activeScan.id);
        setActiveScan(updated);

        if (updated.status === 'COMPLETED' || updated.status === 'FAILED') {
          if (updated.status === 'COMPLETED') {
            const scanFindings = await fetchScanFindings(updated.id);
            setFindings(scanFindings);
          }
          fetchScanTelemetry(updated.id).then(setTelemetry).catch(() => setTelemetry(null));
        }
      } catch (err: unknown) {
        console.error('Polling error for scan:', err);
      }
    }, 2000);

    return () => clearInterval(interval);
  }, [activeScan]);


  const handleStartScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!repoUrl.trim()) return;

    setErrorMsg(null);
    setIsSubmitting(true);
    setFindings([]);
    setTelemetry(null);

    try {
      const scan = await startScan({
        repository_url: repoUrl.trim(),
        branch: branch.trim() || 'main',
      });
      setActiveScan(scan);
    } catch (err: unknown) {
      if (err instanceof Error) {
        setErrorMsg(err.message);
      } else {
        setErrorMsg('Failed to initiate scan.');
      }
    } finally {
      setIsSubmitting(false);
    }
  };

  const isScanRunning = Boolean(
    activeScan && (activeScan.status === 'PENDING' || activeScan.status === 'RUNNING')
  );

  return (
    <div className="page-view-enter">
      {/* Top Workspace Breadcrumbs & Switcher */}
      <div className="view-top-bar">
        <div className="flex items-center gap-3">
          {onNavigate && (
            <button
              type="button"
              className="back-to-home-btn"
              onClick={() => onNavigate('LANDING')}
              title="Return to Overview"
            >
              ← Back to Overview
            </button>
          )}
          <div className="flex items-center gap-2">
            <span className="text-sm font-bold text-white">Security &amp; AST Scan Workspace</span>
            <span className="badge-tag text-[10px] text-cyan-300 border-cyan-500/30">Active Mode</span>
          </div>
        </div>

        {onNavigate && (
          <div className="flex items-center gap-2">
            <button
              type="button"
              className="filter-btn text-xs"
              onClick={() => onNavigate('CHANGE_ANALYSIS')}
            >
              🔍 PR Change Intelligence →
            </button>
            <button
              type="button"
              className="filter-btn text-xs"
              onClick={() => onNavigate('ARCHITECTURE')}
            >
              🏗️ Architecture Flow →
            </button>
          </div>
        )}
      </div>

      {/* Scan Input Form */}
      <RepositoryScanForm
        repoUrl={repoUrl}
        onRepoUrlChange={setRepoUrl}
        branch={branch}
        onBranchChange={setBranch}
        onSubmit={handleStartScan}
        isSubmitting={isSubmitting}
        isScanRunning={isScanRunning}
        errorMsg={errorMsg}
      />

      {/* Active Scan Progress & Metadata */}
      {activeScan && <ScanStatusPanel scan={activeScan} />}

      {/* Real-time Workflow Stream Timeline */}
      {activeScan && (
        <div className="mb-8">
          <WorkflowTimeline scanId={activeScan.id} />
        </div>
      )}

      {/* Completed Architecture Overview */}
      {activeScan?.status === 'COMPLETED' && <ScanOverview scan={activeScan} />}

      {/* Execution Telemetry & Diagnostics */}
      {telemetry && <ScanTelemetryPanel telemetry={telemetry} />}

      {/* Findings List & Remediation Workbench */}
      {activeScan?.status === 'COMPLETED' && (
        <FindingsList
          findings={findings}
          severityFilter={severityFilter}
          onSeverityFilterChange={setSeverityFilter}
          expandedFindingId={expandedFindingId}
          onToggleExpand={(id) => setExpandedFindingId(expandedFindingId === id ? null : id)}
        />
      )}
    </div>
  );
}

