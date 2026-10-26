'use client';

import React, { useEffect, useRef, useState } from 'react';
import { Finding, Scan, ScanTelemetry } from '@/types/domain';
import { fetchScan, fetchScanFindings, fetchScanTelemetry, startScan } from '@/lib/api';
import { WorkspaceMode } from '@/components/layout/WorkspaceNav';
import { RepositoryScanForm } from './RepositoryScanForm';
import { ScanStatusPanel } from './ScanStatusPanel';
import { ScanOverview } from './ScanOverview';
import { ScanTelemetryPanel } from './ScanTelemetryPanel';
import { FindingsList } from '@/features/findings/FindingsList';
import { WorkflowTimeline } from '@/components/WorkflowTimeline';
import { Alert } from '@/components/ui/Alert';

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
  const [findingsLoaded, setFindingsLoaded] = useState(false);
  const [artifactError, setArtifactError] = useState<string | null>(null);
  const scanGenerationRef = useRef(0);
  // React state cannot synchronously prevent a second submit in the same render.
  const scanSubmissionPendingRef = useRef(false);

  // Sync initialRepoUrl / initialBranch when changed externally (e.g. from preset click)
  useEffect(() => {
    if (initialRepoUrl) setRepoUrl(initialRepoUrl);
    if (initialBranch) setBranch(initialBranch);
  }, [initialRepoUrl, initialBranch]);

  // Keep one poller per scan identity, not per status object. A transition to
  // COMPLETED must not cancel the still-pending findings/telemetry fetch.
  useEffect(() => {
    const scanId = activeScan?.id;
    if (!scanId) return;

    const generation = scanGenerationRef.current;
    let stopped = false;
    let retryTimer: ReturnType<typeof setTimeout> | undefined;
    let artifactAttempts = 0;
    const isCurrent = () => !stopped && generation === scanGenerationRef.current;

    const poll = async () => {
      if (!isCurrent()) return;
      let retry = true;
      try {
        const updated = await fetchScan(scanId);
        if (!isCurrent()) return;
        setActiveScan((current) => current?.id === scanId ? updated : current);

        if (updated.status === 'COMPLETED' || updated.status === 'FAILED') {
          const [findingsResult, telemetryResult] = await Promise.allSettled([
            updated.status === 'COMPLETED' ? fetchScanFindings(scanId) : Promise.resolve([]),
            fetchScanTelemetry(scanId),
          ]);
          if (!isCurrent()) return;
          if (updated.status === 'COMPLETED') {
            if (findingsResult.status === 'fulfilled') {
              setFindings(findingsResult.value);
              setFindingsLoaded(true);
              setArtifactError(null);
            } else {
              artifactAttempts += 1;
              setArtifactError('Scan completed, but the findings endpoint could not be loaded. Results are unknown.');
            }
          }
          if (telemetryResult.status === 'fulfilled') setTelemetry(telemetryResult.value);
          retry = updated.status === 'COMPLETED'
            && findingsResult.status === 'rejected'
            && artifactAttempts < 3;
        }
      } catch (err: unknown) {
        if (isCurrent()) console.error('Polling error for scan:', err);
      }
      if (isCurrent() && retry) retryTimer = setTimeout(poll, 2000);
    };

    void poll();
    return () => {
      stopped = true;
      if (retryTimer) clearTimeout(retryTimer);
    };
  }, [activeScan?.id]);


  const handleStartScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!repoUrl.trim() || scanSubmissionPendingRef.current || isScanRunning) return;
    scanSubmissionPendingRef.current = true;

    const generation = ++scanGenerationRef.current;
    let scanStillRunning = false;
    setErrorMsg(null);
    setIsSubmitting(true);
    setActiveScan(null);
    setFindings([]);
    setFindingsLoaded(false);
    setArtifactError(null);
    setTelemetry(null);

    try {
      const scan = await startScan({
        repository_url: repoUrl.trim(),
        branch: branch.trim() || 'main',
      });
      if (generation === scanGenerationRef.current) {
        // Keep the synchronous guard until React observes the running scan.
        scanStillRunning = scan.status === 'PENDING' || scan.status === 'RUNNING';
        setActiveScan(scan);
      }
    } catch (err: unknown) {
      if (generation === scanGenerationRef.current) {
        setErrorMsg(err instanceof Error ? err.message : 'Failed to initiate scan.');
      }
    } finally {
      scanSubmissionPendingRef.current = scanStillRunning;
      if (generation === scanGenerationRef.current) setIsSubmitting(false);
    }
  };

  const isScanRunning = Boolean(
    activeScan && (activeScan.status === 'PENDING' || activeScan.status === 'RUNNING')
  );

  useEffect(() => {
    // A terminal scan releases the guard; another scan may then be requested.
    if (!isScanRunning) scanSubmissionPendingRef.current = false;
  }, [isScanRunning]);

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

      {/* Never interpret a missing findings response as an empty result set. */}
      {activeScan?.status === 'COMPLETED' && artifactError && !findingsLoaded && (
        <Alert variant="error" title="Findings unavailable">{artifactError}</Alert>
      )}

      {/* Findings List & Remediation Workbench */}
      {activeScan?.status === 'COMPLETED' && findingsLoaded && (
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

