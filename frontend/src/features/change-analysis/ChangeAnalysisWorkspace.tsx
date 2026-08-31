'use client';

import React, { useEffect, useState } from 'react';
import {
  ChangeAnalysisReportResponse,
  ChangeAnalysisResponse,
  ChangeAnalysisTelemetry,
  ChangeImpact,
  ChangeReviewFinding,
  ConfigDelta,
  DependencyDelta,
  ReviewPublicationPreviewResponse,
  RouteContractDelta,
  SchemaModelDelta,
} from '@/types/domain';
import {
  approveReviewPublication,
  downloadChangeAnalysisMarkdown,
  fetchChangeAnalysis,
  fetchChangeAnalysisDiff,
  fetchChangeAnalysisImpacts,
  fetchChangeAnalysisReport,
  fetchChangeAnalysisReview,
  fetchChangeAnalysisTelemetry,
  fetchReviewPublication,
  generateReviewPublicationPreview,
  publishReviewPublication,
  startChangeAnalysis,
  startChangeAnalysisFromPR,
} from '@/lib/api';
import { useWorkflowStream } from '@/lib/useWorkflowStream';
import { Card } from '@/components/ui/Card';
import { Button } from '@/components/ui/Button';
import { ChangeAnalysisInput } from './ChangeAnalysisInput';
import { ChangeAnalysisStatus } from './ChangeAnalysisStatus';
import { ChangeSummary } from './ChangeSummary';
import { ImpactExplorer } from './ImpactExplorer';
import { ContractDeltasPanel } from './ContractDeltasPanel';
import { ChangeTelemetryPanel } from './ChangeTelemetryPanel';
import { ChangeReviewPanel } from '@/features/review/ChangeReviewPanel';
import { ReviewReportPanel } from '@/features/review/ReviewReportPanel';
import { ReviewPublicationPanel } from '@/features/review/ReviewPublicationPanel';
import { WorkspaceMode } from '@/components/layout/WorkspaceNav';
import { useAuth } from '@/context/AuthContext';

export interface ChangeAnalysisWorkspaceProps {
  onNavigate?: (mode: WorkspaceMode) => void;
  onOpenAuthModal?: () => void;
}

export function ChangeAnalysisWorkspace({ onNavigate, onOpenAuthModal }: ChangeAnalysisWorkspaceProps = {}) {
  const { isAuthenticated, login } = useAuth();
  // Input form state
  const [inputMode, setInputMode] = useState<'PR' | 'EXACT'>('PR');
  const [prUrl, setPrUrl] = useState<string>('https://github.com/fastapi/fastapi/pull/1234');
  const [repoUrl, setRepoUrl] = useState<string>('https://github.com/fastapi/fastapi');
  const [baseSha, setBaseSha] = useState<string>('');
  const [headSha, setHeadSha] = useState<string>('');
  const [baseRef, setBaseRef] = useState<string>('main');
  const [headRef, setHeadRef] = useState<string>('feature/auth-overhaul');

  const [isSubmitting, setIsSubmitting] = useState<boolean>(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  // Active Analysis state
  const [activeAnalysis, setActiveAnalysis] = useState<ChangeAnalysisResponse | null>(null);
  const [report, setReport] = useState<ChangeAnalysisReportResponse | null>(null);
  const [impacts, setImpacts] = useState<ChangeImpact[]>([]);
  const [reviewFindings, setReviewFindings] = useState<ChangeReviewFinding[]>([]);
  const [telemetry, setTelemetry] = useState<ChangeAnalysisTelemetry | null>(null);
  const [diffDeltas, setDiffDeltas] = useState<{
    route_deltas: RouteContractDelta[];
    schema_deltas: SchemaModelDelta[];
    dependency_deltas: DependencyDelta[];
    config_deltas: ConfigDelta[];
  }>({
    route_deltas: [],
    schema_deltas: [],
    dependency_deltas: [],
    config_deltas: [],
  });

  // Review publication state (Phase 7)
  const [publication, setPublication] = useState<ReviewPublicationPreviewResponse | null>(null);
  const [isGeneratingPreview, setIsGeneratingPreview] = useState<boolean>(false);
  const [isApprovingPub, setIsApprovingPub] = useState<boolean>(false);
  const [isPublishingPub, setIsPublishingPub] = useState<boolean>(false);
  const [pubError, setPubError] = useState<string | null>(null);
  const [showPublishConfirm, setShowPublishConfirm] = useState<boolean>(false);
  const [copiedDigest, setCopiedDigest] = useState<boolean>(false);

  // UI exploration tabs & filters
  const [activeTab, setActiveTab] = useState<
    'IMPACTS' | 'CONTRACTS' | 'REVIEW' | 'REPORT' | 'TELEMETRY' | 'PUBLISH'
  >('IMPACTS');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [expandedImpactId, setExpandedImpactId] = useState<string | null>(null);
  const [expandedFindingId, setExpandedFindingId] = useState<string | null>(null);
  const [copiedReport, setCopiedReport] = useState<boolean>(false);

  // SSE Workflow Event Stream
  const { events: workflowEvents } = useWorkflowStream(
    null,
    Boolean(activeAnalysis && activeAnalysis.status !== 'COMPLETED' && activeAnalysis.status !== 'FAILED'),
    activeAnalysis?.id
  );

  // Polling active analysis status
  useEffect(() => {
    if (!activeAnalysis || activeAnalysis.status === 'COMPLETED' || activeAnalysis.status === 'FAILED') {
      return;
    }

    const interval = setInterval(async () => {
      try {
        const updated = await fetchChangeAnalysis(activeAnalysis.id);
        setActiveAnalysis(updated);

        if (updated.status === 'COMPLETED' || updated.status === 'FAILED') {
          if (updated.status === 'COMPLETED') {
            loadCompletedAnalysisData(updated.id);
          }
        }
      } catch (err) {
        console.error('Polling error for change analysis:', err);
      }
    }, 2000);

    return () => clearInterval(interval);
  }, [activeAnalysis]);

  const loadCompletedAnalysisData = async (analysisId: string) => {
    try {
      const [fetchedImpacts, fetchedReview, fetchedReport, fetchedTelemetry, fetchedDiff, fetchedPub] =
        await Promise.all([
          fetchChangeAnalysisImpacts(analysisId).catch(() => []),
          fetchChangeAnalysisReview(analysisId).catch(() => null),
          fetchChangeAnalysisReport(analysisId).catch(() => null),
          fetchChangeAnalysisTelemetry(analysisId).catch(() => null),
          fetchChangeAnalysisDiff(analysisId).catch(() => null),
          fetchReviewPublication(analysisId).catch(() => null),
        ]);

      setImpacts(fetchedImpacts || []);
      if (fetchedReview && fetchedReview.findings) {
        setReviewFindings(fetchedReview.findings);
      }
      if (fetchedReport) {
        setReport(fetchedReport);
      }
      if (fetchedTelemetry) {
        setTelemetry(fetchedTelemetry);
      }
      if (fetchedDiff) {
        setDiffDeltas({
          route_deltas: fetchedDiff.route_deltas || [],
          schema_deltas: fetchedDiff.schema_deltas || [],
          dependency_deltas: fetchedDiff.dependency_deltas || [],
          config_deltas: fetchedDiff.config_deltas || [],
        });
      }
      if (fetchedPub) {
        setPublication(fetchedPub);
      }
    } catch (err) {
      console.error('Failed to load completed analysis artifacts:', err);
    }
  };

  const handleStartAnalysis = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg(null);

    if (!isAuthenticated) {
      setIsSubmitting(true);
      try {
        await login('demo@repolens.io', 'RepoLensDemo2026!');
      } catch {
        if (onOpenAuthModal) {
          onOpenAuthModal();
        } else {
          setErrorMsg('Authentication required. Please sign in or register.');
        }
        setIsSubmitting(false);
        return;
      }
    }

    setIsSubmitting(true);
    setReport(null);
    setImpacts([]);
    setReviewFindings([]);
    setTelemetry(null);

    try {
      let res: ChangeAnalysisResponse;
      if (inputMode === 'PR') {
        if (!prUrl.trim()) {
          throw new Error('Please provide a valid GitHub Pull Request URL.');
        }
        res = await startChangeAnalysisFromPR({ pr_url: prUrl.trim() });
      } else {
        if (!repoUrl.trim() || !baseSha.trim() || !headSha.trim()) {
          throw new Error('Repository URL, Base commit SHA, and Head commit SHA are all required.');
        }
        res = await startChangeAnalysis({
          repository_url: repoUrl.trim(),
          base_commit_sha: baseSha.trim(),
          head_commit_sha: headSha.trim(),
          base_ref: baseRef.trim() || undefined,
          head_ref: headRef.trim() || undefined,
        });
      }
      setActiveAnalysis(res);
    } catch (err: unknown) {
      if (err instanceof Error) {
        setErrorMsg(err.message);
      } else {
        setErrorMsg('Failed to initiate change analysis.');
      }
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleDownloadMarkdown = async () => {
    if (!activeAnalysis) return;
    try {
      const text = await downloadChangeAnalysisMarkdown(activeAnalysis.id);
      const blob = new Blob([text], { type: 'text/markdown' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `repolens_change_report_${activeAnalysis.id.slice(0, 8)}.md`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err) {
      console.error('Download failed:', err);
    }
  };

  const handleCopyMarkdown = () => {
    if (!report?.markdown_report) return;
    navigator.clipboard.writeText(report.markdown_report);
    setCopiedReport(true);
    setTimeout(() => setCopiedReport(false), 2000);
  };

  const handleGeneratePreview = async () => {
    if (!activeAnalysis) return;
    setIsGeneratingPreview(true);
    setPubError(null);
    try {
      const pub = await generateReviewPublicationPreview(activeAnalysis.id);
      setPublication(pub);
    } catch (err: unknown) {
      setPubError(err instanceof Error ? err.message : 'Failed to generate review publication preview');
    } finally {
      setIsGeneratingPreview(false);
    }
  };

  const handleApprovePublication = async () => {
    if (!activeAnalysis || !publication) return;
    setIsApprovingPub(true);
    setPubError(null);
    try {
      const pub = await approveReviewPublication(activeAnalysis.id, publication.preview_digest);
      setPublication(pub);
    } catch (err: unknown) {
      setPubError(err instanceof Error ? err.message : 'Failed to approve review publication');
    } finally {
      setIsApprovingPub(false);
    }
  };

  const handlePublishReview = async () => {
    if (!activeAnalysis || !publication) return;
    setIsPublishingPub(true);
    setPubError(null);
    try {
      await publishReviewPublication(activeAnalysis.id, publication.preview_digest);
      const updated = await fetchReviewPublication(activeAnalysis.id);
      setPublication(updated);
      setShowPublishConfirm(false);
    } catch (err: unknown) {
      setPubError(err instanceof Error ? err.message : 'Failed to publish review to GitHub');
    } finally {
      setIsPublishingPub(false);
    }
  };

  const handleCopyDigest = () => {
    if (publication?.preview_digest) {
      navigator.clipboard.writeText(publication.preview_digest);
      setCopiedDigest(true);
      setTimeout(() => setCopiedDigest(false), 2000);
    }
  };

  const isRunning = Boolean(
    activeAnalysis &&
      (activeAnalysis.status === 'PENDING' ||
        activeAnalysis.status === 'ACQUIRING' ||
        activeAnalysis.status === 'DIFFING' ||
        activeAnalysis.status === 'ANALYZING' ||
        activeAnalysis.status === 'VERIFYING')
  );

  const totalContractChanges =
    diffDeltas.route_deltas.length +
    diffDeltas.schema_deltas.length +
    diffDeltas.dependency_deltas.length +
    diffDeltas.config_deltas.length;

  return (
    <div className="page-view-enter flex flex-col gap-8">
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
            <span className="text-sm font-bold text-white">Change Intelligence &amp; PR Review</span>
            <span className="badge-tag text-[10px] text-cyan-300 border-cyan-500/30">Blast Radius Active</span>
          </div>
        </div>

        {onNavigate && (
          <div className="flex items-center gap-2">
            <button
              type="button"
              className="filter-btn text-xs"
              onClick={() => onNavigate('SCAN')}
            >
              🛡️ Security Scan Workspace →
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

      {/* Input Section Card */}
      <ChangeAnalysisInput
        inputMode={inputMode}
        onInputModeChange={setInputMode}
        prUrl={prUrl}
        onPrUrlChange={setPrUrl}
        repoUrl={repoUrl}
        onRepoUrlChange={setRepoUrl}
        baseSha={baseSha}
        onBaseShaChange={setBaseSha}
        headSha={headSha}
        onHeadShaChange={setHeadSha}
        baseRef={baseRef}
        onBaseRefChange={setBaseRef}
        headRef={headRef}
        onHeadRefChange={setHeadRef}
        onSubmit={handleStartAnalysis}
        isSubmitting={isSubmitting}
        isRunning={isRunning}
        errorMsg={errorMsg}
      />

      {/* Active Analysis Lifecycle Status Card */}
      {activeAnalysis && (
        <ChangeAnalysisStatus
          analysis={activeAnalysis}
          isRunning={isRunning}
          workflowEvents={workflowEvents}
          onDownloadMarkdown={handleDownloadMarkdown}
        />
      )}

      {/* Overview Metrics & Deterministic Risk */}
      {activeAnalysis && <ChangeSummary analysis={activeAnalysis} />}

      {/* Exploration Tabs Container */}
      {activeAnalysis && (
        <Card>
          {/* Navigation Tab Bar */}
          <div
            role="tablist"
            aria-label="Change Analysis Subsections"
            className="flex gap-2 border-b border-white/10 pb-4 mb-6 flex-wrap"
          >
            <Button
              variant={activeTab === 'IMPACTS' ? 'filter-active' : 'filter'}
              size="sm"
              onClick={() => setActiveTab('IMPACTS')}
              aria-selected={activeTab === 'IMPACTS'}
              role="tab"
            >
              💥 Blast Radius Explorer ({impacts.length})
            </Button>
            <Button
              variant={activeTab === 'CONTRACTS' ? 'filter-active' : 'filter'}
              size="sm"
              onClick={() => setActiveTab('CONTRACTS')}
              aria-selected={activeTab === 'CONTRACTS'}
              role="tab"
            >
              ⚡ Contract Changes ({totalContractChanges})
            </Button>
            <Button
              variant={activeTab === 'REVIEW' ? 'filter-active' : 'filter'}
              size="sm"
              onClick={() => setActiveTab('REVIEW')}
              aria-selected={activeTab === 'REVIEW'}
              role="tab"
            >
              🤖 Verified AI Review ({reviewFindings.length})
            </Button>
            <Button
              variant={activeTab === 'REPORT' ? 'filter-active' : 'filter'}
              size="sm"
              onClick={() => setActiveTab('REPORT')}
              aria-selected={activeTab === 'REPORT'}
              role="tab"
            >
              📄 Executive Report
            </Button>
            <Button
              variant={activeTab === 'TELEMETRY' ? 'filter-active' : 'filter'}
              size="sm"
              onClick={() => setActiveTab('TELEMETRY')}
              aria-selected={activeTab === 'TELEMETRY'}
              role="tab"
            >
              📊 Telemetry
            </Button>
            <Button
              variant={activeTab === 'PUBLISH' ? 'filter-active' : 'filter'}
              size="sm"
              onClick={() => setActiveTab('PUBLISH')}
              aria-selected={activeTab === 'PUBLISH'}
              role="tab"
            >
              🚀 GitHub PR Review{' '}
              {publication?.status === 'PUBLISHED'
                ? '✓'
                : publication?.status
                ? `(${publication.status})`
                : ''}
            </Button>
          </div>

          {/* TAB 1: Blast Radius Impact Explorer */}
          {activeTab === 'IMPACTS' && (
            <ImpactExplorer
              impacts={impacts}
              severityFilter={severityFilter}
              onSeverityFilterChange={setSeverityFilter}
              statusFilter={statusFilter}
              onStatusFilterChange={setStatusFilter}
              expandedImpactId={expandedImpactId}
              onToggleExpand={(id) => setExpandedImpactId(expandedImpactId === id ? null : id)}
            />
          )}

          {/* TAB 2: Contract Changes */}
          {activeTab === 'CONTRACTS' && (
            <ContractDeltasPanel
              routeDeltas={diffDeltas.route_deltas}
              schemaDeltas={diffDeltas.schema_deltas}
              dependencyDeltas={diffDeltas.dependency_deltas}
              configDeltas={diffDeltas.config_deltas}
            />
          )}

          {/* TAB 3: Verified AI Review */}
          {activeTab === 'REVIEW' && (
            <ChangeReviewPanel
              reviewFindings={reviewFindings}
              expandedFindingId={expandedFindingId}
              onToggleExpand={(id) => setExpandedFindingId(expandedFindingId === id ? null : id)}
            />
          )}

          {/* TAB 4: Executive Report & Markdown */}
          {activeTab === 'REPORT' && (
            <ReviewReportPanel
              report={report}
              copiedReport={copiedReport}
              onCopyMarkdown={handleCopyMarkdown}
              onDownloadMarkdown={handleDownloadMarkdown}
            />
          )}

          {/* TAB 5: Telemetry */}
          {activeTab === 'TELEMETRY' && (
            <ChangeTelemetryPanel telemetry={telemetry} />
          )}

          {/* TAB 6: Safe GitHub PR Review Publication */}
          {activeTab === 'PUBLISH' && (
            <ReviewPublicationPanel
              publication={publication}
              isGeneratingPreview={isGeneratingPreview}
              isApprovingPub={isApprovingPub}
              isPublishingPub={isPublishingPub}
              pubError={pubError}
              showPublishConfirm={showPublishConfirm}
              copiedDigest={copiedDigest}
              isAnalysisCompleted={activeAnalysis.status === 'COMPLETED'}
              onGeneratePreview={handleGeneratePreview}
              onApprovePublication={handleApprovePublication}
              onPublishReview={handlePublishReview}
              onCopyDigest={handleCopyDigest}
              onSetShowPublishConfirm={setShowPublishConfirm}
            />
          )}
        </Card>
      )}
    </div>
  );
}
