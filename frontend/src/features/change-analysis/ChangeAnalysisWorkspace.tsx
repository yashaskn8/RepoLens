'use client';

import React, { useEffect, useRef, useState } from 'react';
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
import { parseExactChangeCommits } from '@/lib/exactChangeCommits';
import { Card } from '@/components/ui/Card';
import { Alert } from '@/components/ui/Alert';
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

export interface ChangeAnalysisWorkspaceProps {
  onNavigate?: (mode: WorkspaceMode) => void;
}

export function ChangeAnalysisWorkspace({ onNavigate }: ChangeAnalysisWorkspaceProps = {}) {
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
  const analysisGenerationRef = useRef(0);
  const artifactLoadSequenceRef = useRef(0);
  // React state updates are asynchronous; guard retry re-entry synchronously.
  const artifactRetryPendingRef = useRef(false);
  // Invalidate pending report downloads and publication/artifact callbacks on unmount.
  useEffect(() => () => { analysisGenerationRef.current += 1; }, []);
  const submitPendingRef = useRef(false);
  const publicationPendingRef = useRef(false);
  // Invalidate an older persisted-publication fetch when an operator action begins or finishes.
  const publicationActionSequenceRef = useRef(0);
  const [artifactError, setArtifactError] = useState<string | null>(null);
  const [isRetryingArtifacts, setIsRetryingArtifacts] = useState(false);
  const [artifactAvailability, setArtifactAvailability] = useState({
    impacts: false, review: false, report: false, diff: false, telemetry: false,
  });
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
  const [copyDigestError, setCopyDigestError] = useState<string | null>(null);
  const copyDigestSequenceRef = useRef(0);
  // A regenerated preview may have a different digest; invalidate older copy callbacks.
  useEffect(() => {
    copyDigestSequenceRef.current += 1;
    setCopiedDigest(false);
    setCopyDigestError(null);
  }, [publication?.preview_digest]);

  // UI exploration tabs & filters
  const [activeTab, setActiveTab] = useState<
    'IMPACTS' | 'CONTRACTS' | 'REVIEW' | 'REPORT' | 'TELEMETRY' | 'PUBLISH'
  >('IMPACTS');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [expandedImpactId, setExpandedImpactId] = useState<string | null>(null);
  const [expandedFindingId, setExpandedFindingId] = useState<string | null>(null);
  const [copiedReport, setCopiedReport] = useState<boolean>(false);
  const [copyError, setCopyError] = useState<string | null>(null);
  const copySequenceRef = useRef(0);

  // SSE Workflow Event Stream
  const { events: workflowEvents } = useWorkflowStream(
    null,
    Boolean(activeAnalysis && activeAnalysis.status !== 'COMPLETED' && activeAnalysis.status !== 'FAILED'),
    activeAnalysis?.id
  );

  // Fetch one analysis identity until terminal; an already-completed response
  // (e.g. idempotent reuse) must still populate the artifacts.
  useEffect(() => {
    const analysisId = activeAnalysis?.id;
    if (!analysisId) return;

    const generation = analysisGenerationRef.current;
    let stopped = false;
    let retryTimer: ReturnType<typeof setTimeout> | undefined;
    let pollAbort: AbortController | undefined;
    const isCurrent = () => !stopped && generation === analysisGenerationRef.current;

    const poll = async () => {
      if (!isCurrent()) return;
      let terminal = false;
      const controller = new AbortController();
      pollAbort = controller;
      let deadlineTimer: ReturnType<typeof setTimeout> | undefined;
      // A hung status request must not permanently stop progress polling.
      // Promise.race also handles fetch implementations that ignore abort.
      const deadline = new Promise<never>((_, reject) => {
        deadlineTimer = setTimeout(() => {
          controller.abort();
          reject(new Error('Change analysis status request timed out'));
        }, 15_000);
      });
      try {
        const updated = await Promise.race([
          fetchChangeAnalysis(analysisId, controller.signal),
          deadline,
        ]);
        if (!isCurrent()) return;
        setActiveAnalysis((current) => current?.id === analysisId ? updated : current);
        terminal = updated.status === 'COMPLETED' || updated.status === 'FAILED';
        if (updated.status === 'COMPLETED') {
          await loadCompletedAnalysisData(analysisId, generation);
        }
      } catch (err) {
        if (isCurrent()) console.error('Polling error for change analysis:', err);
      } finally {
        if (deadlineTimer !== undefined) clearTimeout(deadlineTimer);
        if (pollAbort === controller) pollAbort = undefined;
      }
      if (isCurrent() && !terminal) retryTimer = setTimeout(poll, 2000);
    };

    void poll();
    return () => {
      stopped = true;
      if (retryTimer !== undefined) clearTimeout(retryTimer);
      pollAbort?.abort();
    };
  }, [activeAnalysis?.id]);

  const loadCompletedAnalysisData = async (analysisId: string, generation: number) => {
    const loadSequence = ++artifactLoadSequenceRef.current;
    const publicationActionSequence = publicationActionSequenceRef.current;
    // A stalled evidence endpoint must eventually report a recoverable failure.
    // Abort the network request, but also settle the wrapper when a mocked or
    // non-cooperative request ignores AbortSignal. Late results cannot apply.
    const withArtifactDeadline = <T,>(request: (signal: AbortSignal) => Promise<T>): Promise<T> => {
      const controller = new AbortController();
      let timer: ReturnType<typeof setTimeout> | undefined;
      const deadline = new Promise<never>((_, reject) => {
        timer = setTimeout(() => {
          controller.abort();
          reject(new Error('Artifact request timed out'));
        }, 15_000);
      });
      return Promise.race([
        Promise.resolve().then(() => request(controller.signal)),
        deadline,
      ]).finally(() => {
        if (timer !== undefined) clearTimeout(timer);
      });
    };
    // Publication previews are optional and may be absent or slow. Never let
    // that request delay the required report, findings, diff, or telemetry.
    void withArtifactDeadline((signal) => fetchReviewPublication(analysisId, signal)).then((publication) => {
      if (generation !== analysisGenerationRef.current ||
          loadSequence !== artifactLoadSequenceRef.current ||
          publicationPendingRef.current ||
          publicationActionSequence !== publicationActionSequenceRef.current) return;
      setPublication(publication);
    }, () => { /* No publication preview exists yet, or its fetch failed. */ });
    // Apply each completed artifact immediately. A slow or stalled sibling
    // must not hide an already-available report, review, diff, or telemetry.
    const isCurrent = () =>
      generation === analysisGenerationRef.current && loadSequence === artifactLoadSequenceRef.current;
    const applyWhenCurrent = <T,>(request: Promise<T>, apply: (value: T) => void) =>
      request.then((value) => {
        if (isCurrent()) apply(value);
        return value;
      });
    const outcomes = await Promise.allSettled([
      applyWhenCurrent(withArtifactDeadline((signal) => fetchChangeAnalysisImpacts(analysisId, signal)), (value) => {
        setImpacts(value || []);
        setArtifactAvailability((state) => ({ ...state, impacts: true }));
      }),
      applyWhenCurrent(withArtifactDeadline((signal) => fetchChangeAnalysisReview(analysisId, signal)), (value) => {
        setReviewFindings(value.findings || []);
        setArtifactAvailability((state) => ({ ...state, review: true }));
      }),
      applyWhenCurrent(withArtifactDeadline((signal) => fetchChangeAnalysisReport(analysisId, signal)), (value) => {
        setReport(value);
        setArtifactAvailability((state) => ({ ...state, report: true }));
      }),
      applyWhenCurrent(withArtifactDeadline((signal) => fetchChangeAnalysisTelemetry(analysisId, signal)), (value) => {
        setTelemetry(value);
        setArtifactAvailability((state) => ({ ...state, telemetry: true }));
      }),
      applyWhenCurrent(withArtifactDeadline((signal) => fetchChangeAnalysisDiff(analysisId, signal)), (diff) => {
        setDiffDeltas({
          route_deltas: diff.route_deltas || [],
          schema_deltas: diff.schema_deltas || [],
          dependency_deltas: diff.dependency_deltas || [],
          config_deltas: diff.config_deltas || [],
        });
        setArtifactAvailability((state) => ({ ...state, diff: true }));
      }),
    ]);
    if (!isCurrent()) return;
    const missing: string[] = [];
    const [impactsResult, reviewResult, reportResult, telemetryResult, diffResult] = outcomes;
    if (impactsResult.status === 'rejected') missing.push('impacts');
    if (reviewResult.status === 'rejected') missing.push('review');
    if (reportResult.status === 'rejected') missing.push('report');
    if (telemetryResult.status === 'rejected') missing.push('telemetry');
    if (diffResult.status === 'rejected') missing.push('structural diff');
    setArtifactError(missing.length
      ? `Analysis completed, but unavailable artifacts: ${missing.join(', ')}. Empty panels are not evidence of zero findings.`
      : null);
  };

  const retryCompletedArtifacts = async () => {
    if (!activeAnalysis || activeAnalysis.status !== 'COMPLETED' || isRetryingArtifacts || artifactRetryPendingRef.current) return;
    artifactRetryPendingRef.current = true;
    const generation = analysisGenerationRef.current;
    setIsRetryingArtifacts(true);
    try {
      await loadCompletedAnalysisData(activeAnalysis.id, generation);
    } finally {
      if (generation === analysisGenerationRef.current) {
        artifactRetryPendingRef.current = false;
        setIsRetryingArtifacts(false);
      }
    }
  };

  const handleStartAnalysis = async (e: React.FormEvent) => {
    e.preventDefault();
    if (submitPendingRef.current) return;
    let exactCommits: ReturnType<typeof parseExactChangeCommits> | null = null;
    if (inputMode === 'EXACT') {
      try {
        exactCommits = parseExactChangeCommits(baseSha, headSha);
      } catch (err: unknown) {
        setErrorMsg(err instanceof Error ? err.message : 'Enter two distinct exact commit SHAs.');
        return;
      }
    }
    submitPendingRef.current = true;
    const generation = ++analysisGenerationRef.current;
    setErrorMsg(null);
    setArtifactError(null);
    artifactRetryPendingRef.current = false;
    setIsRetryingArtifacts(false);
    setArtifactAvailability({
      impacts: false, review: false, report: false, diff: false, telemetry: false,
    });
    setIsSubmitting(true);
    setActiveAnalysis(null);
    setReport(null);
    setImpacts([]);
    setReviewFindings([]);
    setTelemetry(null);
    setPublication(null);
    setPubError(null);
    // Invalidate publication requests from the previous analysis. A late
    // response must not repopulate its preview or clear the new action's lock.
    publicationPendingRef.current = false;
    publicationActionSequenceRef.current += 1;
    setIsGeneratingPreview(false);
    setIsApprovingPub(false);
    setIsPublishingPub(false);
    setShowPublishConfirm(false);
    setCopiedDigest(false);
    setCopyDigestError(null);
    copyDigestSequenceRef.current += 1;
    copySequenceRef.current += 1;
    setCopiedReport(false);
    setCopyError(null);
    setDiffDeltas({ route_deltas: [], schema_deltas: [], dependency_deltas: [], config_deltas: [] });

    try {
      let res: ChangeAnalysisResponse;
      if (inputMode === 'PR') {
        if (!prUrl.trim()) {
          throw new Error('Please provide a valid GitHub Pull Request URL.');
        }
        res = await startChangeAnalysisFromPR({ pr_url: prUrl.trim() });
      } else {
        if (!repoUrl.trim()) {
          throw new Error('Repository URL is required.');
        }
        res = await startChangeAnalysis({
          repository_url: repoUrl.trim(),
          base_commit_sha: exactCommits!.baseSha,
          head_commit_sha: exactCommits!.headSha,
          base_ref: baseRef.trim() || undefined,
          head_ref: headRef.trim() || undefined,
        });
      }
      if (generation === analysisGenerationRef.current) setActiveAnalysis(res);
    } catch (err: unknown) {
      if (generation === analysisGenerationRef.current) {
        setErrorMsg(err instanceof Error ? err.message : 'Failed to initiate change analysis.');
      }
    } finally {
      if (generation === analysisGenerationRef.current) {
        submitPendingRef.current = false;
        setIsSubmitting(false);
      }
    }
  };

  const handleDownloadMarkdown = async () => {
    if (!activeAnalysis) return;
    const generation = analysisGenerationRef.current;
    const analysisId = activeAnalysis.id;
    try {
      const text = await downloadChangeAnalysisMarkdown(analysisId);
      if (generation !== analysisGenerationRef.current) return;
      const blob = new Blob([text], { type: 'text/markdown' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `repolens_change_report_${analysisId.slice(0, 8)}.md`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err) {
      console.error('Download failed:', err);
    }
  };

  const handleCopyMarkdown = async () => {
    if (!report?.markdown_report) return;
    const generation = analysisGenerationRef.current;
    const copySequence = ++copySequenceRef.current;
    setCopiedReport(false);
    setCopyError(null);
    try {
      await navigator.clipboard.writeText(report.markdown_report);
      if (generation !== analysisGenerationRef.current || copySequence !== copySequenceRef.current) return;
      setCopiedReport(true);
      setTimeout(() => {
        if (generation === analysisGenerationRef.current && copySequence === copySequenceRef.current) {
          setCopiedReport(false);
        }
      }, 2000);
    } catch {
      if (generation === analysisGenerationRef.current && copySequence === copySequenceRef.current) {
        setCopyError('Could not copy the report. Check clipboard permissions or select and copy the text manually.');
      }
    }
  };

  const handleGeneratePreview = async () => {
    if (!activeAnalysis || publicationPendingRef.current) return;
    const generation = analysisGenerationRef.current;
    const analysisId = activeAnalysis.id;
    publicationPendingRef.current = true;
    publicationActionSequenceRef.current += 1;
    setIsGeneratingPreview(true);
    setPubError(null);
    try {
      const pub = await generateReviewPublicationPreview(analysisId);
      if (generation === analysisGenerationRef.current) setPublication(pub);
    } catch (err: unknown) {
      if (generation === analysisGenerationRef.current) {
        setPubError(err instanceof Error ? err.message : 'Failed to generate review publication preview');
      }
    } finally {
      if (generation === analysisGenerationRef.current) {
        publicationPendingRef.current = false;
        publicationActionSequenceRef.current += 1;
        setIsGeneratingPreview(false);
      }
    }
  };

  const handleApprovePublication = async () => {
    if (!activeAnalysis || !publication || publicationPendingRef.current) return;
    const generation = analysisGenerationRef.current;
    const analysisId = activeAnalysis.id;
    const digest = publication.preview_digest;
    publicationPendingRef.current = true;
    publicationActionSequenceRef.current += 1;
    setIsApprovingPub(true);
    setPubError(null);
    try {
      const pub = await approveReviewPublication(analysisId, digest);
      if (generation === analysisGenerationRef.current) setPublication(pub);
    } catch (err: unknown) {
      if (generation === analysisGenerationRef.current) {
        setPubError(err instanceof Error ? err.message : 'Failed to approve review publication');
      }
    } finally {
      if (generation === analysisGenerationRef.current) {
        publicationPendingRef.current = false;
        publicationActionSequenceRef.current += 1;
        setIsApprovingPub(false);
      }
    }
  };

  const handlePublishReview = async () => {
    if (!activeAnalysis || !publication || publicationPendingRef.current) return;
    const generation = analysisGenerationRef.current;
    const analysisId = activeAnalysis.id;
    const digest = publication.preview_digest;
    publicationPendingRef.current = true;
    publicationActionSequenceRef.current += 1;
    setIsPublishingPub(true);
    setPubError(null);
    try {
      await publishReviewPublication(analysisId, digest);
      const updated = await fetchReviewPublication(analysisId);
      if (generation === analysisGenerationRef.current) {
        setPublication(updated);
        setShowPublishConfirm(false);
      }
    } catch (err: unknown) {
      if (generation === analysisGenerationRef.current) {
        setPubError(err instanceof Error ? err.message : 'Failed to publish review to GitHub');
      }
    } finally {
      if (generation === analysisGenerationRef.current) {
        publicationPendingRef.current = false;
        publicationActionSequenceRef.current += 1;
        setIsPublishingPub(false);
      }
    }
  };

  const handleCopyDigest = async () => {
    if (!publication?.preview_digest) return;
    const generation = analysisGenerationRef.current;
    const copySequence = ++copyDigestSequenceRef.current;
    const digest = publication.preview_digest;
    setCopiedDigest(false);
    setCopyDigestError(null);
    try {
      await navigator.clipboard.writeText(digest);
      if (generation !== analysisGenerationRef.current || copySequence !== copyDigestSequenceRef.current) return;
      setCopiedDigest(true);
      setTimeout(() => {
        if (generation === analysisGenerationRef.current && copySequence === copyDigestSequenceRef.current) {
          setCopiedDigest(false);
        }
      }, 2000);
    } catch {
      if (generation === analysisGenerationRef.current && copySequence === copyDigestSequenceRef.current) {
        setCopyDigestError('Could not copy the preview digest. Check clipboard permissions or select and copy it manually.');
      }
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
            <span className="text-sm font-bold text-white">PR Impact Analysis &amp; Review</span>
            <span className="badge-tag text-[10px] text-cyan-300 border-cyan-500/30">Analysis Active</span>
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

      {activeAnalysis?.status === 'COMPLETED' && artifactError && (
        <div className="flex flex-col gap-2">
          <Alert variant="error" title="Incomplete analysis artifacts">{artifactError}</Alert>
          <Button variant="filter" size="sm" onClick={() => void retryCompletedArtifacts()} disabled={isRetryingArtifacts}>
            {isRetryingArtifacts ? 'Retrying artifacts…' : 'Retry missing artifacts'}
          </Button>
        </div>
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
              📊 Downstream Impacts ({impacts.length})
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
          {activeTab === 'IMPACTS' && (artifactAvailability.impacts ? (
            <ImpactExplorer
              impacts={impacts}
              severityFilter={severityFilter}
              onSeverityFilterChange={setSeverityFilter}
              statusFilter={statusFilter}
              onStatusFilterChange={setStatusFilter}
              expandedImpactId={expandedImpactId}
              onToggleExpand={(id) => setExpandedImpactId(expandedImpactId === id ? null : id)}
            />
          ) : <Alert variant="warning">Impact evidence is not available; zero impacts cannot be concluded.</Alert>)}

          {/* TAB 2: Contract Changes */}
          {activeTab === 'CONTRACTS' && (artifactAvailability.diff ? (
            <ContractDeltasPanel
              routeDeltas={diffDeltas.route_deltas}
              schemaDeltas={diffDeltas.schema_deltas}
              dependencyDeltas={diffDeltas.dependency_deltas}
              configDeltas={diffDeltas.config_deltas}
            />
          ) : <Alert variant="warning">Structural diff evidence is not available; zero contract changes cannot be concluded.</Alert>)}

          {/* TAB 3: Verified AI Review */}
          {activeTab === 'REVIEW' && (artifactAvailability.review ? (
            <ChangeReviewPanel
              reviewFindings={reviewFindings}
              expandedFindingId={expandedFindingId}
              onToggleExpand={(id) => setExpandedFindingId(expandedFindingId === id ? null : id)}
            />
          ) : <Alert variant="warning">Verified review evidence is unavailable. No clean conclusion is possible.</Alert>)}

          {/* TAB 4: Executive Report & Markdown */}
          {activeTab === 'REPORT' && (artifactAvailability.report ? (
            <ReviewReportPanel
              report={report}
              copiedReport={copiedReport}
              copyError={copyError}
              onCopyMarkdown={() => void handleCopyMarkdown()}
              onDownloadMarkdown={handleDownloadMarkdown}
            />
          ) : <Alert variant="warning">The report has not been loaded successfully.</Alert>)}

          {/* TAB 5: Telemetry */}
          {activeTab === 'TELEMETRY' && (artifactAvailability.telemetry ? (
            <ChangeTelemetryPanel telemetry={telemetry} />
          ) : <Alert variant="warning">Execution telemetry is not available.</Alert>)}

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
              copyDigestError={copyDigestError}
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
