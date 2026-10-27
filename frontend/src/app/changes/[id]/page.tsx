'use client';

import React, { useState, useEffect, useRef, use } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { AppShell } from '@/components/layout/AppShell';
import { Card } from '@/components/ui/Card';
import { Button } from '@/components/ui/Button';
import { Badge } from '@/components/ui/Badge';
import { Tabs } from '@/components/ui/Tabs';
import { Skeleton } from '@/components/ui/Skeleton';
import { EmptyState } from '@/components/ui/EmptyState';
import { useAuth } from '@/context/AuthContext';
import {
  ApiError,
  fetchChangeAnalysis,
  fetchChangeAnalysisDiff,
  fetchChangeAnalysisImpacts,
  fetchChangeAnalysisReview,
  fetchReviewPublication,
  generateReviewPublicationPreview,
  approveReviewPublication,
  publishReviewPublication,
  getErrorMessage,
} from '@/lib/api';
import {
  ChangeAnalysisResponse,
  ChangeImpact,
  ChangeReviewReport,
  FileDiffFact,
  ReviewPublicationPreviewResponse,
  StructuralDiffResult,
} from '@/types/domain';
import {
  GitPullRequest,
  GitBranch,
  ShieldAlert,
  Layers,
  FileCode,
  FileDiff,
  CheckCircle2,
  AlertTriangle,
  Send,
  Eye,
  Lock,
  ExternalLink,
  ChevronRight,
  Sparkles,
  ShieldX,
  AlertCircle,
  HelpCircle,
  Network,
} from 'lucide-react';

// Bound read-only requests so an unresponsive endpoint cannot indefinitely
// suppress completed evidence or block recovery. Abort is best effort;
// Promise.race also handles a transport that ignores AbortSignal.
function withChangeDetailDeadline<T>(request: (signal: AbortSignal) => Promise<T>): Promise<T> {
  const controller = new AbortController();
  let timer: ReturnType<typeof setTimeout> | undefined;
  const deadline = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      controller.abort();
      reject(new Error('Change analysis request timed out'));
    }, 15_000);
  });
  return Promise.race([Promise.resolve().then(() => request(controller.signal)), deadline])
    .finally(() => { if (timer !== undefined) clearTimeout(timer); });
}

interface ChangeDetailPageProps {
  params: Promise<{ id: string }>;
}

export default function ChangeDetailPage({ params }: ChangeDetailPageProps) {
  const { id: analysisId } = use(params);
  const { user, isLoading: authLoading } = useAuth();
  const accountId = user?.id ?? null;

  // An account change must synchronously remove the previous account's PR
  // diff, review and publication approval state, before any effect runs.
  if (authLoading || !accountId) {
    return (
      <AppShell breadcrumbs={[{ label: 'PR Impact', href: '/change-analysis' }]} title="PR Impact Workspace">
        <EmptyState
          icon={<Lock size={24} />}
          title={authLoading ? 'Checking session' : 'Sign in to view PR analysis'}
          description="Authenticate before loading private pull request analysis and review publication controls."
        />
      </AppShell>
    );
  }

  return <ChangeDetailWorkspace key={`${accountId}:${analysisId}`} analysisId={analysisId} />;
}

function ChangeDetailWorkspace({ analysisId }: { analysisId: string }) {
  const router = useRouter();
  const { isOperator } = useAuth();
  const actionGeneration = useRef(0);
  const publishingRef = useRef(false);
  const publicationReadSequenceRef = useRef(0);

  // An already-started approval request must not start a second GitHub write
  // after navigation or an account switch unmounts this workspace.
  useEffect(() => () => { actionGeneration.current += 1; }, []);

  const [analysis, setAnalysis] = useState<ChangeAnalysisResponse | null>(null);
  const [diff, setDiff] = useState<StructuralDiffResult | null>(null);
  const [impacts, setImpacts] = useState<ChangeImpact[]>([]);
  const [impactsLoaded, setImpactsLoaded] = useState(false);
  const [review, setReview] = useState<ChangeReviewReport | null>(null);
  const [publication, setPublication] = useState<ReviewPublicationPreviewResponse | null>(null);

  const [centerTab, setCenterTab] = useState<'diff' | 'contracts' | 'callers' | 'report'>('diff');
  const [selectedFile, setSelectedFile] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isPublishing, setIsPublishing] = useState(false);
  const [confirmedPublish, setConfirmedPublish] = useState(false);
  const [publishMessage, setPublishMessage] = useState<string | null>(null);
  const [missingArtifacts, setMissingArtifacts] = useState<string[]>([]);
  const [analysisLoadError, setAnalysisLoadError] = useState<string | null>(null);
  const [artifactRetryToken, setArtifactRetryToken] = useState(0);
  const retryPendingRef = useRef(false);

  useEffect(() => {
    let cancelled = false;
    let retryTimer: ReturnType<typeof setTimeout> | undefined;

    // Keep already-loaded evidence visible while retrying transient failures.
    if (artifactRetryToken === 0) {
      setAnalysis(null);
      setDiff(null);
      setImpacts([]);
      setImpactsLoaded(false);
      setReview(null);
      setPublication(null);
      setSelectedFile(null);
      setMissingArtifacts([]);
    }
    setAnalysisLoadError(null);
    setIsLoading(true);

    async function loadData() {
      let terminal = false;
      try {
        const current = await withChangeDetailDeadline((signal) => fetchChangeAnalysis(analysisId, signal));
        if (cancelled) return;
        setAnalysis(current);
        setAnalysisLoadError(null);
        terminal = current.status === 'COMPLETED' || current.status === 'FAILED';
        if (current.status === 'COMPLETED') {
          // Optional publication state must not hold up the required evidence.
          // An operator action supersedes an older background publication read.
          const publicationReadSequence = publicationReadSequenceRef.current;
          void withChangeDetailDeadline((signal) => fetchReviewPublication(analysisId, signal))
            .then((value) => {
              if (!cancelled && publicationReadSequence === publicationReadSequenceRef.current) {
                setPublication(value);
              }
            }, () => { /* No preview exists, or the optional read failed. */ });
          const [diffRes, impactsRes, reviewRes] = await Promise.allSettled([
            withChangeDetailDeadline((signal) => fetchChangeAnalysisDiff(analysisId, signal)),
            withChangeDetailDeadline((signal) => fetchChangeAnalysisImpacts(analysisId, signal)),
            withChangeDetailDeadline((signal) => fetchChangeAnalysisReview(analysisId, signal)),
          ]);
          if (cancelled) return;
          const missing: string[] = [];
          if (diffRes.status === 'fulfilled') {
            setDiff(diffRes.value);
            if (diffRes.value.changed_files?.length > 0) {
              setSelectedFile(diffRes.value.changed_files[0].file_path);
            }
          } else missing.push('structural diff');
          if (impactsRes.status === 'fulfilled') {
            setImpacts(impactsRes.value || []);
            setImpactsLoaded(true);
          } else missing.push('downstream impacts');
          if (reviewRes.status === 'fulfilled') setReview(reviewRes.value);
          else missing.push('review evidence');
          setMissingArtifacts(missing);
        }
      } catch (error: unknown) {
        // Authorization and missing-resource errors are terminal, not transient
        // polling failures. Never retain evidence from a revoked session.
        const status = error instanceof ApiError ? error.status : undefined;
        if (status === 401 || status === 403 || status === 404) {
          terminal = true;
          if (!cancelled) {
            actionGeneration.current += 1;
            publicationReadSequenceRef.current += 1;
            setAnalysis(null);
            setDiff(null);
            setImpacts([]);
            setImpactsLoaded(false);
            setReview(null);
            setPublication(null);
            setSelectedFile(null);
            setMissingArtifacts([]);
            setConfirmedPublish(false);
            setAnalysisLoadError(status === 401
              ? 'Sign in again to access this analysis.'
              : 'This analysis is unavailable or access was denied.');
          }
        } else if (!cancelled) {
          // Timeouts and network/server failures remain retryable.
          setAnalysisLoadError('Unable to load analysis status. Retrying automatically.');
        }
      } finally {
        if (!cancelled) {
          setIsLoading(false);
          retryPendingRef.current = false;
          if (!terminal) retryTimer = setTimeout(loadData, 2000);
        }
      }
    }

    void loadData();
    return () => {
      cancelled = true;
      if (retryTimer) clearTimeout(retryTimer);
    };
  }, [analysisId, artifactRetryToken]);

  const retryMissingArtifacts = () => {
    if (analysis?.status !== 'COMPLETED' || missingArtifacts.length === 0 || retryPendingRef.current) return;
    retryPendingRef.current = true;
    setArtifactRetryToken((value) => value + 1);
  };

  const handleGeneratePreview = async () => {
    const generation = actionGeneration.current;
    publicationReadSequenceRef.current += 1;
    try {
      const pub = await generateReviewPublicationPreview(analysisId);
      if (generation === actionGeneration.current) setPublication(pub);
    } catch (err: unknown) {
      if (generation === actionGeneration.current) {
        setPublishMessage(getErrorMessage(err, 'Failed to generate review preview.'));
      }
    }
  };

  const handleApproveAndPublish = async () => {
    if (!publication?.preview_digest || publication.status === 'PUBLISHED' || !isOperator || !confirmedPublish || publishingRef.current) return;
    const generation = actionGeneration.current;
    publicationReadSequenceRef.current += 1;
    const digest = publication.preview_digest;
    publishingRef.current = true;
    setIsPublishing(true);
    setPublishMessage(null);

    try {
      await approveReviewPublication(analysisId, digest);
      if (generation !== actionGeneration.current) return;
      const res = await publishReviewPublication(analysisId, digest);
      if (generation !== actionGeneration.current) return;
      setPublishMessage(`Review published successfully to GitHub (Review ID: ${res.github_review_id || 'OK'})`);
      // The successful POST is authoritative. A delayed confirmation GET
      // must not turn a completed write into a failure or permit another write.
      setPublication((current) => current?.publication_id === res.publication_id
        ? { ...current, ...res } : current);
      setConfirmedPublish(false);
      try {
        const updatedPub = await withChangeDetailDeadline((signal) => fetchReviewPublication(analysisId, signal));
        if (generation === actionGeneration.current) {
          setPublication((current) => {
            if (!current || current.publication_id !== updatedPub.publication_id) return current;
            if (current.status === 'PUBLISHED' && updatedPub.status !== 'PUBLISHED') return current;
            return updatedPub;
          });
        }
      } catch {
        if (generation === actionGeneration.current) {
          setPublishMessage('Review published successfully, but status refresh was unavailable. Verify the current status before another publication attempt.');
        }
      }
    } catch (err: unknown) {
      if (generation === actionGeneration.current) {
        setPublishMessage(getErrorMessage(err, 'Failed to publish review to GitHub.'));
      }
    } finally {
      publishingRef.current = false;
      if (generation === actionGeneration.current) setIsPublishing(false);
    }
  };

  const currentFileDiff = diff?.changed_files?.find((f: FileDiffFact) => f.file_path === selectedFile) || diff?.changed_files?.[0];

  const breakingChangesCount = (diff?.route_deltas?.length || 0) + (diff?.schema_deltas?.length || 0);
  const criticalFindingsCount = review?.findings?.filter((f) => f.severity === 'CRITICAL' || f.severity === 'HIGH').length || 0;

  // Missing or failed evidence is UNKNOWN, never an implicit clean review.
  const assessmentAvailable = analysis?.status === 'COMPLETED' && diff !== null && impactsLoaded && review !== null;
  let recommendation: {
    status: 'Assessment unavailable' | 'Needs review' | 'Blocking issues' | 'No blockers detected';
    variant: 'success' | 'warning' | 'critical';
    details: string;
  } = {
    status: 'Assessment unavailable',
    variant: 'warning',
    details: analysis?.status === 'FAILED'
      ? 'Analysis failed; no merge safety conclusion is available.'
      : 'Waiting for completed analysis, structural diff and review evidence.',
  };

  if (assessmentAvailable && (analysis.risk_level === 'CRITICAL' || breakingChangesCount > 0)) {
    recommendation = {
      status: 'Blocking issues',
      variant: 'critical',
      details: `${breakingChangesCount > 0 ? `${breakingChangesCount} breaking contract delta(s)` : 'Critical security issues'} need manual review before merging.`,
    };
  } else if (assessmentAvailable && (
    analysis.risk_level === 'HIGH' || analysis.risk_level === 'MEDIUM' || criticalFindingsCount > 0
  )) {
    recommendation = {
      status: 'Needs review',
      variant: 'warning',
      details: 'Automated analysis identified risks that require human review.',
    };
  } else if (assessmentAvailable && analysis.risk_level === 'LOW') {
    recommendation = {
      status: 'No blockers detected',
      variant: 'success',
      details: 'No high-risk signals in the available analysis; human review is still required.',
    };
  }

  return (
    <AppShell
      breadcrumbs={[
        { label: 'PR Impact', href: '/change-analysis' },
        { label: analysis ? `${analysis.repository_owner}/${analysis.repository_name}` : analysisId.slice(0, 8) },
      ]}
      title="PR Impact Workspace"
    >
      <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem', height: 'calc(100vh - 8rem)' }}>
        {analysisLoadError && (
          <div role="alert" className="glass-panel" style={{ padding: '0.9rem 1.25rem', color: 'var(--warning-text)' }}>
            {analysisLoadError}
          </div>
        )}
        {/* Workspace Executive Summary Card */}
        <div
          className="glass-panel"
          style={{
            padding: '1.25rem 1.5rem',
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
            gap: '1.25rem',
            alignItems: 'center',
            background: 'linear-gradient(135deg, rgba(99, 102, 241, 0.08) 0%, rgba(8, 12, 28, 0.9) 100%)',
            border: '1px solid var(--border-glass-hover)',
          }}
        >
          {/* PR / Repo Details */}
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.25rem' }}>
              <GitPullRequest size={16} style={{ color: 'var(--accent-cyan)' }} />
              <h1 style={{ fontSize: '1.15rem', fontWeight: 800, fontFamily: 'var(--font-display)', color: '#ffffff' }}>
                {analysis ? `${analysis.repository_owner}/${analysis.repository_name}` : 'Pull Request Impact'}
              </h1>
            </div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
              Base: {analysis?.base_commit_sha?.slice(0, 8) || 'main'} ➔ Head: {analysis?.head_commit_sha?.slice(0, 8) || 'HEAD'}
            </div>
          </div>

          {/* Risk Level Prominently Displayed */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem' }}>
            <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600, letterSpacing: '0.04em' }}>
              Risk Level
            </span>
            <div>
              <Badge
                variant={
                  analysis?.risk_level === 'CRITICAL'
                    ? 'critical'
                    : analysis?.risk_level === 'HIGH'
                    ? 'high'
                    : analysis?.risk_level === 'MEDIUM'
                    ? 'medium'
                    : analysis?.risk_level === 'LOW'
                    ? 'success'
                    : 'warning'
                }
                size="md"
              >
                {analysis?.risk_level && analysis.risk_level !== 'NONE' ? `${analysis.risk_level} RISK` : 'Not assessed'}
              </Badge>
            </div>
          </div>

          {/* Clear Recommendation */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem' }}>
            <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600, letterSpacing: '0.04em' }}>
              Recommendation
            </span>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
              <Badge
                variant={
                  recommendation.variant === 'critical'
                    ? 'critical'
                    : recommendation.variant === 'warning'
                    ? 'high'
                    : 'success'
                }
                size="md"
              >
                {recommendation.status}
              </Badge>
            </div>
            <span style={{ fontSize: '0.7rem', color: 'var(--text-secondary)' }}>
              {recommendation.details}
            </span>
          </div>

          {/* Stats: Files & Breaking Changes */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem' }}>
            <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600, letterSpacing: '0.04em' }}>
              Impact Scope
            </span>
            <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
              <Badge variant="default" size="sm">
                {diff === null ? 'Files unavailable' : `${diff.changed_files?.length ?? 0} files`}
              </Badge>
              {diff === null ? (
                <Badge variant="default" size="sm">Diff unavailable</Badge>
              ) : breakingChangesCount > 0 ? (
                <Badge variant="critical" size="sm">
                  {breakingChangesCount} contract deltas
                </Badge>
              ) : (
                <Badge variant="cyan" size="sm">
                  0 detected contract deltas
                </Badge>
              )}
            </div>
          </div>
        </div>

        {analysis?.status === 'COMPLETED' && missingArtifacts.length > 0 && (
          <div role="alert" className="glass-panel" style={{ padding: '0.9rem 1.25rem', display: 'flex', alignItems: 'center', gap: '1rem', flexWrap: 'wrap' }}>
            <span style={{ flex: 1, color: 'var(--warning-text)' }}>
              Unavailable analysis artifacts: {missingArtifacts.join(', ')}. Missing evidence does not mean zero findings.
            </span>
            <Button type="button" variant="secondary" size="sm" disabled={isLoading} onClick={retryMissingArtifacts}>
              {isLoading ? 'Retrying artifacts...' : 'Retry missing artifacts'}
            </Button>
          </div>
        )}

        {/* 3-PANE ENGINEERING REVIEW LAYOUT */}
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: '18rem minmax(0, 1fr) 22rem',
            gap: '1.25rem',
            flex: 1,
            minHeight: 0,
          }}
        >
          {/* LEFT PANE: Changed Files List with Diff Summary */}
          <div
            className="glass-panel"
            style={{
              padding: '1.25rem',
              display: 'flex',
              flexDirection: 'column',
              gap: '0.85rem',
              overflowY: 'auto',
            }}
          >
            <div style={{ fontSize: '0.8125rem', fontWeight: 700, color: 'var(--text-primary)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
              Changed Files ({diff === null ? 'unavailable' : diff.changed_files?.length ?? 0})
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.4rem' }}>
              {diff?.changed_files?.map((file: FileDiffFact) => {
                const isSelected = selectedFile === file.file_path;
                return (
                  <button
                    key={file.file_path}
                    type="button"
                    onClick={() => setSelectedFile(file.file_path)}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      padding: '0.6rem 0.75rem',
                      borderRadius: 'var(--radius-md)',
                      backgroundColor: isSelected ? 'rgba(99, 102, 241, 0.22)' : 'rgba(5, 8, 18, 0.6)',
                      border: isSelected ? '1px solid var(--border-focus)' : '1px solid var(--border-subtle)',
                      color: isSelected ? '#ffffff' : 'var(--text-secondary)',
                      cursor: 'pointer',
                      textAlign: 'left',
                      transition: 'all var(--transition-fast)',
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', overflow: 'hidden' }}>
                      <FileCode size={14} style={{ flexShrink: 0, color: isSelected ? 'var(--accent-cyan)' : 'inherit' }} />
                      <span
                        style={{
                          fontSize: '0.8125rem',
                          fontFamily: 'var(--font-mono)',
                          whiteSpace: 'nowrap',
                          overflow: 'hidden',
                          textOverflow: 'ellipsis',
                        }}
                      >
                        {file.file_path.split('/').pop()}
                      </span>
                    </div>

                    <Badge variant={file.change_type === 'ADDED' ? 'success' : file.change_type === 'DELETED' ? 'critical' : 'cyan'} size="sm">
                      {file.change_type}
                    </Badge>
                  </button>
                );
              })}
            </div>

            {/* Impact Summary */}
            <div style={{ marginTop: 'auto', borderTop: '1px solid var(--border-subtle)', paddingTop: '0.85rem' }}>
              <div style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-muted)', marginBottom: '0.35rem' }}>
                Diff Summary
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem', fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                <div>• Total Files Touched: {diff?.changed_files?.length || 0}</div>
                <div>• Breaking Changes: {diff === null ? 'unavailable' : breakingChangesCount}</div>
                <div>• Downstream Callers: {impactsLoaded ? impacts.length : 'unavailable'}</div>
              </div>
            </div>
          </div>

          {/* CENTER PANE: Structural Diff, Breaking Changes, & Callers */}
          <div
            className="glass-panel"
            style={{
              display: 'flex',
              flexDirection: 'column',
              overflow: 'hidden',
            }}
          >
            {/* Center Tabs Header */}
            <div
              style={{
                padding: '0.75rem 1.25rem',
                borderBottom: '1px solid var(--border-subtle)',
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
              }}
            >
              <Tabs
                tabs={[
                  { id: 'diff', label: 'File Diff', icon: <FileDiff size={14} /> },
                  { id: 'contracts', label: 'Breaking Changes', count: breakingChangesCount, icon: <Layers size={14} /> },
                  { id: 'callers', label: 'Affected Callers', count: impactsLoaded ? impacts.length : undefined, icon: <Network size={14} /> },
                  { id: 'report', label: 'Review Summary', icon: <FileCode size={14} /> },
                ]}
                activeTab={centerTab}
                onChange={(id) => setCenterTab(id as any)}
              />

              {currentFileDiff && centerTab === 'diff' && (
                <span style={{ fontSize: '0.75rem', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
                  {currentFileDiff.file_path}
                </span>
              )}
            </div>

            {/* Center Tab Body */}
            <div style={{ flex: 1, overflowY: 'auto', padding: '1.25rem' }}>
              {/* Tab: File Diff */}
              {centerTab === 'diff' && (
                <div>
                  {currentFileDiff ? (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                      <div
                        style={{
                          background: 'var(--bg-code)',
                          border: '1px solid var(--border-subtle)',
                          borderRadius: 'var(--radius-md)',
                          padding: '1.25rem',
                        }}
                      >
                        <div style={{ fontSize: '0.8125rem', fontFamily: 'var(--font-mono)', color: 'var(--accent-cyan)', marginBottom: '0.5rem' }}>
                          {currentFileDiff.file_path} ({currentFileDiff.change_type})
                        </div>
                        <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)', lineHeight: 1.6 }}>
                          Changed Line Spans: {JSON.stringify(currentFileDiff.changed_line_ranges || [])}
                        </div>
                      </div>
                    </div>
                  ) : (
                    <div style={{ color: 'var(--text-muted)', fontSize: '0.875rem', textAlign: 'center', padding: '3rem' }}>
                      No diff available or file unchanged.
                    </div>
                  )}
                </div>
              )}

              {/* Tab: Breaking Changes */}
              {centerTab === 'contracts' && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                    <h4 style={{ fontSize: '0.9375rem', fontWeight: 700, color: '#ffffff' }}>
                      Route &amp; Schema Contract Deltas
                    </h4>
                    {breakingChangesCount > 0 && (
                      <Badge variant="critical" size="sm">
                        Breaking mutations detected
                      </Badge>
                    )}
                  </div>

                  {diff === null ? (
                    <EmptyState
                      icon={<AlertTriangle size={24} />}
                      title="Structural diff unavailable"
                      description="Contract compatibility cannot be assessed until structural diff evidence loads successfully."
                    />
                  ) : breakingChangesCount === 0 ? (
                    <EmptyState
                      icon={<CheckCircle2 size={24} style={{ color: 'var(--success-text)' }} />}
                      title="Zero breaking changes detected"
                      description="No route or schema deltas were detected in the available structural diff. This is not a compatibility guarantee."
                    />
                  ) : (
                    <>
                      {diff?.route_deltas?.map((rDelta, idx) => (
                        <div
                          key={idx}
                          style={{
                            padding: '1rem',
                            background: 'rgba(239, 68, 68, 0.08)',
                            border: '1px solid rgba(239, 68, 68, 0.3)',
                            borderRadius: 'var(--radius-md)',
                          }}
                        >
                          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.35rem' }}>
                            <Badge variant="critical" size="sm">ROUTE DELTA</Badge>
                            <span style={{ fontSize: '0.875rem', fontWeight: 600, color: '#ffffff' }}>
                              {rDelta.head_http_method || rDelta.base_http_method} {rDelta.head_path || rDelta.base_path}
                            </span>
                          </div>
                          <p style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)' }}>
                            {rDelta.change_type} • {rDelta.details}
                          </p>
                        </div>
                      ))}

                      {diff?.schema_deltas?.map((sDelta, idx) => (
                        <div
                          key={idx}
                          style={{
                            padding: '1rem',
                            background: 'rgba(239, 68, 68, 0.08)',
                            border: '1px solid rgba(239, 68, 68, 0.3)',
                            borderRadius: 'var(--radius-md)',
                          }}
                        >
                          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.35rem' }}>
                            <Badge variant="critical" size="sm">SCHEMA DELTA</Badge>
                            <span style={{ fontSize: '0.875rem', fontWeight: 600, color: '#ffffff' }}>
                              {sDelta.model_name}.{sDelta.field_name}
                            </span>
                          </div>
                          <p style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)' }}>
                            {sDelta.change_type} • {sDelta.details}
                          </p>
                        </div>
                      ))}
                    </>
                  )}
                </div>
              )}

              {/* Tab: Affected Downstream Callers */}
              {centerTab === 'callers' && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                  <h4 style={{ fontSize: '0.9375rem', fontWeight: 700, color: '#ffffff' }}>
                    Affected Downstream Callers &amp; Dependencies ({impactsLoaded ? impacts.length : 'unavailable'})
                  </h4>

                  {!impactsLoaded ? (
                    <EmptyState
                      icon={<AlertTriangle size={24} />}
                      title="Downstream impact evidence unavailable"
                      description="Caller impact cannot be assessed until downstream impact evidence loads successfully."
                    />
                  ) : impacts.length === 0 ? (
                    <EmptyState
                      icon={<CheckCircle2 size={24} style={{ color: 'var(--success-text)' }} />}
                      title="No downstream callers affected"
                      description="No downstream caller impacts were returned by the available analysis. This is not proof that no consumers are affected."
                    />
                  ) : (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.65rem' }}>
                      {impacts.map((impact, idx) => (
                        <div
                          key={idx}
                          style={{
                            padding: '0.85rem 1rem',
                            background: 'rgba(5, 8, 18, 0.7)',
                            border: '1px solid var(--border-subtle)',
                            borderRadius: 'var(--radius-md)',
                            display: 'flex',
                            justifyContent: 'space-between',
                            alignItems: 'center',
                          }}
                        >
                          <div>
                            <div style={{ fontSize: '0.8125rem', fontWeight: 600, color: '#ffffff', fontFamily: 'var(--font-mono)' }}>
                              {impact.affected_symbol || impact.affected_file || impact.title}
                            </div>
                            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                              Impact type: {impact.impact_type} • Source: {impact.source_symbol || impact.source_file || 'File change'}
                            </div>
                          </div>
                          <Badge variant="cyan" size="sm">
                            {impact.severity || 'IMPACT'}
                          </Badge>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* Tab: Review Summary */}
              {centerTab === 'report' && (
                <div
                  style={{
                    fontSize: '0.875rem',
                    color: 'var(--text-light)',
                    lineHeight: 1.65,
                    whiteSpace: 'pre-wrap',
                    fontFamily: 'var(--font-sans)',
                  }}
                >
                  {review?.summary || 'No review summary generated yet.'}
                </div>
              )}
            </div>
          </div>

          {/* RIGHT PANE: Review Findings & Safe PR Publication Gate */}
          <div
            className="glass-panel"
            style={{
              padding: '1.25rem',
              display: 'flex',
              flexDirection: 'column',
              gap: '1.25rem',
              overflowY: 'auto',
            }}
          >
            {/* Review Findings Section */}
            <div>
              <div style={{ fontSize: '0.8125rem', fontWeight: 700, color: 'var(--text-primary)', textTransform: 'uppercase', letterSpacing: '0.04em', marginBottom: '0.75rem' }}>
                Review Findings ({review === null ? 'unavailable' : review.findings?.length ?? 0})
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.65rem' }}>
                {(!review?.findings || review.findings.length === 0) ? (
                  <div style={{ fontSize: '0.8125rem', color: 'var(--text-muted)' }}>
                    {review === null
                      ? 'Review evidence is unavailable.'
                      : 'No automated review findings were returned; this is not a safety guarantee.'}
                  </div>
                ) : (
                  review.findings.map((item, idx) => (
                    <div
                      key={idx}
                      style={{
                        padding: '0.85rem',
                        borderRadius: 'var(--radius-md)',
                        backgroundColor: 'rgba(5, 8, 18, 0.7)',
                        border: '1px solid var(--border-subtle)',
                      }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem', marginBottom: '0.3rem' }}>
                        <Badge
                          variant={
                            item.severity === 'CRITICAL'
                              ? 'critical'
                              : item.severity === 'HIGH'
                              ? 'high'
                              : item.severity === 'MEDIUM'
                              ? 'medium'
                              : 'low'
                          }
                          size="sm"
                        >
                          {item.severity}
                        </Badge>
                        <span style={{ fontSize: '0.8125rem', fontWeight: 600, color: '#ffffff' }}>
                          {item.title}
                        </span>
                      </div>
                      <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', lineHeight: 1.45 }}>
                        {item.reasoning_summary}
                      </p>
                    </div>
                  ))
                )}
              </div>
            </div>

            {/* Safe GitHub Review Publication Card */}
            <div
              style={{
                marginTop: 'auto',
                padding: '1rem',
                borderRadius: 'var(--radius-lg)',
                background: 'linear-gradient(135deg, rgba(99, 102, 241, 0.12) 0%, rgba(5, 8, 18, 0.85) 100%)',
                border: '1px solid var(--border-glass-hover)',
                display: 'flex',
                flexDirection: 'column',
                gap: '0.75rem',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <Lock size={15} style={{ color: 'var(--accent-cyan)' }} />
                <span style={{ fontSize: '0.875rem', fontWeight: 700, color: '#ffffff' }}>
                  Safe PR Review Publication
                </span>
              </div>

              <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', lineHeight: 1.45 }}>
                Publish verified inline comments to GitHub pull request. Requires explicit human authorization.
              </p>

              {publishMessage && (
                <div style={{ fontSize: '0.75rem', color: 'var(--accent-cyan)', padding: '0.35rem 0.5rem', background: 'rgba(56, 189, 248, 0.1)', borderRadius: 'var(--radius-sm)' }}>
                  {publishMessage}
                </div>
              )}

              {publication ? (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.65rem' }}>
                  <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                    Digest: {publication.preview_digest?.slice(0, 16)}...
                  </div>

                  <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.75rem', color: 'var(--text-light)', cursor: 'pointer' }}>
                    <input
                      type="checkbox"
                      checked={confirmedPublish}
                      onChange={(e) => setConfirmedPublish(e.target.checked)}
                      disabled={!isOperator || publication.status === 'PUBLISHED'}
                    />
                    <span>I authorize posting this review to GitHub</span>
                  </label>

                  <Button
                    variant="glow"
                    size="sm"
                    onClick={handleApproveAndPublish}
                    disabled={publication.status === 'PUBLISHED' || !confirmedPublish || isPublishing || !isOperator}
                    isLoading={isPublishing}
                    leftIcon={<Send size={13} />}
                  >
                    {publication.status === 'PUBLISHED' ? 'Review Already Published' : isOperator ? 'Approve & Publish to PR' : 'Operator Required to Publish'}
                  </Button>
                </div>
              ) : (
                <Button
                  variant="secondary"
                  size="sm"
                  onClick={handleGeneratePreview}
                  leftIcon={<Eye size={13} />}
                >
                  Generate Review Preview
                </Button>
              )}
            </div>
          </div>
        </div>
      </div>
    </AppShell>
  );
}
