'use client';

import React, { useState, useEffect, use } from 'react';
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
  fetchChangeAnalysis,
  fetchChangeAnalysisDiff,
  fetchChangeAnalysisImpacts,
  fetchChangeAnalysisReview,
  fetchReviewPublication,
  generateReviewPublicationPreview,
  approveReviewPublication,
  publishReviewPublication,
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
} from 'lucide-react';

interface ChangeDetailPageProps {
  params: Promise<{ id: string }>;
}

export default function ChangeDetailPage({ params }: ChangeDetailPageProps) {
  const resolvedParams = use(params);
  const analysisId = resolvedParams.id;
  const router = useRouter();
  const { isOperator } = useAuth();

  const [analysis, setAnalysis] = useState<ChangeAnalysisResponse | null>(null);
  const [diff, setDiff] = useState<StructuralDiffResult | null>(null);
  const [impacts, setImpacts] = useState<ChangeImpact[]>([]);
  const [review, setReview] = useState<ChangeReviewReport | null>(null);
  const [publication, setPublication] = useState<ReviewPublicationPreviewResponse | null>(null);

  const [centerTab, setCenterTab] = useState<'diff' | 'contracts' | 'report'>('diff');
  const [selectedFile, setSelectedFile] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isPublishing, setIsPublishing] = useState(false);
  const [confirmedPublish, setConfirmedPublish] = useState(false);
  const [publishMessage, setPublishMessage] = useState<string | null>(null);

  useEffect(() => {
    async function loadData() {
      try {
        const [analysisRes, diffRes, impactsRes, reviewRes, pubRes] = await Promise.allSettled([
          fetchChangeAnalysis(analysisId),
          fetchChangeAnalysisDiff(analysisId),
          fetchChangeAnalysisImpacts(analysisId),
          fetchChangeAnalysisReview(analysisId),
          fetchReviewPublication(analysisId),
        ]);

        if (analysisRes.status === 'fulfilled') setAnalysis(analysisRes.value);
        if (diffRes.status === 'fulfilled') {
          setDiff(diffRes.value);
          if (diffRes.value.changed_files?.length > 0) {
            setSelectedFile(diffRes.value.changed_files[0].file_path);
          }
        }
        if (impactsRes.status === 'fulfilled') setImpacts(impactsRes.value || []);
        if (reviewRes.status === 'fulfilled') setReview(reviewRes.value);
        if (pubRes.status === 'fulfilled') setPublication(pubRes.value);
      } finally {
        setIsLoading(false);
      }
    }

    loadData();
  }, [analysisId]);

  const handleGeneratePreview = async () => {
    try {
      const pub = await generateReviewPublicationPreview(analysisId);
      setPublication(pub);
    } catch (err: any) {
      setPublishMessage(err?.message || 'Failed to generate review preview.');
    }
  };

  const handleApproveAndPublish = async () => {
    if (!publication?.preview_digest) return;
    setIsPublishing(true);
    setPublishMessage(null);

    try {
      await approveReviewPublication(analysisId, publication.preview_digest);
      const res = await publishReviewPublication(analysisId, publication.preview_digest);
      setPublishMessage(`Review published successfully to GitHub (Review ID: ${res.github_review_id || 'OK'})`);
      const updatedPub = await fetchReviewPublication(analysisId);
      setPublication(updatedPub);
    } catch (err: any) {
      setPublishMessage(err?.message || 'Failed to publish review to GitHub.');
    } finally {
      setIsPublishing(false);
    }
  };

  const currentFileDiff = diff?.changed_files?.find((f: FileDiffFact) => f.file_path === selectedFile) || diff?.changed_files?.[0];

  return (
    <AppShell
      breadcrumbs={[
        { label: 'Change Intelligence', href: '/change-analysis' },
        { label: analysis ? `${analysis.repository_owner}/${analysis.repository_name}` : analysisId.slice(0, 8) },
      ]}
      title="Change Intelligence Workspace"
    >
      <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem', height: 'calc(100vh - 8rem)' }}>
        {/* Workspace Top Bar */}
        <div
          className="glass-panel"
          style={{
            padding: '1.25rem 1.75rem',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            flexWrap: 'wrap',
            gap: '1rem',
            border: '1px solid var(--border-glass-hover)',
          }}
        >
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem', marginBottom: '0.25rem' }}>
              <GitPullRequest size={18} style={{ color: 'var(--accent-cyan)' }} />
              <h1 style={{ fontSize: '1.25rem', fontWeight: 800, fontFamily: 'var(--font-display)', color: '#ffffff' }}>
                {analysis ? `${analysis.repository_owner}/${analysis.repository_name}` : 'Change Analysis'}
              </h1>
              {analysis?.risk_level && (
                <Badge
                  variant={
                    analysis.risk_level === 'CRITICAL'
                      ? 'critical'
                      : analysis.risk_level === 'HIGH'
                      ? 'high'
                      : analysis.risk_level === 'MEDIUM'
                      ? 'medium'
                      : 'low'
                  }
                  size="sm"
                >
                  {analysis.risk_level} RISK
                </Badge>
              )}
            </div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
              Base: {analysis?.base_commit_sha?.slice(0, 8)} ➔ Head: {analysis?.head_commit_sha?.slice(0, 8)} •{' '}
              {analysis?.changed_files_count || 0} files touched • {impacts.length} impacts identified
            </div>
          </div>

          <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center' }}>
            <Badge variant="cyan" size="sm">
              Blast Radius: {analysis?.impacted_symbols_count || 0} symbols
            </Badge>
          </div>
        </div>

        {/* 3-PANE ENGINEERING REVIEW LAYOUT */}
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: '17rem minmax(0, 1fr) 22rem',
            gap: '1.25rem',
            flex: 1,
            minHeight: 0,
          }}
        >
          {/* LEFT PANE: Changed Files & Blast Radius Navigation */}
          <div
            className="glass-panel"
            style={{
              padding: '1.25rem',
              display: 'flex',
              flexDirection: 'column',
              gap: '1rem',
              overflowY: 'auto',
            }}
          >
            <div style={{ fontSize: '0.8125rem', fontWeight: 700, color: 'var(--text-primary)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
              Changed Files ({diff?.changed_files?.length || 0})
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

            {/* Impacted Contracts Summary */}
            <div style={{ marginTop: 'auto', borderTop: '1px solid var(--border-subtle)', paddingTop: '1rem' }}>
              <div style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-muted)', marginBottom: '0.5rem' }}>
                Impact Summary
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem', fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                <div>• Direct Files: {diff?.changed_files?.length || 0}</div>
                <div>• Route Deltas: {diff?.route_deltas?.length || 0}</div>
                <div>• Schema Deltas: {diff?.schema_deltas?.length || 0}</div>
              </div>
            </div>
          </div>

          {/* CENTER PANE: Unified Structural Diff & Contract Deltas */}
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
                  { id: 'diff', label: 'Structural Diff', icon: <FileDiff size={14} /> },
                  { id: 'contracts', label: 'Contract Deltas', count: (diff?.route_deltas?.length || 0) + (diff?.schema_deltas?.length || 0), icon: <Layers size={14} /> },
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
                        <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)' }}>
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

              {centerTab === 'contracts' && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                  <h4 style={{ fontSize: '0.9375rem', fontWeight: 700, color: '#ffffff' }}>
                    Route & Schema Contract Deltas
                  </h4>

                  {(!diff?.route_deltas || diff.route_deltas.length === 0) &&
                  (!diff?.schema_deltas || diff.schema_deltas.length === 0) ? (
                    <div style={{ color: 'var(--text-muted)', fontSize: '0.875rem' }}>
                      No breaking cross-layer contract mutations detected.
                    </div>
                  ) : (
                    <>
                      {diff?.route_deltas?.map((rDelta, idx) => (
                        <div
                          key={idx}
                          style={{
                            padding: '1rem',
                            background: 'rgba(5, 8, 18, 0.7)',
                            border: '1px solid var(--border-subtle)',
                            borderRadius: 'var(--radius-md)',
                          }}
                        >
                          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.35rem' }}>
                            <Badge variant="purple" size="sm">ROUTE DELTA</Badge>
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
                            background: 'rgba(5, 8, 18, 0.7)',
                            border: '1px solid var(--border-subtle)',
                            borderRadius: 'var(--radius-md)',
                          }}
                        >
                          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.35rem' }}>
                            <Badge variant="cyan" size="sm">SCHEMA DELTA</Badge>
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
                AI Review Findings ({review?.findings?.length || 0})
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.65rem' }}>
                {review?.findings?.map((item, idx) => (
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
                ))}
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
                      disabled={!isOperator}
                    />
                    <span>I authorize posting this review to GitHub</span>
                  </label>

                  <Button
                    variant="glow"
                    size="sm"
                    onClick={handleApproveAndPublish}
                    disabled={!confirmedPublish || isPublishing || !isOperator}
                    isLoading={isPublishing}
                    leftIcon={<Send size={13} />}
                  >
                    {isOperator ? 'Approve & Publish to PR' : 'Operator Required to Publish'}
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
