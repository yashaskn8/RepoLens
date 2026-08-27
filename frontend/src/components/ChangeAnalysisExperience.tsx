'use client';

import React, { useEffect, useState } from 'react';
import {
  ChangeAnalysisPRRequest,
  ChangeAnalysisReportResponse,
  ChangeAnalysisRequest,
  ChangeAnalysisResponse,
  ChangeAnalysisStatus,
  ChangeAnalysisTelemetry,
  ChangeImpact,
  ChangeReviewFinding,
  ConfigDelta,
  DependencyDelta,
  RouteContractDelta,
  SchemaModelDelta,
  Severity,
} from '@/types/domain';
import {
  downloadChangeAnalysisMarkdown,
  fetchChangeAnalysis,
  fetchChangeAnalysisDiff,
  fetchChangeAnalysisImpacts,
  fetchChangeAnalysisReport,
  fetchChangeAnalysisReview,
  fetchChangeAnalysisTelemetry,
  startChangeAnalysis,
  startChangeAnalysisFromPR,
} from '@/lib/api';
import { useWorkflowStream } from '@/lib/useWorkflowStream';

export function ChangeAnalysisExperience() {
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

  // UI exploration tabs & filters
  const [activeTab, setActiveTab] = useState<'IMPACTS' | 'CONTRACTS' | 'REVIEW' | 'REPORT' | 'TELEMETRY'>('IMPACTS');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [expandedImpactId, setExpandedImpactId] = useState<string | null>(null);
  const [expandedFindingId, setExpandedFindingId] = useState<string | null>(null);
  const [copiedReport, setCopiedReport] = useState<boolean>(false);

  // SSE Workflow Event Stream
  const { events: workflowEvents, status: streamStatus } = useWorkflowStream(
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
      const [fetchedImpacts, fetchedReview, fetchedReport, fetchedTelemetry, fetchedDiff] = await Promise.all([
        fetchChangeAnalysisImpacts(analysisId).catch(() => []),
        fetchChangeAnalysisReview(analysisId).catch(() => null),
        fetchChangeAnalysisReport(analysisId).catch(() => null),
        fetchChangeAnalysisTelemetry(analysisId).catch(() => null),
        fetchChangeAnalysisDiff(analysisId).catch(() => null),
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
    } catch (err) {
      console.error('Failed to load completed analysis artifacts:', err);
    }
  };

  const handleStartAnalysis = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg(null);
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

  // Severity badge helpers
  const getSeverityBadgeClass = (sev: Severity) => {
    switch (sev) {
      case 'CRITICAL':
        return 'badge-critical';
      case 'HIGH':
        return 'badge-high';
      case 'MEDIUM':
        return 'badge-medium';
      case 'LOW':
        return 'badge-low';
      default:
        return 'badge-info';
    }
  };

  const getRiskBadgeColor = (risk?: string | null) => {
    switch (risk) {
      case 'CRITICAL':
        return { bg: 'rgba(239, 68, 68, 0.2)', border: '#ef4444', text: '#f87171' };
      case 'HIGH':
        return { bg: 'rgba(249, 115, 22, 0.2)', border: '#f97316', text: '#fb923c' };
      case 'MEDIUM':
        return { bg: 'rgba(234, 179, 8, 0.2)', border: '#eab308', text: '#fde047' };
      case 'LOW':
      default:
        return { bg: 'rgba(59, 130, 246, 0.2)', border: '#3b82f6', text: '#60a5fa' };
    }
  };

  // Filtered impacts
  const filteredImpacts = impacts.filter((imp) => {
    const matchesSev = severityFilter === 'ALL' || imp.severity === severityFilter;
    const matchesStat = statusFilter === 'ALL' || imp.verification_status === statusFilter;
    return matchesSev && matchesStat;
  });

  const isRunning =
    activeAnalysis?.status === 'PENDING' ||
    activeAnalysis?.status === 'ACQUIRING' ||
    activeAnalysis?.status === 'DIFFING' ||
    activeAnalysis?.status === 'ANALYZING' ||
    activeAnalysis?.status === 'VERIFYING';

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '2rem' }}>
      {/* Input Section Card */}
      <div className="glass-card">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem' }}>
          <div className="card-title" style={{ margin: 0 }}>
            <span>🔍 Change Intelligence & PR Review</span>
            <span className="badge-tag">Evidence Grounded</span>
          </div>

          <div style={{ display: 'flex', gap: '0.5rem' }}>
            <button
              type="button"
              className={`filter-btn ${inputMode === 'PR' ? 'filter-btn-active' : ''}`}
              onClick={() => setInputMode('PR')}
              disabled={isRunning}
            >
              Public PR URL
            </button>
            <button
              type="button"
              className={`filter-btn ${inputMode === 'EXACT' ? 'filter-btn-active' : ''}`}
              onClick={() => setInputMode('EXACT')}
              disabled={isRunning}
            >
              Exact SHAs (Advanced)
            </button>
          </div>
        </div>

        <form onSubmit={handleStartAnalysis} style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          {inputMode === 'PR' ? (
            <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}>
              <input
                type="text"
                className="search-input"
                value={prUrl}
                onChange={(e) => setPrUrl(e.target.value)}
                placeholder="https://github.com/owner/repository/pull/123"
                style={{ flex: 1, minWidth: '320px' }}
                disabled={isSubmitting || isRunning}
              />
              <button type="submit" className="btn-primary" disabled={isSubmitting || isRunning}>
                {isSubmitting || isRunning ? 'Analyzing Revisions...' : 'Analyze Pull Request'}
              </button>
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
              <input
                type="text"
                className="search-input"
                value={repoUrl}
                onChange={(e) => setRepoUrl(e.target.value)}
                placeholder="https://github.com/owner/repository"
                disabled={isSubmitting || isRunning}
              />
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '0.75rem' }}>
                <input
                  type="text"
                  className="search-input"
                  value={baseSha}
                  onChange={(e) => setBaseSha(e.target.value)}
                  placeholder="Base 40-character commit SHA"
                  disabled={isSubmitting || isRunning}
                />
                <input
                  type="text"
                  className="search-input"
                  value={headSha}
                  onChange={(e) => setHeadSha(e.target.value)}
                  placeholder="Head 40-character commit SHA"
                  disabled={isSubmitting || isRunning}
                />
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '0.75rem' }}>
                <input
                  type="text"
                  className="search-input"
                  value={baseRef}
                  onChange={(e) => setBaseRef(e.target.value)}
                  placeholder="Base branch / ref (e.g. main)"
                  disabled={isSubmitting || isRunning}
                />
                <input
                  type="text"
                  className="search-input"
                  value={headRef}
                  onChange={(e) => setHeadRef(e.target.value)}
                  placeholder="Head branch / ref (e.g. feature/auth)"
                  disabled={isSubmitting || isRunning}
                />
              </div>
              <button
                type="submit"
                className="btn-primary"
                style={{ alignSelf: 'flex-start' }}
                disabled={isSubmitting || isRunning}
              >
                {isSubmitting || isRunning ? 'Analyzing Revisions...' : 'Analyze Changes'}
              </button>
            </div>
          )}

          {errorMsg && <div className="error-banner">⚠️ {errorMsg}</div>}
        </form>
      </div>

      {/* Active Analysis Lifecycle Banner */}
      {activeAnalysis && (
        <div className="glass-card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                <span
                  className="badge"
                  style={{
                    backgroundColor:
                      activeAnalysis.status === 'COMPLETED'
                        ? 'rgba(34, 197, 94, 0.2)'
                        : activeAnalysis.status === 'FAILED'
                        ? 'rgba(239, 68, 68, 0.2)'
                        : 'rgba(59, 130, 246, 0.2)',
                    color:
                      activeAnalysis.status === 'COMPLETED'
                        ? '#4ade80'
                        : activeAnalysis.status === 'FAILED'
                        ? '#fca5a5'
                        : '#93c5fd',
                  }}
                >
                  {activeAnalysis.status}
                </span>
                <span style={{ fontSize: '0.85rem', color: '#94a3b8' }}>ID: {activeAnalysis.id}</span>
              </div>

              {activeAnalysis.model_metadata?.pr_number && (
                <div style={{ marginTop: '0.5rem', fontSize: '1.1rem', fontWeight: 600 }}>
                  Pull Request #{activeAnalysis.model_metadata.pr_number}: {activeAnalysis.model_metadata.pr_title || ''}
                </div>
              )}

              <div style={{ marginTop: '0.35rem', fontSize: '0.85rem', color: '#cbd5e1' }}>
                <span style={{ fontFamily: 'monospace', color: '#38bdf8' }}>
                  {activeAnalysis.base_ref || 'base'} ({activeAnalysis.base_commit_sha.slice(0, 8)})
                </span>{' '}
                →{' '}
                <span style={{ fontFamily: 'monospace', color: '#a855f7' }}>
                  {activeAnalysis.head_ref || 'head'} ({activeAnalysis.head_commit_sha.slice(0, 8)})
                </span>
              </div>
            </div>

            {activeAnalysis.status === 'COMPLETED' && (
              <div style={{ display: 'flex', gap: '0.5rem' }}>
                <button type="button" className="btn-primary" onClick={handleDownloadMarkdown}>
                  📥 Download Report (.md)
                </button>
              </div>
            )}
          </div>

          {/* Running progress bar */}
          {isRunning && (
            <div style={{ marginTop: '1.25rem' }}>
              <div className="progress-bar-container">
                <div className="progress-bar-animated" />
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.75rem', color: '#94a3b8', marginTop: '0.5rem' }}>
                <span>Durable Workflow Pipeline: ACQUIRE → DIFF → IMPACT → REVIEW → VERIFY → COMPLETE</span>
                <span>Streaming SSE Events...</span>
              </div>
            </div>
          )}

          {/* Real-time SSE Workflow Events list if available */}
          {workflowEvents.length > 0 && (
            <div style={{ marginTop: '1.25rem', padding: '0.75rem', background: '#090d16', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.06)' }}>
              <div style={{ fontSize: '0.75rem', fontWeight: 600, color: '#94a3b8', marginBottom: '0.5rem' }}>
                DURABLE WORKFLOW AUDIT TRAIL ({workflowEvents.length} events)
              </div>
              <div style={{ maxHeight: '120px', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '0.25rem' }}>
                {workflowEvents.slice(-6).map((ev) => (
                  <div key={ev.id} style={{ fontSize: '0.8rem', fontFamily: 'monospace', color: '#cbd5e1' }}>
                    <span style={{ color: '#818cf8' }}>[{ev.stage || 'WORKFLOW'}]</span> {ev.message}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Overview Metrics and Deterministic Risk */}
      {activeAnalysis && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '1rem' }}>
          <div className="glass-card" style={{ padding: '1.25rem' }}>
            <div style={{ fontSize: '0.75rem', color: '#94a3b8' }}>FILES CHANGED</div>
            <div style={{ fontSize: '1.75rem', fontWeight: 800, color: '#f1f5f9' }}>
              {activeAnalysis.changed_files_count}
            </div>
          </div>

          <div className="glass-card" style={{ padding: '1.25rem' }}>
            <div style={{ fontSize: '0.75rem', color: '#94a3b8' }}>SYMBOLS CHANGED</div>
            <div style={{ fontSize: '1.75rem', fontWeight: 800, color: '#38bdf8' }}>
              {activeAnalysis.changed_symbols_count}
            </div>
          </div>

          <div className="glass-card" style={{ padding: '1.25rem' }}>
            <div style={{ fontSize: '0.75rem', color: '#94a3b8' }}>BLAST RADIUS (IMPACTED)</div>
            <div style={{ fontSize: '1.75rem', fontWeight: 800, color: '#fb923c' }}>
              {activeAnalysis.impacted_symbols_count}
            </div>
          </div>

          <div
            className="glass-card"
            style={{
              padding: '1.25rem',
              border: `1px solid ${getRiskBadgeColor(activeAnalysis.risk_level).border}`,
              background: getRiskBadgeColor(activeAnalysis.risk_level).bg,
            }}
          >
            <div style={{ fontSize: '0.75rem', color: '#94a3b8' }}>DETERMINISTIC RISK</div>
            <div
              style={{
                fontSize: '1.75rem',
                fontWeight: 800,
                color: getRiskBadgeColor(activeAnalysis.risk_level).text,
              }}
            >
              {activeAnalysis.risk_level || 'LOW'}
            </div>
          </div>
        </div>
      )}

      {/* Exploration Tabs */}
      {activeAnalysis && (
        <div className="glass-card">
          {/* Navigation Bar */}
          <div style={{ display: 'flex', gap: '0.5rem', borderBottom: '1px solid rgba(255,255,255,0.08)', paddingBottom: '1rem', marginBottom: '1.5rem', flexWrap: 'wrap' }}>
            <button
              type="button"
              className={`filter-btn ${activeTab === 'IMPACTS' ? 'filter-btn-active' : ''}`}
              onClick={() => setActiveTab('IMPACTS')}
            >
              💥 Blast Radius Explorer ({impacts.length})
            </button>
            <button
              type="button"
              className={`filter-btn ${activeTab === 'CONTRACTS' ? 'filter-btn-active' : ''}`}
              onClick={() => setActiveTab('CONTRACTS')}
            >
              ⚡ Contract Changes (
              {diffDeltas.route_deltas.length +
                diffDeltas.schema_deltas.length +
                diffDeltas.dependency_deltas.length +
                diffDeltas.config_deltas.length}
              )
            </button>
            <button
              type="button"
              className={`filter-btn ${activeTab === 'REVIEW' ? 'filter-btn-active' : ''}`}
              onClick={() => setActiveTab('REVIEW')}
            >
              🤖 Verified AI Review ({reviewFindings.length})
            </button>
            <button
              type="button"
              className={`filter-btn ${activeTab === 'REPORT' ? 'filter-btn-active' : ''}`}
              onClick={() => setActiveTab('REPORT')}
            >
              📄 Executive Report
            </button>
            <button
              type="button"
              className={`filter-btn ${activeTab === 'TELEMETRY' ? 'filter-btn-active' : ''}`}
              onClick={() => setActiveTab('TELEMETRY')}
            >
              📊 Telemetry
            </button>
          </div>

          {/* TAB 1: BLAST RADIUS IMPACT EXPLORER */}
          {activeTab === 'IMPACTS' && (
            <div>
              {/* Filters */}
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem', flexWrap: 'wrap', gap: '0.75rem' }}>
                <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
                  <span style={{ fontSize: '0.8rem', color: '#94a3b8' }}>Severity:</span>
                  {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((sev) => (
                    <button
                      key={sev}
                      type="button"
                      className={`filter-btn ${severityFilter === sev ? 'filter-btn-active' : ''}`}
                      onClick={() => setSeverityFilter(sev)}
                    >
                      {sev}
                    </button>
                  ))}
                </div>

                <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
                  <span style={{ fontSize: '0.8rem', color: '#94a3b8' }}>Status:</span>
                  {['ALL', 'FACT', 'INFERENCE', 'ASSUMPTION'].map((stat) => (
                    <button
                      key={stat}
                      type="button"
                      className={`filter-btn ${statusFilter === stat ? 'filter-btn-active' : ''}`}
                      onClick={() => setStatusFilter(stat)}
                    >
                      {stat}
                    </button>
                  ))}
                </div>
              </div>

              {/* Impact Cards */}
              {filteredImpacts.length === 0 ? (
                <div style={{ padding: '2rem', textAlign: 'center', color: '#94a3b8' }}>
                  No impact records matching the selected filters.
                </div>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                  {filteredImpacts.map((imp) => {
                    const isExpanded = expandedImpactId === imp.id;
                    return (
                      <div
                        key={imp.id}
                        className="finding-card"
                        style={{ cursor: 'pointer' }}
                        onClick={() => setExpandedImpactId(isExpanded ? null : imp.id)}
                      >
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '0.5rem' }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                            <span className={`badge ${getSeverityBadgeClass(imp.severity)}`}>{imp.severity}</span>
                            <span className="badge-tag">{imp.impact_type}</span>
                            <span
                              className="pill-tag"
                              style={{
                                color:
                                  imp.verification_status === 'FACT'
                                    ? '#4ade80'
                                    : imp.verification_status === 'INFERENCE'
                                    ? '#60a5fa'
                                    : '#fde047',
                              }}
                            >
                              {imp.verification_status}
                            </span>
                          </div>
                          <span style={{ fontSize: '0.8rem', color: '#94a3b8' }}>
                            {isExpanded ? '▲ Hide Evidence' : '▼ Expand Evidence'}
                          </span>
                        </div>

                        <div style={{ fontSize: '1rem', fontWeight: 600, marginTop: '0.6rem', color: '#f1f5f9' }}>
                          {imp.title}
                        </div>

                        <div style={{ fontSize: '0.875rem', color: '#cbd5e1', marginTop: '0.35rem' }}>
                          {imp.description}
                        </div>

                        {/* Visual Source -> Affected mapping */}
                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginTop: '0.75rem', fontSize: '0.825rem', fontFamily: 'monospace' }}>
                          <span style={{ color: '#38bdf8' }}>
                            {imp.source_file} {imp.source_symbol ? `(${imp.source_symbol})` : ''}
                          </span>
                          <span style={{ color: '#94a3b8' }}>→</span>
                          <span style={{ color: '#ec4899' }}>
                            {imp.affected_file} {imp.affected_symbol ? `(${imp.affected_symbol})` : ''}
                          </span>
                        </div>

                        {/* Expandable Evidence Drawer */}
                        {isExpanded && (
                          <div className="evidence-box" style={{ marginTop: '1rem' }} onClick={(e) => e.stopPropagation()}>
                            <div style={{ fontSize: '0.75rem', fontWeight: 600, color: '#94a3b8', marginBottom: '0.5rem' }}>
                              DETERMINISTIC EVIDENCE & CONTEXT PAYLOAD
                            </div>
                            <pre className="code-snippet">
                              {JSON.stringify(imp.evidence_payload || {}, null, 2)}
                            </pre>
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          )}

          {/* TAB 2: CONTRACT CHANGES */}
          {activeTab === 'CONTRACTS' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1.75rem' }}>
              {/* Route Contract Deltas */}
              <div>
                <div style={{ fontSize: '1.1rem', fontWeight: 600, marginBottom: '0.75rem', color: '#f1f5f9' }}>
                  🌐 API Route Contract Changes ({diffDeltas.route_deltas.length})
                </div>
                {diffDeltas.route_deltas.length === 0 ? (
                  <div style={{ color: '#94a3b8', fontSize: '0.875rem' }}>No API route contract changes detected.</div>
                ) : (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                    {diffDeltas.route_deltas.map((r, idx) => (
                      <div key={idx} className="finding-card">
                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                          <span className="badge badge-high">{r.change_type}</span>
                          <span style={{ fontFamily: 'monospace', fontWeight: 600 }}>{r.route_name}</span>
                          <span className="badge-tag">{r.file_path}</span>
                        </div>
                        <div style={{ marginTop: '0.5rem', fontSize: '0.875rem', color: '#cbd5e1' }}>
                          {r.details || `${r.base_path || ''} → ${r.head_path || ''}`}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Schema & Model Deltas */}
              <div>
                <div style={{ fontSize: '1.1rem', fontWeight: 600, marginBottom: '0.75rem', color: '#f1f5f9' }}>
                  📐 Data Schema & Model Deltas ({diffDeltas.schema_deltas.length})
                </div>
                {diffDeltas.schema_deltas.length === 0 ? (
                  <div style={{ color: '#94a3b8', fontSize: '0.875rem' }}>No schema or model field changes detected.</div>
                ) : (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                    {diffDeltas.schema_deltas.map((s, idx) => (
                      <div key={idx} className="finding-card">
                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                          <span className="badge badge-medium">{s.change_type}</span>
                          <span style={{ fontFamily: 'monospace', fontWeight: 600 }}>
                            {s.model_name}.{s.field_name}
                          </span>
                          <span className="badge-tag">{s.file_path}</span>
                        </div>
                        <div style={{ marginTop: '0.5rem', fontSize: '0.875rem', color: '#cbd5e1' }}>
                          Type: <span style={{ fontFamily: 'monospace', color: '#38bdf8' }}>{s.base_type || 'none'}</span> →{' '}
                          <span style={{ fontFamily: 'monospace', color: '#a855f7' }}>{s.head_type || 'none'}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Dependency Deltas */}
              <div>
                <div style={{ fontSize: '1.1rem', fontWeight: 600, marginBottom: '0.75rem', color: '#f1f5f9' }}>
                  📦 Package Dependencies ({diffDeltas.dependency_deltas.length})
                </div>
                {diffDeltas.dependency_deltas.length === 0 ? (
                  <div style={{ color: '#94a3b8', fontSize: '0.875rem' }}>No dependency manifest changes detected.</div>
                ) : (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                    {diffDeltas.dependency_deltas.map((d, idx) => (
                      <div key={idx} className="finding-card">
                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                          <span className="badge badge-info">{d.change_type}</span>
                          <span style={{ fontWeight: 600 }}>{d.package_name}</span>
                          <span className="badge-tag">{d.manifest_file}</span>
                        </div>
                        <div style={{ marginTop: '0.35rem', fontSize: '0.85rem', color: '#94a3b8' }}>
                          Version: {d.base_version || 'N/A'} → {d.head_version || 'N/A'}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}

          {/* TAB 3: VERIFIED AI REVIEW */}
          {activeTab === 'REVIEW' && (
            <div>
              {reviewFindings.length === 0 ? (
                <div style={{ padding: '2rem', textAlign: 'center', color: '#94a3b8' }}>
                  No AI review findings available or analysis is still in progress.
                </div>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                  {reviewFindings.map((rf) => {
                    const isExpanded = expandedFindingId === rf.id;
                    return (
                      <div
                        key={rf.id}
                        className="finding-card"
                        style={{ cursor: 'pointer' }}
                        onClick={() => setExpandedFindingId(isExpanded ? null : rf.id)}
                      >
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '0.5rem' }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                            <span className={`badge ${getSeverityBadgeClass(rf.severity)}`}>{rf.severity}</span>
                            <span className="badge-tag">{rf.risk_type}</span>
                            <span
                              className="pill-tag"
                              style={{
                                color: rf.verdict === 'CONFIRMED' ? '#4ade80' : '#60a5fa',
                              }}
                            >
                              {rf.verdict} ({Math.round(rf.confidence * 100)}%)
                            </span>
                          </div>
                          <span style={{ fontSize: '0.8rem', color: '#94a3b8' }}>
                            {isExpanded ? '▲ Hide Details' : '▼ View Details'}
                          </span>
                        </div>

                        <div style={{ fontSize: '1rem', fontWeight: 600, marginTop: '0.6rem', color: '#f1f5f9' }}>
                          {rf.title}
                        </div>

                        <div style={{ fontSize: '0.875rem', color: '#cbd5e1', marginTop: '0.35rem' }}>
                          {rf.reasoning_summary}
                        </div>

                        {/* Affected targets */}
                        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.4rem', marginTop: '0.75rem' }}>
                          {rf.affected_files.map((p, idx) => (
                            <span key={idx} className="badge-tag">
                              📄 {p}
                            </span>
                          ))}
                          {rf.affected_symbols.map((s, idx) => (
                            <span key={idx} className="badge-tag" style={{ color: '#38bdf8' }}>
                              🧩 {s}
                            </span>
                          ))}
                        </div>

                        {/* Expanded details */}
                        {isExpanded && (
                          <div className="evidence-box" style={{ marginTop: '1rem' }} onClick={(e) => e.stopPropagation()}>
                            <div style={{ fontSize: '0.75rem', fontWeight: 600, color: '#94a3b8', marginBottom: '0.35rem' }}>
                              GROUNDED EVIDENCE REFS
                            </div>
                            <div style={{ fontSize: '0.8rem', color: '#cbd5e1', marginBottom: '0.75rem' }}>
                              {rf.evidence_refs.join(', ') || 'Direct AST diff facts'}
                            </div>

                            {rf.assumptions && rf.assumptions.length > 0 && (
                              <>
                                <div style={{ fontSize: '0.75rem', fontWeight: 600, color: '#94a3b8', marginBottom: '0.35rem' }}>
                                  DISCLOSED ASSUMPTIONS
                                </div>
                                <ul style={{ fontSize: '0.8rem', color: '#cbd5e1', paddingLeft: '1.2rem', margin: 0 }}>
                                  {rf.assumptions.map((asm, idx) => (
                                    <li key={idx}>{asm}</li>
                                  ))}
                                </ul>
                              </>
                            )}
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          )}

          {/* TAB 4: EXECUTIVE REPORT & MARKDOWN */}
          {activeTab === 'REPORT' && (
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
                <span style={{ fontSize: '0.9rem', color: '#94a3b8' }}>
                  Deterministic Markdown Report with full provenance and limitations.
                </span>
                <div style={{ display: 'flex', gap: '0.5rem' }}>
                  <button type="button" className="filter-btn" onClick={handleCopyMarkdown}>
                    {copiedReport ? '✓ Copied!' : '📋 Copy Markdown'}
                  </button>
                  <button type="button" className="btn-primary" onClick={handleDownloadMarkdown}>
                    📥 Download (.md)
                  </button>
                </div>
              </div>

              {/* Analysis limitations banner */}
              <div style={{ padding: '0.75rem 1rem', background: 'rgba(59, 130, 246, 0.08)', border: '1px solid rgba(59, 130, 246, 0.25)', borderRadius: '8px', marginBottom: '1rem', fontSize: '0.825rem', color: '#93c5fd' }}>
                🛡️ <strong>Epistemic Guarantee:</strong> Analysis is grounded strictly in AST diff facts and dependency graph traversal. Repository test suites and CI pipelines were <strong>not executed</strong>.
              </div>

              <pre
                style={{
                  background: '#090d16',
                  border: '1px solid rgba(255,255,255,0.08)',
                  borderRadius: '8px',
                  padding: '1.25rem',
                  fontSize: '0.85rem',
                  fontFamily: 'monospace',
                  whiteSpace: 'pre-wrap',
                  color: '#e2e8f0',
                  maxHeight: '500px',
                  overflowY: 'auto',
                }}
              >
                {report?.markdown_report || 'Generating report...'}
              </pre>
            </div>
          )}

          {/* TAB 5: TELEMETRY */}
          {activeTab === 'TELEMETRY' && (
            <div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '1rem', marginBottom: '1.5rem' }}>
                <div className="glass-card" style={{ padding: '1rem' }}>
                  <div style={{ fontSize: '0.75rem', color: '#94a3b8' }}>EXECUTION TIME</div>
                  <div style={{ fontSize: '1.25rem', fontWeight: 700 }}>
                    {telemetry?.duration_ms ? `${(telemetry.duration_ms / 1000).toFixed(2)}s` : 'N/A'}
                  </div>
                </div>

                <div className="glass-card" style={{ padding: '1rem' }}>
                  <div style={{ fontSize: '0.75rem', color: '#94a3b8' }}>TOTAL TOKENS</div>
                  <div style={{ fontSize: '1.25rem', fontWeight: 700, color: '#38bdf8' }}>
                    {telemetry?.total_tokens || 0}
                  </div>
                </div>

                <div className="glass-card" style={{ padding: '1rem' }}>
                  <div style={{ fontSize: '0.75rem', color: '#94a3b8' }}>DIRECT IMPACTS</div>
                  <div style={{ fontSize: '1.25rem', fontWeight: 700, color: '#4ade80' }}>
                    {telemetry?.direct_impacts || 0}
                  </div>
                </div>

                <div className="glass-card" style={{ padding: '1rem' }}>
                  <div style={{ fontSize: '0.75rem', color: '#94a3b8' }}>TRANSITIVE IMPACTS</div>
                  <div style={{ fontSize: '1.25rem', fontWeight: 700, color: '#a855f7' }}>
                    {telemetry?.transitive_impacts || 0}
                  </div>
                </div>
              </div>

              <div className="evidence-box">
                <div style={{ fontSize: '0.75rem', fontWeight: 600, color: '#94a3b8', marginBottom: '0.5rem' }}>
                  RAW TELEMETRY PAYLOAD (NO SECRETS)
                </div>
                <pre className="code-snippet">{JSON.stringify(telemetry || {}, null, 2)}</pre>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
