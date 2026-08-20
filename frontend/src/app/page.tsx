'use client';

import React, { useEffect, useState } from 'react';
import {
  Finding,
  HealthResponse,
  Scan,
  Severity,
  VerificationVerdict,
} from '@/types/domain';
import { fetchHealth, fetchScan, fetchScanFindings, startScan } from '@/lib/api';
import { RemediationLifecycle } from '@/components/RemediationLifecycle';

export default function HomePage() {
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [repoUrl, setRepoUrl] = useState<string>('https://github.com/yashaskn8/RepoLens');
  const [branch, setBranch] = useState<string>('main');
  const [activeScan, setActiveScan] = useState<Scan | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [isSubmitting, setIsSubmitting] = useState<boolean>(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [verdictFilter, setVerdictFilter] = useState<string>('ALL');
  const [expandedFindingId, setExpandedFindingId] = useState<string | null>(null);

  // 1. Initial health check
  useEffect(() => {
    fetchHealth()
      .then((data) => setHealth(data))
      .catch(() => setHealth(null));
  }, []);

  // 2. Poll active scan status
  useEffect(() => {
    if (!activeScan || activeScan.status === 'COMPLETED' || activeScan.status === 'FAILED') {
      return;
    }

    const interval = setInterval(async () => {
      try {
        const updated = await fetchScan(activeScan.id);
        setActiveScan(updated);

        if (updated.status === 'COMPLETED') {
          const scanFindings = await fetchScanFindings(updated.id);
          setFindings(scanFindings);
        }
      } catch (err: unknown) {
        console.error('Polling error:', err);
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

  const filteredFindings = findings.filter((f) => {
    const matchesSeverity = severityFilter === 'ALL' || f.severity === severityFilter;
    const matchesVerdict =
      verdictFilter === 'ALL' ||
      (verdictFilter === 'CONFIRMED' && f.verification_verdict === 'CONFIRMED') ||
      (verdictFilter === 'POSSIBLE' && f.verification_verdict === 'POSSIBLE');
    return matchesSeverity && matchesVerdict;
  });

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

  const archOverview = activeScan?.model_metadata?.extra_metadata?.architecture_overview as string | undefined;
  const frameworks = (activeScan?.model_metadata?.extra_metadata?.frameworks as string[]) || [];
  const languages = (activeScan?.model_metadata?.extra_metadata?.languages as Record<string, number>) || {};

  return (
    <main className="container">
      {/* Header */}
      <header className="header">
        <div className="brand">
          <div className="brand-icon">RL</div>
          <div>
            <div className="brand-title">RepoLens</div>
            <div style={{ fontSize: '0.75rem', color: '#94a3b8' }}>AI Code Intelligence & Security</div>
          </div>
        </div>
        <div>
          {health ? (
            <span className="status-badge">
              <span className="status-dot" />
              {health.service} v{health.version} ({health.database})
            </span>
          ) : (
            <span className="status-badge" style={{ borderColor: 'rgba(239, 68, 68, 0.4)', color: '#fca5a5' }}>
              Backend offline
            </span>
          )}
        </div>
      </header>

      {/* Hero */}
      <section className="hero">
        <div className="hero-pill">Multi-Agent Static & LLM Analysis</div>
        <h1>Deterministic Evidence & Multi-Agent Intelligence</h1>
        <p>
          Analyze public GitHub repositories with Tree-sitter AST structural parsing, Semgrep, Trivy, OSV-Scanner,
          and parallel specialist agents grounded in source evidence.
        </p>
      </section>

      {/* Scan Input Form */}
      <div className="glass-card" style={{ marginBottom: '2rem' }}>
        <div className="card-title">
          <span>Analyze Public GitHub Repository</span>
          <span className="badge-tag">HTTPS Only</span>
        </div>

        <form onSubmit={handleStartScan} style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}>
            <input
              type="text"
              className="search-input"
              value={repoUrl}
              onChange={(e) => setRepoUrl(e.target.value)}
              placeholder="https://github.com/owner/repository"
              style={{ flex: 1, minWidth: '280px' }}
              disabled={isSubmitting || (activeScan?.status === 'PENDING' || activeScan?.status === 'RUNNING')}
            />
            <input
              type="text"
              className="search-input"
              value={branch}
              onChange={(e) => setBranch(e.target.value)}
              placeholder="main"
              style={{ width: '120px' }}
              disabled={isSubmitting || (activeScan?.status === 'PENDING' || activeScan?.status === 'RUNNING')}
            />
            <button
              type="submit"
              className="btn-primary"
              disabled={isSubmitting || (activeScan?.status === 'PENDING' || activeScan?.status === 'RUNNING')}
            >
              {isSubmitting || activeScan?.status === 'PENDING' || activeScan?.status === 'RUNNING'
                ? 'Analyzing...'
                : 'Analyze Repository'}
            </button>
          </div>

          {errorMsg && (
            <div className="error-banner">
              ⚠️ {errorMsg}
            </div>
          )}
        </form>
      </div>

      {/* Scan Status & Progress Indicator */}
      {activeScan && (
        <div className="glass-card" style={{ marginBottom: '2rem' }}>
          <div className="card-title">
            <span>Scan Lifecycle Progress</span>
            <span
              className="badge-tag"
              style={{
                background:
                  activeScan.status === 'COMPLETED'
                    ? 'rgba(34, 197, 94, 0.2)'
                    : activeScan.status === 'FAILED'
                    ? 'rgba(239, 68, 68, 0.2)'
                    : 'rgba(59, 130, 246, 0.2)',
                color:
                  activeScan.status === 'COMPLETED'
                    ? '#4ade80'
                    : activeScan.status === 'FAILED'
                    ? '#fca5a5'
                    : '#93c5fd',
              }}
            >
              {activeScan.status}
            </span>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '1rem', marginTop: '1rem' }}>
            <div>
              <div style={{ fontSize: '0.75rem', color: '#94a3b8' }}>SCAN ID</div>
              <div style={{ fontFamily: 'monospace', fontSize: '0.85rem' }}>{activeScan.id}</div>
            </div>
            <div>
              <div style={{ fontSize: '0.75rem', color: '#94a3b8' }}>REPOSITORY</div>
              <div style={{ fontSize: '0.85rem' }}>{activeScan.repository_url}</div>
            </div>
            <div>
              <div style={{ fontSize: '0.75rem', color: '#94a3b8' }}>COMMIT SHA</div>
              <div style={{ fontFamily: 'monospace', fontSize: '0.85rem' }}>{activeScan.commit_hash || 'Resolving...'}</div>
            </div>
            <div>
              <div style={{ fontSize: '0.75rem', color: '#94a3b8' }}>VERIFIED FINDINGS</div>
              <div style={{ fontSize: '1.1rem', fontWeight: 600, color: '#38bdf8' }}>{activeScan.findings_count}</div>
            </div>
          </div>

          {(activeScan.status === 'PENDING' || activeScan.status === 'RUNNING') && (
            <div style={{ marginTop: '1.25rem' }}>
              <div className="progress-bar-container">
                <div className="progress-bar-animated" />
              </div>
              <div style={{ fontSize: '0.8rem', color: '#94a3b8', marginTop: '0.5rem', textAlign: 'center' }}>
                Executing shallow clone, deterministic parsing (Semgrep/Trivy/OSV), and LangGraph specialists...
              </div>
            </div>
          )}
        </div>
      )}

      {/* Architecture Summary */}
      {activeScan?.status === 'COMPLETED' && (
        <div className="glass-card" style={{ marginBottom: '2rem' }}>
          <div className="card-title">
            <span>Repository Intelligence & Architecture</span>
            <span className="badge-tag">Mapper Analysis</span>
          </div>

          {archOverview && (
            <div style={{ marginBottom: '1rem', lineHeight: '1.6', color: '#cbd5e1' }}>
              {archOverview}
            </div>
          )}

          <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap', marginTop: '0.75rem' }}>
            {Object.entries(languages).map(([lang, count]) => (
              <span key={lang} className="pill-tag">
                {lang}: {count} files
              </span>
            ))}
            {frameworks.map((fw) => (
              <span key={fw} className="pill-tag" style={{ background: 'rgba(56, 189, 248, 0.15)', borderColor: 'rgba(56, 189, 248, 0.3)', color: '#38bdf8' }}>
                Framework: {fw}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Findings Section */}
      {activeScan?.status === 'COMPLETED' && (
        <div className="glass-card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem', marginBottom: '1.5rem' }}>
            <div>
              <h2 style={{ margin: 0, fontSize: '1.25rem' }}>Verified Grounded Findings ({filteredFindings.length})</h2>
              <div style={{ fontSize: '0.8rem', color: '#94a3b8' }}>
                Validated against source evidence with false-positive rejection
              </div>
            </div>

            {/* Severity Filter */}
            <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
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
          </div>

          {filteredFindings.length === 0 ? (
            <div style={{ padding: '3rem 1rem', textAlign: 'center', color: '#94a3b8' }}>
              <div style={{ fontSize: '2rem', marginBottom: '0.5rem' }}>🛡️</div>
              No findings matching the selected filters.
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
              {filteredFindings.map((finding) => (
                <div key={finding.id} className="finding-card">
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: '1rem', flexWrap: 'wrap' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
                      <span className={`badge ${getSeverityBadgeClass(finding.severity)}`}>
                        {finding.severity}
                      </span>
                      {finding.verification_verdict && (
                        <span
                          className="badge"
                          style={{
                            background:
                              finding.verification_verdict === 'CONFIRMED'
                                ? 'rgba(34, 197, 94, 0.2)'
                                : 'rgba(234, 179, 8, 0.2)',
                            color: finding.verification_verdict === 'CONFIRMED' ? '#4ade80' : '#fde047',
                            borderColor:
                              finding.verification_verdict === 'CONFIRMED'
                                ? 'rgba(34, 197, 94, 0.4)'
                                : 'rgba(234, 179, 8, 0.4)',
                          }}
                        >
                          {finding.verification_verdict}
                        </span>
                      )}
                      <span style={{ fontSize: '0.8rem', color: '#94a3b8', textTransform: 'uppercase' }}>
                        {finding.category || 'General'}
                      </span>
                    </div>

                    {finding.model_metadata && (
                      <span style={{ fontSize: '0.75rem', color: '#64748b' }}>
                        Agent: {finding.model_metadata.provider || 'AI'} ({finding.model_metadata.model_name})
                      </span>
                    )}
                  </div>

                  <h3 style={{ margin: '0.75rem 0 0.5rem 0', fontSize: '1.1rem', color: '#f8fafc' }}>
                    {finding.title}
                  </h3>

                  <p style={{ margin: '0 0 1rem 0', fontSize: '0.9rem', color: '#cbd5e1', lineHeight: '1.5' }}>
                    {finding.description}
                  </p>

                  {/* Verification Rationale */}
                  {finding.verification_reason && (
                    <div style={{ fontSize: '0.8rem', color: '#94a3b8', background: 'rgba(15, 23, 42, 0.4)', padding: '0.5rem 0.75rem', borderRadius: '4px', marginBottom: '0.75rem' }}>
                      <strong style={{ color: '#e2e8f0' }}>Verification: </strong>
                      {finding.verification_reason}
                    </div>
                  )}

                  {/* Evidence Display */}
                  {finding.evidences && finding.evidences.length > 0 && (
                    <div className="evidence-box">
                      <div style={{ fontSize: '0.8rem', fontWeight: 600, color: '#38bdf8', marginBottom: '0.5rem' }}>
                        📍 {finding.evidences[0].file_path}
                        {finding.evidences[0].start_line ? ` (Lines ${finding.evidences[0].start_line}-${finding.evidences[0].end_line || finding.evidences[0].start_line})` : ''}
                      </div>

                      {finding.evidences[0].code_snippet && (
                        <pre className="code-snippet">
                          {finding.evidences[0].code_snippet}
                        </pre>
                      )}
                    </div>
                  )}

                  {/* Mitigation Guidance */}
                  {finding.mitigation_guidance && (
                    <div style={{ marginTop: '0.75rem', fontSize: '0.85rem', color: '#a7f3d0' }}>
                      <strong>Remediation: </strong>
                      {finding.mitigation_guidance}
                    </div>
                  )}

                  {/* Remediation Lifecycle Action Button */}
                  <div style={{ marginTop: '1rem', display: 'flex', justifyContent: 'flex-end' }}>
                    <button
                      type="button"
                      className="filter-btn"
                      style={{
                        background: expandedFindingId === finding.id ? 'rgba(56, 189, 248, 0.2)' : 'rgba(30, 41, 59, 0.8)',
                        borderColor: expandedFindingId === finding.id ? '#38bdf8' : 'rgba(71, 85, 105, 0.5)',
                        color: expandedFindingId === finding.id ? '#38bdf8' : '#cbd5e1',
                        fontSize: '0.8rem',
                        fontWeight: 600,
                        padding: '0.4rem 0.85rem',
                      }}
                      onClick={() => setExpandedFindingId(expandedFindingId === finding.id ? null : finding.id)}
                    >
                      {expandedFindingId === finding.id ? 'Hide Remediation & Patch ▴' : '🛠️ Remediate & Safe Patch ▾'}
                    </button>
                  </div>

                  {/* Embedded Remediation Lifecycle */}
                  {expandedFindingId === finding.id && (
                    <div style={{ marginTop: '1.25rem' }}>
                      <RemediationLifecycle finding={finding} />
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </main>
  );
}
