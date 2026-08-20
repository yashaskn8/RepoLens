'use client';

import React, { useEffect, useState } from 'react';
import { HealthResponse } from '@/types/domain';
import { fetchHealth } from '@/lib/api';

export default function HomePage() {
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState<boolean>(true);

  useEffect(() => {
    fetchHealth()
      .then((data) => {
        setHealth(data);
        setLoading(false);
      })
      .catch((err) => {
        setError(err.message || 'Failed to connect to backend');
        setLoading(false);
      });
  }, []);

  return (
    <main className="container">
      {/* Header */}
      <header className="header">
        <div className="brand">
          <div className="brand-icon">RL</div>
          <div className="brand-title">RepoLens</div>
        </div>
        <div>
          {loading ? (
            <span className="status-badge">Checking backend...</span>
          ) : error ? (
            <span className="status-badge" style={{ borderColor: 'rgba(239, 68, 68, 0.4)', color: '#fca5a5' }}>
              Backend offline (local dev)
            </span>
          ) : (
            <span className="status-badge">
              <span className="status-dot" />
              {health?.service} v{health?.version} ({health?.database})
            </span>
          )}
        </div>
      </header>

      {/* Hero Section */}
      <section className="hero">
        <div className="hero-pill">Phase 1A: Project Foundation</div>
        <h1>AI-Powered Code Intelligence & Repository Analysis</h1>
        <p>
          RepoLens provides deep repository inspection, multi-stage static analysis,
          and automated remediation for modern development teams.
        </p>
      </section>

      {/* Grid: Architecture & Domain Schemas */}
      <div className="grid-2">
        <div className="glass-card">
          <div className="card-title">
            <span>Canonical Domain Entities</span>
            <span className="badge-tag">Type-Safe</span>
          </div>
          <div className="schema-list">
            <div className="schema-item">
              <span className="schema-name">Scan</span>
              <span className="badge-tag">Lifecycle & Findings Container</span>
            </div>
            <div className="schema-item">
              <span className="schema-name">Finding</span>
              <span className="badge-tag">Categorized Issue & Guidance</span>
            </div>
            <div className="schema-item">
              <span className="schema-name">Evidence</span>
              <span className="badge-tag">File Snippet & Line Range</span>
            </div>
            <div className="schema-item">
              <span className="schema-name">ModelExecutionMetadata</span>
              <span className="badge-tag">Tokens & Telemetry</span>
            </div>
          </div>
        </div>

        <div className="glass-card">
          <div className="card-title">
            <span>Enums & Lifecycles</span>
            <span className="badge-tag">Domain Enums</span>
          </div>
          <div className="schema-list">
            <div className="schema-item">
              <span className="schema-name">Severity</span>
              <span className="badge-tag">CRITICAL | HIGH | MEDIUM | LOW | INFO</span>
            </div>
            <div className="schema-item">
              <span className="schema-name">FindingStatus</span>
              <span className="badge-tag">OPEN | RESOLVED | FALSE_POSITIVE | SUPPRESSED</span>
            </div>
            <div className="schema-item">
              <span className="schema-name">ScanStatus</span>
              <span className="badge-tag">PENDING | RUNNING | COMPLETED | FAILED</span>
            </div>
            <div className="schema-item">
              <span className="schema-name">Database</span>
              <span className="badge-tag">SQLite (Dev) / PostgreSQL (Prod)</span>
            </div>
          </div>
        </div>
      </div>

      {/* Backend Health Panel */}
      <div className="glass-card">
        <div className="card-title">
          <span>Backend Health Check</span>
          <span className="badge-tag">GET /health</span>
        </div>
        <pre className="code-block">
          {loading
            ? 'Loading status...'
            : error
            ? `Connection Notice: Start the backend with 'uvicorn app.main:app --reload' on port 8000.\nDetail: ${error}`
            : JSON.stringify(health, null, 2)}
        </pre>
      </div>
    </main>
  );
}
