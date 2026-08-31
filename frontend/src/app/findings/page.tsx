'use client';

import React, { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { AppShell } from '@/components/layout/AppShell';
import { Card } from '@/components/ui/Card';
import { Button } from '@/components/ui/Button';
import { Badge } from '@/components/ui/Badge';
import { SearchInput } from '@/components/ui/Input';
import { EmptyState } from '@/components/ui/EmptyState';
import { Finding, Severity } from '@/types/domain';
import {
  ShieldAlert,
  Search,
  Filter,
  FileCode,
  CheckCircle2,
  AlertTriangle,
  Wrench,
  ChevronRight,
  SlidersHorizontal,
  Lock,
  Layers,
  Code2,
  ArrowRight,
  Sparkles,
  ExternalLink,
  Tag,
  ShieldCheck,
} from 'lucide-react';

const DEMO_FINDINGS: Finding[] = [
  {
    id: 'find-ast-101',
    scan_id: 'scan-demo-01',
    title: 'Unauthenticated Privilege Escalation in Handler',
    description: 'Handler endpoint permits modification of user role attribute without explicit OPERATOR permission check.',
    severity: 'CRITICAL',
    status: 'OPEN',
    rule_id: 'sec.auth.role-escalation',
    category: 'Authorization',
    verification_verdict: 'CONFIRMED',
    verification_reason: 'AST call graph demonstrates unrestricted write to role field in user_service.py:87.',
    detector_id: 'ast-rule-auth-04',
    detector_kind: 'AST_SEMANTIC',
    mitigation_guidance: 'Enforce require_operator dependency gate before processing user role mutation.',
    evidences: [
      {
        id: 'ev-1',
        file_path: 'backend/app/services/user_service.py',
        start_line: 84,
        end_line: 92,
        code_snippet: 'async def update_user(user_id: str, payload: UserUpdate):\n    # Missing permission check\n    user.role = payload.role\n    await db.commit()',
      },
    ],
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  },
  {
    id: 'find-ast-102',
    scan_id: 'scan-demo-01',
    title: 'Cross-Layer Contract Type Desynchronization',
    description: 'Frontend TypeScript interface expects UUID string while FastAPI controller emits integer ID.',
    severity: 'HIGH',
    status: 'OPEN',
    rule_id: 'contract.types.mismatch',
    category: 'API Contract',
    verification_verdict: 'CONFIRMED',
    verification_reason: 'Discrepancy detected between domain.ts:Scan.id (string) and backend schema scan.py:ScanRead.id (int).',
    detector_id: 'cross-layer-contract-checker',
    detector_kind: 'CROSS_LAYER_GRAPH',
    mitigation_guidance: 'Normalize Scan identifier to UUID string in Pydantic schema and database model.',
    evidences: [
      {
        id: 'ev-2',
        file_path: 'frontend/src/types/domain.ts',
        start_line: 42,
        end_line: 48,
        code_snippet: 'export interface Scan {\n  id: string;\n  repository_url: string;\n  status: ScanStatus;\n}',
      },
      {
        id: 'ev-3',
        file_path: 'backend/app/schemas/scan.py',
        start_line: 19,
        end_line: 24,
        code_snippet: 'class ScanRead(BaseModel):\n    id: int\n    repository_url: HttpUrl',
      },
    ],
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  },
  {
    id: 'find-ast-103',
    scan_id: 'scan-demo-01',
    title: 'CSRF Token Verification Bypass in State Mutation',
    description: 'State-modifying POST request route lacks CSRF cookie validation middleware enforcement.',
    severity: 'HIGH',
    status: 'OPEN',
    rule_id: 'sec.csrf.missing-header',
    category: 'CSRF Defense',
    verification_verdict: 'CONFIRMED',
    verification_reason: 'AST syntax tree verifies router endpoint lacks repolens_csrf double-submit cookie inspection.',
    detector_id: 'ast-rule-csrf-01',
    detector_kind: 'AST_SYNTACTIC',
    mitigation_guidance: 'Attach verify_csrf_token dependency middleware to all state-mutating routers.',
    evidences: [
      {
        id: 'ev-4',
        file_path: 'backend/app/api/v1/endpoints/settings.py',
        start_line: 35,
        end_line: 42,
        code_snippet: '@router.post("/settings")\nasync def update_settings(payload: SettingsUpdate):\n    return await settings_service.update(payload)',
      },
    ],
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  },
  {
    id: 'find-ast-104',
    scan_id: 'scan-demo-01',
    title: 'Secret Token Exposure in Error Response Body',
    description: 'Exception handler returns unredacted API key in detailed traceback payload.',
    severity: 'MEDIUM',
    status: 'OPEN',
    rule_id: 'sec.secret.unredacted-log',
    category: 'Information Disclosure',
    verification_verdict: 'CONFIRMED',
    verification_reason: 'Redaction regex scanner flags unmasked token pattern in exception serializer.',
    detector_id: 'secret-redaction-scanner',
    detector_kind: 'REGEX_STATIC',
    mitigation_guidance: 'Wrap exception formatting with redact_sensitive_patterns utility.',
    evidences: [
      {
        id: 'ev-5',
        file_path: 'backend/app/core/errors.py',
        start_line: 58,
        end_line: 64,
        code_snippet: 'def format_error(exc: Exception) -> dict:\n    return {"error": str(exc), "trace": traceback.format_exc()}',
      },
    ],
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  },
  {
    id: 'find-ast-105',
    scan_id: 'scan-demo-01',
    title: 'Missing Database Index on Query Filter Column',
    description: 'Frequently queried scan_id foreign key lacks database B-tree index in schema migration.',
    severity: 'LOW',
    status: 'OPEN',
    rule_id: 'perf.db.unindexed-fk',
    category: 'Performance',
    verification_verdict: 'CONFIRMED',
    verification_reason: 'Alembic revision 003 does not specify index=True on findings.scan_id column.',
    detector_id: 'schema-index-analyzer',
    detector_kind: 'AST_SEMANTIC',
    mitigation_guidance: 'Add index=True to SQLAlchemy ForeignKey definition and generate Alembic migration.',
    evidences: [
      {
        id: 'ev-6',
        file_path: 'backend/app/models/finding.py',
        start_line: 22,
        end_line: 27,
        code_snippet: 'scan_id = Column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)',
      },
    ],
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  },
];

export default function FindingsPage() {
  const router = useRouter();
  const [findings, setFindings] = useState<Finding[]>(DEMO_FINDINGS);
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [selectedFinding, setSelectedFinding] = useState<Finding>(DEMO_FINDINGS[0]);

  useEffect(() => {
    if (typeof window !== 'undefined') {
      const storedScans = localStorage.getItem('repolens_recent_scans');
      if (storedScans) {
        try {
          const scans = JSON.parse(storedScans);
          const allFindings: Finding[] = scans.flatMap((s: any) => s.findings || []);
          if (allFindings.length > 0) {
            setFindings(allFindings);
            setSelectedFinding(allFindings[0]);
          }
        } catch {
          // ignore
        }
      }
    }
  }, []);

  const filteredFindings = findings.filter((f) => {
    const matchesSearch =
      !search ||
      f.title.toLowerCase().includes(search.toLowerCase()) ||
      f.rule_id?.toLowerCase().includes(search.toLowerCase()) ||
      f.category?.toLowerCase().includes(search.toLowerCase());
    const matchesSeverity = severityFilter === 'ALL' || f.severity === severityFilter;
    return matchesSearch && matchesSeverity;
  });

  return (
    <AppShell breadcrumbs={[{ label: 'Findings Explorer' }]} title="Verified Security & Quality Findings">
      <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem', height: 'calc(100vh - 8rem)' }}>
        {/* Top Control Bar */}
        <div
          className="glass-panel"
          style={{
            padding: '0.85rem 1.25rem',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            gap: '1rem',
            flexWrap: 'wrap',
          }}
        >
          {/* Search Box */}
          <div style={{ flex: '1 1 280px', maxWidth: '28rem' }}>
            <SearchInput
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              onClear={() => setSearch('')}
              placeholder="Search rule ID, title, or category..."
            />
          </div>

          {/* Severity Filters */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem', flexWrap: 'wrap' }}>
            {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((sev) => {
              const isActive = severityFilter === sev;
              const count = sev === 'ALL' ? findings.length : findings.filter((f) => f.severity === sev).length;
              return (
                <button
                  key={sev}
                  type="button"
                  onClick={() => setSeverityFilter(sev)}
                  style={{
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '0.4rem',
                    padding: '0.35rem 0.75rem',
                    fontSize: '0.75rem',
                    fontWeight: 600,
                    borderRadius: 'var(--radius-sm)',
                    border: isActive ? '1px solid var(--border-glass-hover)' : '1px solid var(--border-subtle)',
                    background: isActive ? 'rgba(99, 102, 241, 0.22)' : 'rgba(255, 255, 255, 0.03)',
                    color: isActive ? '#ffffff' : 'var(--text-secondary)',
                    cursor: 'pointer',
                    transition: 'all var(--transition-fast)',
                  }}
                  className="interactive-btn"
                >
                  <span>{sev}</span>
                  <span
                    style={{
                      fontSize: '0.7rem',
                      padding: '0.05rem 0.4rem',
                      borderRadius: 'var(--radius-full)',
                      background: isActive ? 'rgba(255, 255, 255, 0.2)' : 'rgba(255, 255, 255, 0.06)',
                      color: isActive ? '#ffffff' : 'var(--text-muted)',
                    }}
                  >
                    {count}
                  </span>
                </button>
              );
            })}
          </div>
        </div>

        {/* Master-Detail Split Pane Layout */}
        <div
          style={{
            flex: 1,
            display: 'grid',
            gridTemplateColumns: 'minmax(320px, 420px) 1fr',
            gap: '1.25rem',
            minHeight: 0,
          }}
        >
          {/* Left Pane: Scrollable Findings List */}
          <div
            className="glass-panel"
            style={{
              display: 'flex',
              flexDirection: 'column',
              overflow: 'hidden',
              padding: '0.75rem',
            }}
          >
            <div style={{ padding: '0.5rem 0.5rem 0.75rem 0.5rem', borderBottom: '1px solid var(--border-subtle)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: '0.8125rem', fontWeight: 600, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                {filteredFindings.length} Verified Finding{filteredFindings.length !== 1 ? 's' : ''}
              </span>
              <Badge variant="cyan" size="sm">
                100% EVIDENCE
              </Badge>
            </div>

            <div
              style={{
                flex: 1,
                overflowY: 'auto',
                display: 'flex',
                flexDirection: 'column',
                gap: '0.4rem',
                paddingTop: '0.5rem',
              }}
            >
              {filteredFindings.length === 0 ? (
                <EmptyState
                  title="No findings match filter"
                  description="Try adjusting your severity or keyword filters."
                />
              ) : (
                filteredFindings.map((f) => {
                  const isSelected = selectedFinding?.id === f.id;
                  return (
                    <div
                      key={f.id}
                      onClick={() => setSelectedFinding(f)}
                      style={{
                        padding: '0.85rem 1rem',
                        borderRadius: 'var(--radius-md)',
                        backgroundColor: isSelected ? 'rgba(99, 102, 241, 0.16)' : 'rgba(5, 8, 18, 0.6)',
                        border: isSelected ? '1px solid var(--accent-primary)' : '1px solid var(--border-subtle)',
                        cursor: 'pointer',
                        transition: 'all var(--transition-fast)',
                        boxShadow: isSelected ? '0 0 15px rgba(99, 102, 241, 0.2), var(--shadow-inner-glow)' : 'none',
                      }}
                      className="interactive-btn"
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.35rem' }}>
                        <Badge variant={f.severity?.toLowerCase() || 'default'} size="sm">
                          {f.severity}
                        </Badge>
                        <span style={{ fontSize: '0.75rem', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
                          {f.rule_id}
                        </span>
                      </div>

                      <div style={{ fontSize: '0.875rem', fontWeight: 600, color: isSelected ? '#ffffff' : 'var(--text-primary)', marginBottom: '0.25rem', lineHeight: 1.3 }}>
                        {f.title}
                      </div>

                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                        <span>{f.category}</span>
                        <span style={{ color: 'var(--success-text)', display: 'flex', alignItems: 'center', gap: '0.2rem' }}>
                          <ShieldCheck size={12} />
                          {f.verification_verdict || 'VERIFIED'}
                        </span>
                      </div>
                    </div>
                  );
                })
              )}
            </div>
          </div>

          {/* Right Pane: Deep Investigation Detail Panel */}
          {selectedFinding ? (
            <div
              className="glass-panel"
              style={{
                display: 'flex',
                flexDirection: 'column',
                overflow: 'hidden',
                padding: '1.5rem',
              }}
            >
              {/* Detail Header */}
              <div style={{ borderBottom: '1px solid var(--border-subtle)', paddingBottom: '1.25rem', marginBottom: '1.25rem' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: '1rem', marginBottom: '0.75rem' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
                    <Badge variant={selectedFinding.severity?.toLowerCase() || 'default'} size="md">
                      {selectedFinding.severity}
                    </Badge>
                    <Badge variant="cyan" size="sm">
                      {selectedFinding.category}
                    </Badge>
                    <span style={{ fontSize: '0.8125rem', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
                      {selectedFinding.rule_id}
                    </span>
                  </div>

                  <Link href={`/remediation?findingId=${selectedFinding.id}`}>
                    <Button variant="glow" size="sm" rightIcon={<ArrowRight size={14} />}>
                      Remediate (7-Step Flow)
                    </Button>
                  </Link>
                </div>

                <h2
                  style={{
                    fontSize: '1.25rem',
                    fontWeight: 800,
                    fontFamily: 'var(--font-display)',
                    color: '#ffffff',
                    lineHeight: 1.3,
                  }}
                >
                  {selectedFinding.title}
                </h2>
                <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', marginTop: '0.35rem', lineHeight: 1.5 }}>
                  {selectedFinding.description}
                </p>
              </div>

              {/* Scrollable Content Body */}
              <div
                style={{
                  flex: 1,
                  overflowY: 'auto',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '1.25rem',
                  paddingRight: '0.25rem',
                }}
              >
                {/* Evidence Verification Section */}
                <div
                  style={{
                    padding: '1.1rem',
                    borderRadius: 'var(--radius-md)',
                    background: 'rgba(99, 102, 241, 0.08)',
                    border: '1px solid var(--border-glass-hover)',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.5rem' }}>
                    <CheckCircle2 size={16} style={{ color: 'var(--accent-cyan)' }} />
                    <span style={{ fontSize: '0.875rem', fontWeight: 700, color: '#ffffff' }}>
                      Deterministic AST Verification Reason
                    </span>
                  </div>
                  <p style={{ fontSize: '0.8125rem', color: 'var(--text-light)', lineHeight: 1.55 }}>
                    {selectedFinding.verification_reason}
                  </p>
                  <div style={{ marginTop: '0.5rem', display: 'flex', gap: '1rem', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                    <span>Detector: {selectedFinding.detector_id}</span>
                    <span>Kind: {selectedFinding.detector_kind}</span>
                  </div>
                </div>

                {/* AST Code Snippet Evidence */}
                {selectedFinding.evidences && selectedFinding.evidences.length > 0 && (
                  <div>
                    <span style={{ fontSize: '0.8125rem', fontWeight: 700, color: 'var(--text-primary)', textTransform: 'uppercase', letterSpacing: '0.05em', display: 'block', marginBottom: '0.5rem' }}>
                      Code Citation & AST Evidence ({selectedFinding.evidences.length})
                    </span>

                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                      {selectedFinding.evidences.map((ev, idx) => (
                        <div
                          key={ev.id || idx}
                          style={{
                            borderRadius: 'var(--radius-md)',
                            border: '1px solid var(--border-glass)',
                            overflow: 'hidden',
                            background: '#030611',
                          }}
                        >
                          <div
                            style={{
                              padding: '0.5rem 0.85rem',
                              borderBottom: '1px solid var(--border-subtle)',
                              background: 'rgba(255, 255, 255, 0.03)',
                              display: 'flex',
                              justifyContent: 'space-between',
                              alignItems: 'center',
                              fontSize: '0.75rem',
                              fontFamily: 'var(--font-mono)',
                            }}
                          >
                            <span style={{ color: 'var(--accent-cyan)' }}>{ev.file_path}</span>
                            <span style={{ color: 'var(--text-muted)' }}>
                              Lines {ev.start_line}–{ev.end_line}
                            </span>
                          </div>

                          <pre
                            style={{
                              padding: '0.85rem 1rem',
                              margin: 0,
                              fontFamily: 'var(--font-mono)',
                              fontSize: '0.8125rem',
                              color: 'var(--text-code)',
                              lineHeight: 1.5,
                              overflowX: 'auto',
                            }}
                          >
                            <code>{ev.code_snippet}</code>
                          </pre>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Mitigation Guidance */}
                {selectedFinding.mitigation_guidance && (
                  <div
                    style={{
                      padding: '1.1rem',
                      borderRadius: 'var(--radius-md)',
                      background: 'rgba(16, 185, 129, 0.08)',
                      border: '1px solid rgba(16, 185, 129, 0.25)',
                    }}
                  >
                    <span style={{ fontSize: '0.875rem', fontWeight: 700, color: 'var(--success-text)', display: 'block', marginBottom: '0.35rem' }}>
                      Recommended Mitigation
                    </span>
                    <p style={{ fontSize: '0.8125rem', color: 'var(--text-light)', lineHeight: 1.55 }}>
                      {selectedFinding.mitigation_guidance}
                    </p>
                  </div>
                )}
              </div>
            </div>
          ) : (
            <div className="glass-panel" style={{ display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <EmptyState
                icon={<ShieldAlert size={28} />}
                title="Select a finding to inspect"
                description="Click any finding from the list on the left to examine verified AST evidence and launch remediation."
              />
            </div>
          )}
        </div>
      </div>
    </AppShell>
  );
}
