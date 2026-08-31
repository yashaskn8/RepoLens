'use client';

import React, { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { AppShell } from '@/components/layout/AppShell';
import { Card } from '@/components/ui/Card';
import { Button } from '@/components/ui/Button';
import { Badge } from '@/components/ui/Badge';
import { SearchInput, Select } from '@/components/ui/Input';
import { Drawer } from '@/components/ui/Drawer';
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
  LayoutList,
  LayoutGrid,
} from 'lucide-react';

export default function FindingsPage() {
  const router = useRouter();
  const [findings, setFindings] = useState<Finding[]>([]);
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [verdictFilter, setVerdictFilter] = useState('ALL');
  const [viewMode, setViewMode] = useState<'compact' | 'detailed'>('detailed');
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [isDrawerOpen, setIsDrawerOpen] = useState(false);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    // Load findings from recent scans in localStorage or dummy baseline
    if (typeof window !== 'undefined') {
      const storedScans = localStorage.getItem('repolens_recent_scans');
      if (storedScans) {
        try {
          const scans = JSON.parse(storedScans);
          const allFindings: Finding[] = scans.flatMap((s: any) => s.findings || []);
          if (allFindings.length > 0) {
            setFindings(allFindings);
            setIsLoading(false);
            return;
          }
        } catch {
          // ignore
        }
      }

      // Default baseline demonstration findings if none in local storage yet
      const demoFindings: Finding[] = [
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
          verification_reason: 'AST call graph demonstrates unrestricted write to role field in user_service.py.',
          detector_id: 'ast-rule-auth-04',
          detector_kind: 'AST_SEMANTIC',
          mitigation_guidance: 'Enforce require_operator dependency gate before processing user role mutation.',
          evidences: [
            {
              id: 'ev-1',
              file_path: 'backend/src/services/user_service.py',
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
          verification_reason: 'Discrepancy detected between domain.ts:Scan.id and backend schema scan.py:ScanRead.id.',
          detector_id: 'cross-layer-contract-checker',
          detector_kind: 'CROSS_LAYER_GRAPH',
          mitigation_guidance: 'Normalize Scan identifier to UUID string in Pydantic schema and database model.',
          evidences: [
            {
              id: 'ev-2',
              file_path: 'frontend/src/types/domain.ts',
              start_line: 59,
              end_line: 65,
              code_snippet: 'export interface Scan {\n  id: string;\n  repository_url: string;\n}',
            },
          ],
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString(),
        },
        {
          id: 'find-ast-103',
          scan_id: 'scan-demo-01',
          title: 'Missing CSRF Token on State-Modifying Fetch Call',
          description: 'POST mutation executed without attaching X-CSRF-Token header or cookie credential.',
          severity: 'MEDIUM',
          status: 'OPEN',
          rule_id: 'sec.csrf.missing-header',
          category: 'CSRF Protection',
          verification_verdict: 'CONFIRMED',
          verification_reason: 'AST trace indicates direct fetch() call bypassing centralized apiFetch() client.',
          detector_id: 'ast-fetch-trace',
          detector_kind: 'AST_SEMANTIC',
          mitigation_guidance: 'Replace raw fetch call with centralized apiFetch wrapper.',
          evidences: [
            {
              id: 'ev-3',
              file_path: 'frontend/src/features/scan/RepositoryScanForm.tsx',
              start_line: 45,
              end_line: 52,
              code_snippet: 'fetch("/api/v1/scans", { method: "POST", body: JSON.stringify(data) })',
            },
          ],
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString(),
        },
      ];

      setFindings(demoFindings);
      setIsLoading(false);
    }
  }, []);

  const filteredFindings = findings.filter((f) => {
    const matchesSearch =
      f.title.toLowerCase().includes(search.toLowerCase()) ||
      f.description.toLowerCase().includes(search.toLowerCase()) ||
      f.rule_id?.toLowerCase().includes(search.toLowerCase()) ||
      f.evidences.some((e) => e.file_path.toLowerCase().includes(search.toLowerCase()));

    const matchesSeverity = severityFilter === 'ALL' || f.severity === severityFilter;
    const matchesVerdict = verdictFilter === 'ALL' || f.verification_verdict === verdictFilter;

    return matchesSearch && matchesSeverity && matchesVerdict;
  });

  return (
    <AppShell breadcrumbs={[{ label: 'Findings Explorer' }]} title="Findings Explorer">
      <div style={{ display: 'flex', flexDirection: 'column', gap: '1.75rem' }}>
        {/* Top Header */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
          <div>
            <h1
              style={{
                fontSize: '1.75rem',
                fontWeight: 800,
                fontFamily: 'var(--font-display)',
                color: '#ffffff',
                marginBottom: '0.4rem',
              }}
            >
              Verified Findings Explorer
            </h1>
            <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)' }}>
              Deterministic AST & cross-layer verified issues. Strict line citations and human-authorized remediation.
            </p>
          </div>

          <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
            <Button
              variant={viewMode === 'detailed' ? 'secondary' : 'ghost'}
              size="sm"
              onClick={() => setViewMode('detailed')}
              leftIcon={<LayoutList size={14} />}
            >
              Detailed
            </Button>
            <Button
              variant={viewMode === 'compact' ? 'secondary' : 'ghost'}
              size="sm"
              onClick={() => setViewMode('compact')}
              leftIcon={<LayoutGrid size={14} />}
            >
              Compact
            </Button>
          </div>
        </div>

        {/* Filters Toolbar */}
        <Card style={{ padding: '1.25rem', display: 'flex', gap: '1rem', flexWrap: 'wrap', alignItems: 'center' }}>
          <div style={{ flex: '1 1 20rem' }}>
            <SearchInput
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              onClear={() => setSearch('')}
              placeholder="Search by title, rule ID, file path..."
            />
          </div>

          <div style={{ width: '12rem' }}>
            <Select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              options={[
                { label: 'All Severities', value: 'ALL' },
                { label: 'Critical Only', value: 'CRITICAL' },
                { label: 'High Only', value: 'HIGH' },
                { label: 'Medium Only', value: 'MEDIUM' },
                { label: 'Low Only', value: 'LOW' },
              ]}
            />
          </div>

          <div style={{ width: '12rem' }}>
            <Select
              value={verdictFilter}
              onChange={(e) => setVerdictFilter(e.target.value)}
              options={[
                { label: 'All Verdicts', value: 'ALL' },
                { label: 'Confirmed Only', value: 'CONFIRMED' },
                { label: 'Possible Only', value: 'POSSIBLE' },
                { label: 'Rejected Only', value: 'REJECTED' },
              ]}
            />
          </div>
        </Card>

        {/* Findings List */}
        {filteredFindings.length === 0 ? (
          <EmptyState
            icon={<CheckCircle2 size={32} style={{ color: 'var(--success-text)' }} />}
            title="No findings matching current filters"
            description="Adjust your search query or severity filters to inspect other records."
            actionLabel="Reset Filters"
            onAction={() => {
              setSearch('');
              setSeverityFilter('ALL');
              setVerdictFilter('ALL');
            }}
          />
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
            {filteredFindings.map((finding) => (
              <div
                key={finding.id}
                onClick={() => {
                  setSelectedFinding(finding);
                  setIsDrawerOpen(true);
                }}
                style={{
                  padding: viewMode === 'compact' ? '0.85rem 1.25rem' : '1.25rem 1.5rem',
                  borderRadius: 'var(--radius-lg)',
                  backgroundColor: 'rgba(9, 13, 26, 0.78)',
                  border: '1px solid var(--border-glass)',
                  cursor: 'pointer',
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  gap: '1rem',
                  transition: 'all var(--transition-fast)',
                }}
                className="glass-panel-interactive"
              >
                <div style={{ flex: 1 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', marginBottom: '0.3rem', flexWrap: 'wrap' }}>
                    <Badge
                      variant={
                        finding.severity === 'CRITICAL'
                          ? 'critical'
                          : finding.severity === 'HIGH'
                          ? 'high'
                          : finding.severity === 'MEDIUM'
                          ? 'medium'
                          : 'low'
                      }
                      size="sm"
                    >
                      {finding.severity}
                    </Badge>
                    <h3 style={{ fontSize: '0.9375rem', fontWeight: 600, color: '#ffffff' }}>
                      {finding.title}
                    </h3>
                    {finding.rule_id && (
                      <span style={{ fontSize: '0.75rem', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
                        ({finding.rule_id})
                      </span>
                    )}
                    {finding.verification_verdict && (
                      <Badge variant="cyan" size="sm">
                        {finding.verification_verdict}
                      </Badge>
                    )}
                  </div>

                  {viewMode === 'detailed' && (
                    <p style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', marginBottom: '0.5rem', lineHeight: 1.5 }}>
                      {finding.description}
                    </p>
                  )}

                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', flexWrap: 'wrap' }}>
                    {finding.evidences.map((ev, idx) => (
                      <span
                        key={idx}
                        style={{
                          fontSize: '0.75rem',
                          fontFamily: 'var(--font-mono)',
                          color: 'var(--text-muted)',
                          display: 'flex',
                          alignItems: 'center',
                          gap: '0.3rem',
                        }}
                      >
                        <FileCode size={13} />
                        {ev.file_path}
                        {ev.start_line && `:${ev.start_line}`}
                      </span>
                    ))}
                  </div>
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                  <Button
                    variant="secondary"
                    size="sm"
                    onClick={(e) => {
                      e.stopPropagation();
                      router.push(`/remediation?findingId=${finding.id}`);
                    }}
                    leftIcon={<Wrench size={13} />}
                  >
                    Remediate
                  </Button>
                  <ChevronRight size={16} style={{ color: 'var(--text-muted)' }} />
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Finding Detail Inspection Drawer */}
      <Drawer
        isOpen={isDrawerOpen}
        onClose={() => setIsDrawerOpen(false)}
        title={selectedFinding?.title || 'Finding Detail'}
        subtitle={
          selectedFinding && (
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginTop: '0.2rem' }}>
              <Badge
                variant={
                  selectedFinding.severity === 'CRITICAL'
                    ? 'critical'
                    : selectedFinding.severity === 'HIGH'
                    ? 'high'
                    : selectedFinding.severity === 'MEDIUM'
                    ? 'medium'
                    : 'low'
                }
                size="sm"
              >
                {selectedFinding.severity}
              </Badge>
              <span style={{ fontSize: '0.75rem', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
                {selectedFinding.rule_id}
              </span>
            </div>
          )
        }
        footer={
          selectedFinding && (
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.75rem' }}>
              <Button variant="secondary" size="md" onClick={() => setIsDrawerOpen(false)}>
                Close
              </Button>
              <Button
                variant="glow"
                size="md"
                onClick={() => {
                  setIsDrawerOpen(false);
                  router.push(`/remediation?findingId=${selectedFinding.id}`);
                }}
                leftIcon={<Wrench size={15} />}
              >
                Start Remediation
              </Button>
            </div>
          )
        }
      >
        {selectedFinding && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
            <div>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.04em', marginBottom: '0.35rem' }}>
                Description
              </div>
              <p style={{ fontSize: '0.875rem', color: 'var(--text-light)', lineHeight: 1.6 }}>
                {selectedFinding.description}
              </p>
            </div>

            {selectedFinding.verification_reason && (
              <div>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.04em', marginBottom: '0.35rem' }}>
                  Verification Evidence Verdict
                </div>
                <div
                  style={{
                    padding: '0.75rem 1rem',
                    background: 'rgba(56, 189, 248, 0.08)',
                    border: '1px solid rgba(56, 189, 248, 0.25)',
                    borderRadius: 'var(--radius-md)',
                    fontSize: '0.8125rem',
                    color: '#7dd3fc',
                    lineHeight: 1.5,
                  }}
                >
                  {selectedFinding.verification_reason}
                </div>
              </div>
            )}

            {selectedFinding.mitigation_guidance && (
              <div>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.04em', marginBottom: '0.35rem' }}>
                  Mitigation Guidance
                </div>
                <p style={{ fontSize: '0.875rem', color: 'var(--text-light)', lineHeight: 1.6 }}>
                  {selectedFinding.mitigation_guidance}
                </p>
              </div>
            )}

            <div>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.04em', marginBottom: '0.35rem' }}>
                AST Evidence Code Snippet
              </div>
              {selectedFinding.evidences.map((ev, idx) => (
                <div
                  key={idx}
                  style={{
                    padding: '0.85rem',
                    background: 'var(--bg-code)',
                    border: '1px solid var(--border-subtle)',
                    borderRadius: 'var(--radius-md)',
                    marginBottom: '0.5rem',
                  }}
                >
                  <div style={{ fontSize: '0.75rem', fontFamily: 'var(--font-mono)', color: 'var(--accent-cyan)', marginBottom: '0.35rem' }}>
                    {ev.file_path} {ev.start_line ? `:${ev.start_line}` : ''}
                  </div>
                  {ev.code_snippet && (
                    <pre style={{ fontSize: '0.75rem', fontFamily: 'var(--font-mono)', color: 'var(--text-code)', overflowX: 'auto' }}>
                      <code>{ev.code_snippet}</code>
                    </pre>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}
      </Drawer>
    </AppShell>
  );
}
