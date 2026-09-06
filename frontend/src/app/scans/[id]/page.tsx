'use client';

import React, { useState, useEffect, use, useMemo } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { AppShell } from '@/components/layout/AppShell';
import { Card, StatCard } from '@/components/ui/Card';
import { Button } from '@/components/ui/Button';
import { Badge } from '@/components/ui/Badge';
import { Tabs } from '@/components/ui/Tabs';
import { SearchInput, Select } from '@/components/ui/Input';
import { Drawer } from '@/components/ui/Drawer';
import { Skeleton } from '@/components/ui/Skeleton';
import { EmptyState } from '@/components/ui/EmptyState';
import { ArchitectureGraph } from '@/components/visualization/ArchitectureGraph';
import { fetchScan, fetchScanFindings, fetchScanTelemetry } from '@/lib/api';
import { useWorkflowStream } from '@/lib/useWorkflowStream';
import { ScanReportAction } from '@/features/scan/ScanReportAction';
import { FindingCard } from '@/features/findings/FindingCard';
import { Finding, Scan, ScanTelemetry, Severity } from '@/types/domain';
import {
  Scan as ScanIcon,
  ShieldAlert,
  Layers,
  FileCode,
  Clock,
  Activity,
  ArrowRight,
  ExternalLink,
  GitBranch,
  Wrench,
  CheckCircle2,
  AlertTriangle,
  FileText,
  Search,
  Package,
  Cpu,
  ChevronDown,
} from 'lucide-react';

interface ScanDetailPageProps {
  params: Promise<{ id: string }>;
}

type JsonRecord = Record<string, unknown>;

function asRecord(value: unknown): JsonRecord {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? value as JsonRecord
    : {};
}

function asCount(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0
    ? value
    : null;
}

export default function ScanDetailPage({ params }: ScanDetailPageProps) {
  const resolvedParams = use(params);
  const scanId = resolvedParams.id;
  const router = useRouter();

  const [scan, setScan] = useState<Scan | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [telemetry, setTelemetry] = useState<ScanTelemetry | null>(null);
  const [activeTab, setActiveTab] = useState<string>('findings');
  const [expandedFindingId, setExpandedFindingId] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  // Filters for findings tab
  const [searchQuery, setSearchQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState('ALL');

  // Streaming events for workflow
  const { events } = useWorkflowStream(scanId, true);

  useEffect(() => {
    async function loadData() {
      try {
        const [scanRes, findingsRes, telemetryRes] = await Promise.allSettled([
          fetchScan(scanId),
          fetchScanFindings(scanId),
          fetchScanTelemetry(scanId),
        ]);

        if (scanRes.status === 'fulfilled') setScan(scanRes.value);
        if (findingsRes.status === 'fulfilled') setFindings(findingsRes.value || []);
        if (telemetryRes.status === 'fulfilled') setTelemetry(telemetryRes.value);
      } finally {
        setIsLoading(false);
      }
    }

    loadData();
  }, [scanId]);

  // Tab definitions conforming to task requirements
  const tabs = [
    { id: 'findings', label: 'Findings', count: findings.length, icon: <ShieldAlert size={15} /> },
    { id: 'relationships', label: 'Code Relationships', icon: <FileCode size={15} /> },
    { id: 'dependencies', label: 'Dependencies', icon: <Package size={15} /> },
    { id: 'raw_details', label: 'Raw Details', icon: <Activity size={15} /> },
  ];

  // Calculate severity breakdown
  const criticalCount = findings.filter((f) => f.severity === 'CRITICAL').length;
  const highCount = findings.filter((f) => f.severity === 'HIGH').length;
  const mediumCount = findings.filter((f) => f.severity === 'MEDIUM').length;
  const lowCount = findings.filter((f) => f.severity === 'LOW' || f.severity === 'INFO').length;

  // Filter findings
  const filteredFindings = useMemo(() => {
    return findings.filter((f) => {
      const matchesSearch =
        !searchQuery ||
        f.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
        f.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
        f.rule_id?.toLowerCase().includes(searchQuery.toLowerCase()) ||
        f.evidences.some((e) => e.file_path.toLowerCase().includes(searchQuery.toLowerCase()));

      const matchesSeverity = severityFilter === 'ALL' || f.severity === severityFilter;
      return matchesSearch && matchesSeverity;
    });
  }, [findings, searchQuery, severityFilter]);

  // Dependency findings (e.g. from OSV or package manifests)
  const dependencyFindings = useMemo(() => {
    return findings.filter((f) =>
      (f.category && ['dependency', 'osv', 'package', 'cve'].some((k) => f.category?.toLowerCase().includes(k))) ||
      (f.rule_id && f.rule_id.toLowerCase().includes('osv')) ||
      f.evidences.some((e) => ['package.json', 'requirements.txt', 'poetry.lock', 'go.mod', 'cargo.toml'].some((m) => e.file_path.toLowerCase().includes(m)))
    );
  }, [findings]);

  const metadata = asRecord(scan?.model_metadata);
  const indexCoverage = asRecord(metadata.index_coverage);
  const analysisScope = asRecord(metadata.analysis_scope);
  const graphCoverage = asRecord(metadata.graph_coverage);
  const analysisCoverage = asRecord(metadata.analysis_coverage);
  const scannerCoverage = Array.isArray(metadata.scanner_coverage)
    ? metadata.scanner_coverage.map(asRecord)
    : [];
  const indexedFiles = asCount(indexCoverage.indexed_files);
  const discoveredFiles = asCount(indexCoverage.discovered_files);
  const reasoningFiles = asCount(analysisScope.files_processed);
  const partialFiles = asCount(indexCoverage.partial_files);
  const excludedByReason = asRecord(indexCoverage.excluded_by_reason);
  const excludedFiles = Object.values(excludedByReason).reduce<number>(
    (total, value) => total + (asCount(value) ?? 0),
    0,
  );
  const graphNodes = asCount(graphCoverage.total_nodes);
  const graphEdges = asCount(graphCoverage.total_edges);
  const unavailableScanners = scannerCoverage.filter(
    (tool) => String(tool.status || '').toUpperCase() !== 'COMPLETED'
  );
  const analysisStatus = String(analysisCoverage.status || '').toUpperCase();
  const coverageLimited = Boolean(
    analysisStatus && analysisStatus !== 'COMPLETE'
    || indexCoverage.manifest_truncated === true
    || graphCoverage.complete === false
  );
  const dependencyScanner = scannerCoverage.find(
    (tool) => String(tool.tool || '').toLowerCase().includes('osv')
  );
  const dependencyCoverageComplete = String(dependencyScanner?.status || '').toUpperCase() === 'COMPLETED';
  const hasActiveFindingFilters = Boolean(searchQuery.trim() || severityFilter !== 'ALL');

  const repoName = scan
    ? scan.repository_url.replace('https://github.com/', '').replace(/\/$/, '')
    : `Scan ${scanId}`;

  return (
    <AppShell
      breadcrumbs={[
        { label: 'Scans', href: '/scan' },
        { label: repoName },
      ]}
      title="Scan Results"
    >
      <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
        {/* Workspace Top Action Bar */}
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
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '0.25rem' }}>
              <h1
                style={{
                  fontSize: '1.35rem',
                  fontWeight: 800,
                  fontFamily: 'var(--font-display)',
                  color: '#ffffff',
                }}
              >
                {repoName}
              </h1>
              {scan && (
                <Badge
                  variant={
                    scan.status === 'COMPLETED'
                      ? coverageLimited ? 'warning' : 'success'
                      : scan.status === 'FAILED'
                      ? 'error'
                      : 'cyan'
                  }
                  size="sm"
                >
                  {scan.status === 'COMPLETED'
                    ? coverageLimited ? 'Completed — scoped coverage' : 'Analysis Complete'
                    : scan.status}
                </Badge>
              )}
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
              <span>Branch: {scan?.resolved_branch_or_ref || scan?.branch || 'main'}</span>
              <span>•</span>
              <span style={{ fontFamily: 'var(--font-mono)' }}>Commit: {scan?.commit_hash?.slice(0, 8) || scan?.commit_sha?.slice(0, 8) || 'HEAD'}</span>
            </div>
          </div>

          <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}>
            {scan && <ScanReportAction scanId={scan.id} scanStatus={scan.status} />}
            <Button
              variant="secondary"
              size="sm"
              onClick={() => router.push(`/change-analysis?repo=${encodeURIComponent(scan?.repository_url || '')}`)}
              leftIcon={<GitBranch size={14} />}
            >
              Analyze Pull Request
            </Button>
            <Button
              variant="glow"
              size="sm"
              onClick={() => router.push(`/scan?repo=${encodeURIComponent(scan?.repository_url || '')}`)}
              leftIcon={<ScanIcon size={14} />}
            >
              Re-Scan
            </Button>
          </div>
        </div>

        {/* ========================================================================= */}
        {/* CLEAR SUMMARY CARD (MANDATORY TASK COMPONENT)                              */}
        {/* ========================================================================= */}
        <div
          className="glass-panel"
          style={{
            padding: '1.5rem',
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
            gap: '1.25rem',
            background: 'linear-gradient(135deg, rgba(99, 102, 241, 0.08) 0%, rgba(56, 189, 248, 0.04) 50%, rgba(8, 12, 28, 0.9) 100%)',
            border: '1px solid var(--border-glass-hover)',
          }}
        >
          {/* Card 1: Repository Name & Branch */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600, letterSpacing: '0.04em' }}>
              Repository
            </span>
            <span style={{ fontSize: '1.125rem', fontWeight: 700, color: '#ffffff' }}>
              {repoName}
            </span>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
              Branch: <code style={{ fontFamily: 'var(--font-mono)' }}>{scan?.branch || 'main'}</code>
            </span>
          </div>

          {/* Card 2: Files Analyzed */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600, letterSpacing: '0.04em' }}>
              Files Analyzed
            </span>
            <span style={{ fontSize: '1.125rem', fontWeight: 700, color: '#ffffff' }}>
              {indexedFiles !== null
                ? discoveredFiles !== null ? `${indexedFiles.toLocaleString()} of ${discoveredFiles.toLocaleString()}` : indexedFiles.toLocaleString()
                : 'Not reported'}
            </span>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
              {reasoningFiles !== null
                ? `${reasoningFiles.toLocaleString()} analyzable files inspected${partialFiles ? `; ${partialFiles.toLocaleString()} had bounded fact extraction` : ''}${excludedFiles ? `; ${excludedFiles.toLocaleString()} non-analyzable files inventoried` : ''}`
                : 'Passive source parsing; excluded scope is reported separately'}
            </span>
          </div>

          {/* Card 3: Relationships Discovered */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600, letterSpacing: '0.04em' }}>
              Relationships Discovered
            </span>
            <span style={{ fontSize: '1.125rem', fontWeight: 700, color: 'var(--accent-cyan)' }}>
              {graphNodes !== null && graphEdges !== null
                ? `${graphNodes.toLocaleString()} nodes · ${graphEdges.toLocaleString()} links`
                : 'Not reported'}
            </span>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
              {graphCoverage.complete === true ? 'Complete deterministic graph' : 'Partial deterministic graph; unknown links remain'}
            </span>
          </div>

          {/* Card 4: Findings by Severity */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.45rem' }}>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600, letterSpacing: '0.04em' }}>
              Findings by Severity
            </span>
            <div style={{ display: 'flex', gap: '0.4rem', flexWrap: 'wrap', alignItems: 'center' }}>
              <Badge variant="critical" size="sm">
                Critical: {criticalCount}
              </Badge>
              <Badge variant="high" size="sm">
                High: {highCount}
              </Badge>
              <Badge variant="medium" size="sm">
                Medium: {mediumCount}
              </Badge>
              <Badge variant="default" size="sm">
                Low: {lowCount}
              </Badge>
            </div>
          </div>
        </div>

        {/* Segmented Workspace Navigation Tabs */}
        <div style={{ borderBottom: '1px solid var(--border-subtle)', paddingBottom: '0.5rem' }}>
          <Tabs tabs={tabs} activeTab={activeTab} onChange={setActiveTab} />
        </div>

        {/* Tab 1: Findings (Primary View) */}
        {activeTab === 'findings' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
            {/* Filters Toolbar */}
            <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap', alignItems: 'center' }}>
              <div style={{ flex: '1 1 18rem' }}>
                <SearchInput
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  onClear={() => setSearchQuery('')}
                  placeholder="Filter by title, file, or rule..."
                />
              </div>

              <div style={{ width: '12rem' }}>
                <Select
                  value={severityFilter}
                  onChange={(e) => setSeverityFilter(e.target.value)}
                  options={[
                    { label: 'All Severities', value: 'ALL' },
                    { label: `Critical (${criticalCount})`, value: 'CRITICAL' },
                    { label: `High (${highCount})`, value: 'HIGH' },
                    { label: `Medium (${mediumCount})`, value: 'MEDIUM' },
                    { label: `Low (${lowCount})`, value: 'LOW' },
                  ]}
                />
              </div>
            </div>

            {/* Findings List in 4-Question Format */}
            {isLoading ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                <Skeleton height="8rem" />
                <Skeleton height="8rem" />
              </div>
            ) : filteredFindings.length === 0 ? (
              <EmptyState
                icon={coverageLimited
                  ? <AlertTriangle size={28} style={{ color: 'var(--warning-text)' }} />
                  : <CheckCircle2 size={28} style={{ color: 'var(--success-text)' }} />}
                title={hasActiveFindingFilters
                  ? 'No findings match these filters'
                  : coverageLimited ? 'No verified findings in available coverage' : 'No verified findings'}
                description={hasActiveFindingFilters
                  ? 'Clear the filters to review all confirmed findings from this scan.'
                  : coverageLimited
                    ? `This is not a clean bill of health. ${unavailableScanners.length} configured scanner${unavailableScanners.length === 1 ? ' was' : 's were'} unavailable or incomplete, and omitted scope remains unknown.`
                    : 'RepoLens completed the recorded analysis and did not confirm a finding. This does not prove that no defect exists.'}
                actionLabel={hasActiveFindingFilters ? 'Clear Filters' : undefined}
                onAction={hasActiveFindingFilters ? () => {
                    setSearchQuery('');
                    setSeverityFilter('ALL');
                  } : undefined}
              />
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                <div style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)' }}>
                  Showing {filteredFindings.length} of {findings.length} findings. Each finding explains what happened, why it matters, where it is, and what to do.
                </div>
                {filteredFindings.map((finding) => (
                  <FindingCard
                    key={finding.id}
                    finding={finding}
                    isExpanded={expandedFindingId === finding.id}
                    onToggleExpand={() =>
                      setExpandedFindingId(expandedFindingId === finding.id ? null : finding.id)
                    }
                  />
                ))}
              </div>
            )}
          </div>
        )}

        {/* Tab 2: Code Relationships (Architecture / Graph) */}
        {activeTab === 'relationships' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            <div style={{ padding: '0.75rem 1rem', background: 'rgba(99, 102, 241, 0.08)', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-subtle)', fontSize: '0.8125rem', color: 'var(--text-secondary)' }}>
              Interactive dependency and call graph constructed from deterministic Tree-sitter parsing.
            </div>
            <ArchitectureGraph />
          </div>
        )}

        {/* Tab 3: Dependencies */}
        {activeTab === 'dependencies' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
            <div
              className="glass-panel"
              style={{
                padding: '1.5rem',
                display: 'flex',
                flexDirection: 'column',
                gap: '1rem',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <Package size={18} style={{ color: 'var(--accent-cyan)' }} />
                <h3 style={{ fontSize: '1.0625rem', fontWeight: 700, fontFamily: 'var(--font-display)', color: '#ffffff' }}>
                  Dependency Vulnerability Status
                </h3>
              </div>

              {dependencyFindings.length === 0 ? (
                <EmptyState
                  icon={dependencyCoverageComplete
                    ? <CheckCircle2 size={24} style={{ color: 'var(--success-text)' }} />
                    : <AlertTriangle size={24} style={{ color: 'var(--warning-text)' }} />}
                  title={dependencyCoverageComplete ? 'No verified vulnerable dependencies' : 'Dependency scan unavailable'}
                  description={dependencyCoverageComplete
                    ? 'The configured dependency scanner completed and did not produce a confirmed dependency finding.'
                    : 'RepoLens could not complete its configured dependency-vulnerability scanner. Dependency risk remains unknown for this scan.'}
                />
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                  <span style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)' }}>
                    Found {dependencyFindings.length} package dependency vulnerabilities:
                  </span>
                  {dependencyFindings.map((finding) => (
                    <FindingCard
                      key={finding.id}
                      finding={finding}
                      isExpanded={expandedFindingId === finding.id}
                      onToggleExpand={() =>
                        setExpandedFindingId(expandedFindingId === finding.id ? null : finding.id)
                      }
                    />
                  ))}
                </div>
              )}
            </div>
          </div>
        )}

        {/* Tab 4: Raw Details (Collapsible & Organized) */}
        {activeTab === 'raw_details' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
            {/* Telemetry Metrics */}
            <Card style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <Activity size={18} style={{ color: 'var(--accent-primary)' }} />
                <h3 style={{ fontSize: '1rem', fontWeight: 700, fontFamily: 'var(--font-display)', color: '#ffffff' }}>
                  Pipeline Performance Telemetry
                </h3>
              </div>

              <div
                style={{
                  display: 'grid',
                  gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
                  gap: '1rem',
                }}
              >
                <div style={{ padding: '0.85rem', background: 'rgba(5, 8, 18, 0.7)', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-subtle)' }}>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Duration</div>
                  <div style={{ fontSize: '1.125rem', fontWeight: 700, color: '#ffffff', marginTop: '0.2rem' }}>
                    {telemetry?.total_duration_ms != null ? `${(telemetry.total_duration_ms / 1000).toFixed(2)}s` : 'Not reported'}
                  </div>
                </div>
                <div style={{ padding: '0.85rem', background: 'rgba(5, 8, 18, 0.7)', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-subtle)' }}>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Tools Completed</div>
                  <div style={{ fontSize: '1.125rem', fontWeight: 700, color: '#ffffff', marginTop: '0.2rem' }}>
                    {telemetry?.tools_completed ?? 0}
                  </div>
                </div>
                <div style={{ padding: '0.85rem', background: 'rgba(5, 8, 18, 0.7)', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-subtle)' }}>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Token Consumption</div>
                  <div style={{ fontSize: '1.125rem', fontWeight: 700, color: '#ffffff', marginTop: '0.2rem' }}>
                    {telemetry?.total_tokens || 0}
                  </div>
                </div>
                <div style={{ padding: '0.85rem', background: 'rgba(5, 8, 18, 0.7)', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-subtle)' }}>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Confirmed Invariants</div>
                  <div style={{ fontSize: '1.125rem', fontWeight: 700, color: 'var(--success-text)', marginTop: '0.2rem' }}>
                    {telemetry?.confirmed_findings ?? findings.length}
                  </div>
                </div>
              </div>
            </Card>

            {/* Workflow Log */}
            <Card style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <Clock size={18} style={{ color: 'var(--accent-cyan)' }} />
                <h3 style={{ fontSize: '1rem', fontWeight: 700, fontFamily: 'var(--font-display)', color: '#ffffff' }}>
                  Execution Step Timeline ({events.length} steps)
                </h3>
              </div>

              <div
                style={{
                  padding: '1rem',
                  background: '#030611',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: 'var(--radius-md)',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '0.4rem',
                  maxHeight: '18rem',
                  overflowY: 'auto',
                }}
              >
                {events.length === 0 ? (
                  <div style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>No logged events recorded.</div>
                ) : (
                  events.map((ev) => (
                    <div
                      key={ev.id}
                      style={{
                        display: 'flex',
                        alignItems: 'baseline',
                        gap: '0.65rem',
                        fontSize: '0.75rem',
                      }}
                    >
                      <span style={{ color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontSize: '0.7rem' }}>
                        {new Date(ev.created_at).toLocaleTimeString()}
                      </span>
                      <Badge variant="default" size="sm">
                        {ev.event_type}
                      </Badge>
                      <span style={{ color: 'var(--text-code)' }}>{ev.message}</span>
                    </div>
                  ))
                )}
              </div>
            </Card>
          </div>
        )}
      </div>
    </AppShell>
  );
}
