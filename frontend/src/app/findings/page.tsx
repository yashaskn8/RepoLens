'use client';

import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { useRouter } from 'next/navigation';
import { AppShell } from '@/components/layout/AppShell';
import { Alert } from '@/components/ui/Alert';
import { Button } from '@/components/ui/Button';
import { EmptyState } from '@/components/ui/EmptyState';
import { SearchInput } from '@/components/ui/Input';
import { CardSkeleton } from '@/components/ui/Skeleton';
import { FindingCard } from '@/features/findings/FindingCard';
import { fetchScanFindings, listScans } from '@/lib/api';
import { Finding, Severity } from '@/types/domain';
import { RefreshCw, Scan as ScanIcon, ShieldCheck } from 'lucide-react';

const SEVERITIES: Array<'ALL' | Severity> = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

export default function FindingsPage() {
  const router = useRouter();
  const [findings, setFindings] = useState<Finding[]>([]);
  const [search, setSearch] = useState('');
  const [severity, setSeverity] = useState<'ALL' | Severity>('ALL');
  const [expandedFindingId, setExpandedFindingId] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadFindings = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const scans = await listScans(25);
      const results = await Promise.allSettled(scans.map((scan) => fetchScanFindings(scan.id)));
      const loaded = results.flatMap((result) => (result.status === 'fulfilled' ? result.value : []));
      const failedCount = results.filter((result) => result.status === 'rejected').length;
      setFindings(loaded);
      if (failedCount > 0) {
        setError(`${failedCount} scan result${failedCount === 1 ? '' : 's'} could not be loaded. The findings shown are incomplete.`);
      }
    } catch (caught: unknown) {
      setFindings([]);
      setError(caught instanceof Error ? caught.message : 'Failed to load findings');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadFindings();
  }, [loadFindings]);

  const filteredFindings = useMemo(() => {
    const query = search.trim().toLowerCase();
    return findings.filter((finding) => {
      const matchesSeverity = severity === 'ALL' || finding.severity === severity;
      const matchesSearch =
        !query ||
        finding.title.toLowerCase().includes(query) ||
        finding.description.toLowerCase().includes(query) ||
        finding.rule_id?.toLowerCase().includes(query) ||
        finding.category?.toLowerCase().includes(query) ||
        finding.evidences.some((evidence) => evidence.file_path.toLowerCase().includes(query));
      return matchesSeverity && Boolean(matchesSearch);
    });
  }, [findings, search, severity]);

  return (
    <AppShell breadcrumbs={[{ label: 'Findings Explorer' }]} title="Verified Security & Quality Findings">
      <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
        <div
          className="glass-panel"
          style={{ padding: '1rem 1.25rem', display: 'flex', gap: '0.75rem', flexWrap: 'wrap', alignItems: 'center' }}
        >
          <div style={{ flex: '1 1 18rem' }}>
            <SearchInput
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              onClear={() => setSearch('')}
              placeholder="Search title, rule, category, or source file..."
            />
          </div>
          <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: 'var(--text-secondary)', fontSize: '0.8125rem' }}>
            Severity
            <select
              value={severity}
              onChange={(event) => setSeverity(event.target.value as 'ALL' | Severity)}
              style={{ background: 'var(--surface-raised)', color: 'var(--text-primary)', border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-sm)', padding: '0.45rem 0.65rem' }}
            >
              {SEVERITIES.map((value) => <option key={value} value={value}>{value}</option>)}
            </select>
          </label>
          <Button
            variant="secondary"
            size="sm"
            leftIcon={<RefreshCw size={14} />}
            onClick={() => void loadFindings()}
            disabled={loading}
          >
            Refresh
          </Button>
        </div>

        {error && <Alert variant="warning" title="Findings data is incomplete">{error}</Alert>}

        {loading ? (
          <><CardSkeleton /><CardSkeleton /></>
        ) : findings.length === 0 ? (
          <EmptyState
            icon={<ScanIcon size={24} />}
            title="No verified findings yet"
            description="Run a repository scan. Only tenant-owned findings that pass RepoLens evidence verification are shown here."
            actionLabel="Start a repository scan"
            onAction={() => router.push('/scan')}
          />
        ) : filteredFindings.length === 0 ? (
          <EmptyState
            icon={<ShieldCheck size={24} />}
            title="No findings match these filters"
            description="Change the search text or severity filter to inspect the verified findings available for your scans."
          />
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.8125rem' }}>
              Showing {filteredFindings.length} of {findings.length} persisted, evidence-grounded finding{findings.length === 1 ? '' : 's'}.
            </p>
            {filteredFindings.map((finding) => (
              <FindingCard
                key={finding.id}
                finding={finding}
                isExpanded={expandedFindingId === finding.id}
                onToggleExpand={() => setExpandedFindingId(expandedFindingId === finding.id ? null : finding.id)}
              />
            ))}
          </div>
        )}
      </div>
    </AppShell>
  );
}
