'use client';

import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useRouter } from 'next/navigation';
import { useAuth } from '@/context/AuthContext';
import { isCurrentAccountResponse } from '@/lib/accountRequest';
import { AppShell } from '@/components/layout/AppShell';
import { Alert } from '@/components/ui/Alert';
import { Button } from '@/components/ui/Button';
import { EmptyState } from '@/components/ui/EmptyState';
import { SearchInput } from '@/components/ui/Input';
import { CardSkeleton } from '@/components/ui/Skeleton';
import { FindingCard } from '@/features/findings/FindingCard';
import { fetchScanFindings, listScans } from '@/lib/api';
import { loadScanFindingsPage } from '@/lib/findingsPagination';
import { Finding, Severity } from '@/types/domain';
import { RefreshCw, Scan as ScanIcon, ShieldCheck } from 'lucide-react';

const SEVERITIES: Array<'ALL' | Severity> = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
const SCAN_PAGE_SIZE = 25;

export default function FindingsPage() {
  const router = useRouter();
  const { user, isLoading: authLoading } = useAuth();
  const accountId = user?.id ?? null;
  const requestGeneration = useRef(0);
  const [loadedForAccount, setLoadedForAccount] = useState<string | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [search, setSearch] = useState('');
  const [severity, setSeverity] = useState<'ALL' | Severity>('ALL');
  const [expandedFindingId, setExpandedFindingId] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const [loadedScanCount, setLoadedScanCount] = useState(0);
  const [hasOlderScans, setHasOlderScans] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const loadFindings = useCallback(async () => {
    const generation = ++requestGeneration.current;
    setLoading(true);
    setLoadingMore(false);
    setError(null);
    setLoadedForAccount(null);
    if (!accountId || authLoading) {
      setFindings([]);
      setLoadedScanCount(0);
      setHasOlderScans(false);
      setLoading(false);
      return;
    }
    try {
      const page = await loadScanFindingsPage(0, SCAN_PAGE_SIZE, listScans, fetchScanFindings);
      if (!isCurrentAccountResponse(accountId, user?.id ?? null, generation, requestGeneration.current)) return;
      setFindings(page.findings);
      setLoadedScanCount(page.scanCount);
      setHasOlderScans(page.hasOlderScans);
      setLoadedForAccount(accountId);
      if (page.failedCount > 0) {
        setError(`${page.failedCount} scan result${page.failedCount === 1 ? '' : 's'} could not be loaded. The findings shown are incomplete.`);
      }
    } catch (caught: unknown) {
      if (generation !== requestGeneration.current) return;
      setFindings([]);
      setLoadedScanCount(0);
      setHasOlderScans(false);
      setLoadedForAccount(accountId);
      setError(caught instanceof Error ? caught.message : 'Failed to load findings');
    } finally {
      if (generation === requestGeneration.current) setLoading(false);
    }
  }, [accountId, authLoading, user?.id]);

  useEffect(() => {
    // Account-scoped data cannot survive session restoration, logout, or a
    // switch to another tenant; invalidate every older in-flight response.
    requestGeneration.current += 1;
    setFindings([]);
    setLoadedForAccount(null);
    setLoadedScanCount(0);
    setHasOlderScans(false);
    setLoadingMore(false);
    setExpandedFindingId(null);
    setError(null);
    if (!authLoading && accountId) {
      void loadFindings();
    } else {
      setLoading(false);
    }
  }, [accountId, authLoading, loadFindings]);

  const loadOlderScans = useCallback(async () => {
    if (authLoading || !accountId || loadedForAccount !== accountId || loading || loadingMore || !hasOlderScans) return;
    const generation = requestGeneration.current;
    setLoadingMore(true);
    try {
      const page = await loadScanFindingsPage(
        loadedScanCount, SCAN_PAGE_SIZE, listScans, fetchScanFindings
      );
      if (!isCurrentAccountResponse(accountId, user?.id ?? null, generation, requestGeneration.current)) return;
      setFindings((current) => {
        const seen = new Set(current.map((finding) => finding.id));
        return [...current, ...page.findings.filter((finding) => !seen.has(finding.id))];
      });
      setLoadedScanCount((count) => count + page.scanCount);
      setHasOlderScans(page.hasOlderScans);
      if (page.failedCount > 0) {
        setError((previous) => [
          previous,
          `${page.failedCount} older scan result${page.failedCount === 1 ? '' : 's'} could not be loaded. Findings are incomplete.`,
        ].filter(Boolean).join(' '));
      }
    } catch (caught: unknown) {
      if (generation !== requestGeneration.current) return;
      setError((previous) => [
        previous,
        caught instanceof Error ? caught.message : 'Failed to load older scan findings',
      ].filter(Boolean).join(' '));
    } finally {
      if (generation === requestGeneration.current) setLoadingMore(false);
    }
  }, [accountId, user?.id, authLoading, loadedForAccount, hasOlderScans, loadedScanCount, loading, loadingMore]);

  const visibleFindings = loadedForAccount === accountId && accountId ? findings : [];
  const displayLoading = authLoading || (Boolean(accountId) && (loading || loadedForAccount !== accountId));

  const filteredFindings = useMemo(() => {
    const query = search.trim().toLowerCase();
    return visibleFindings.filter((finding) => {
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
  }, [visibleFindings, search, severity]);

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
            disabled={loading || loadingMore}
          >
            Refresh
          </Button>
        </div>

        {accountId && error && <Alert variant="warning" title="Findings data is incomplete">{error}</Alert>}

        {displayLoading ? (
          <><CardSkeleton /><CardSkeleton /></>
        ) : visibleFindings.length === 0 ? (
          <EmptyState
            icon={<ScanIcon size={24} />}
            title={!accountId ? 'Sign in to view findings' : hasOlderScans ? 'No verified findings in loaded scans' : 'No verified findings yet'}
            description={hasOlderScans
              ? 'Load older scans to look for verified findings, or start a new repository scan.'
              : 'Run a repository scan. Only tenant-owned findings that pass RepoLens evidence verification are shown here.'}
            actionLabel={accountId ? 'Start a repository scan' : 'Sign in'}
            onAction={() => accountId ? router.push('/scan') : window.dispatchEvent(new Event('repolens:open-auth'))}
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
              Showing {filteredFindings.length} of {visibleFindings.length} persisted, evidence-grounded finding{visibleFindings.length === 1 ? '' : 's'} across {loadedScanCount} loaded scan{loadedScanCount === 1 ? '' : 's'}.
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
        {!displayLoading && accountId && hasOlderScans && (
          <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center', flexWrap: 'wrap' }}>
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.8125rem' }}>
              Older scans have not been loaded yet; this is not a complete findings history.
            </p>
            <Button
              variant="secondary"
              size="sm"
              onClick={() => void loadOlderScans()}
              disabled={loadingMore}
            >
              {loadingMore ? 'Loading older scans...' : 'Load older scan findings'}
            </Button>
          </div>
        )}
      </div>
    </AppShell>
  );
}
