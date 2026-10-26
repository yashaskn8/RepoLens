'use client';

import { Suspense, useCallback, useEffect, useRef, useState } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';

import { AppShell } from '@/components/layout/AppShell';
import { Alert } from '@/components/ui/Alert';
import { Button } from '@/components/ui/Button';
import { EmptyState } from '@/components/ui/EmptyState';
import { CardSkeleton } from '@/components/ui/Skeleton';
import { RemediationLifecycle } from '@/features/remediation/RemediationLifecycle';
import { fetchFinding } from '@/lib/api';
import type { Finding } from '@/types/domain';

function RemediationWorkspaceContent() {
  const searchParams = useSearchParams();
  const router = useRouter();
  const findingId = searchParams.get('findingId');
  const [finding, setFinding] = useState<Finding | null>(null);
  const [loading, setLoading] = useState(Boolean(findingId));
  const [error, setError] = useState<string | null>(null);
  const [resolvedFindingId, setResolvedFindingId] = useState<string | null>(null);
  const requestVersion = useRef(0);

  const loadFinding = useCallback(async () => {
    const version = ++requestVersion.current;
    setFinding(null);
    setResolvedFindingId(null);
    setError(null);
    if (!findingId) {
      setLoading(false);
      return;
    }
    setLoading(true);
    try {
      const loaded = await fetchFinding(findingId);
      if (version === requestVersion.current) setFinding(loaded);
    } catch (caught: unknown) {
      if (version === requestVersion.current) {
        setError(caught instanceof Error ? caught.message : 'Failed to load finding');
      }
    } finally {
      if (version === requestVersion.current) {
        setResolvedFindingId(findingId);
        setLoading(false);
      }
    }
  }, [findingId]);

  useEffect(() => {
    void loadFinding();
    return () => {
      // Invalidate requests on route changes and unmount, including retries.
      requestVersion.current += 1;
    };
  }, [loadFinding]);

  // Do not show another finding's patch/approval controls before the effect runs.
  const currentFinding = finding?.id === findingId ? finding : null;

  if (!findingId) {
    return (
      <EmptyState
        title="Choose a verified finding"
        description="Open a confirmed finding from a scan before starting the guarded remediation workflow."
        actionLabel="Browse findings"
        onAction={() => router.push('/findings')}
      />
    );
  }

  if (loading || resolvedFindingId !== findingId) {
    return (
      <div style={{ display: 'grid', gap: '1rem' }}>
        <CardSkeleton />
        <CardSkeleton />
        <CardSkeleton />
      </div>
    );
  }

  if (error || !currentFinding) {
    return (
      <div style={{ display: 'grid', gap: '1rem' }}>
        <Alert variant="error">{error || 'The finding is unavailable.'}</Alert>
        <Button variant="secondary" onClick={() => void loadFinding()}>
          Retry
        </Button>
      </div>
    );
  }

  return <RemediationLifecycle key={findingId} finding={currentFinding} />;
}

export default function RemediationPage() {
  return (
    <AppShell
      breadcrumbs={[{ label: 'Remediation Workspace' }]}
      title="Human-authorized remediation"
    >
      <Suspense fallback={<CardSkeleton />}>
        <RemediationWorkspaceContent />
      </Suspense>
    </AppShell>
  );
}
