'use client';

import { Suspense, useCallback, useEffect, useState } from 'react';
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

  const loadFinding = useCallback(async () => {
    if (!findingId) return;
    setLoading(true);
    setError(null);
    try {
      setFinding(await fetchFinding(findingId));
    } catch (caught: unknown) {
      setFinding(null);
      setError(caught instanceof Error ? caught.message : 'Failed to load finding');
    } finally {
      setLoading(false);
    }
  }, [findingId]);

  useEffect(() => {
    void loadFinding();
  }, [loadFinding]);

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

  if (loading) {
    return (
      <div style={{ display: 'grid', gap: '1rem' }}>
        <CardSkeleton />
        <CardSkeleton />
        <CardSkeleton />
      </div>
    );
  }

  if (error || !finding) {
    return (
      <div style={{ display: 'grid', gap: '1rem' }}>
        <Alert variant="error">{error || 'The finding is unavailable.'}</Alert>
        <Button variant="secondary" onClick={() => void loadFinding()}>
          Retry
        </Button>
      </div>
    );
  }

  return <RemediationLifecycle finding={finding} />;
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
