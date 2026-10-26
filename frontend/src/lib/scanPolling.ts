/** Reject stale polling results after scan switches and terminal transitions. */
export function reconcilePolledScan<T extends { id: string; status: string }>(
  current: T | null,
  updated: T,
  expectedScanId: string,
): T | null {
  if (!current || current.id !== expectedScanId || updated.id !== expectedScanId) {
    return current;
  }
  if (current.status === 'COMPLETED' || current.status === 'FAILED') {
    return current;
  }
  return updated;
}
