/** Bounded scan pagination for the findings explorer.
 * The scans API is offset-paginated; never quietly discard older scans.
 */
export async function loadScanFindingsPage<TScan extends { id: string }, TFinding>(
  offset: number,
  pageSize: number,
  list: (limit: number, offset: number) => Promise<TScan[]>,
  loadFindings: (scanId: string) => Promise<TFinding[]>,
): Promise<{
  findings: TFinding[];
  scanCount: number;
  hasOlderScans: boolean;
  failedCount: number;
  failedScanIds: string[];
}> {
  if (!Number.isSafeInteger(offset) || offset < 0 || !Number.isSafeInteger(pageSize) || pageSize < 1 || pageSize > 100) {
    throw new Error('Invalid scan pagination request');
  }
  const scans = await list(pageSize, offset);
  if (!Array.isArray(scans) || scans.length > pageSize || scans.some((scan) => !scan || typeof scan.id !== 'string')) {
    throw new Error('Invalid scan pagination response');
  }
  const results = await Promise.allSettled(scans.map((scan) => loadFindings(scan.id)));
  const failedScanIds = scans.filter((_, index) => results[index].status === 'rejected').map((scan) => scan.id);
  return {
    findings: results.flatMap((result) => result.status === 'fulfilled' ? result.value : []),
    scanCount: scans.length,
    hasOlderScans: scans.length === pageSize,
    failedCount: failedScanIds.length,
    failedScanIds,
  };
}
