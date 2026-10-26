import type { JobCollection, JobResource } from '@/types/domain';

/** Find the latest state of each persisted remediation stage, without guessing
 * a clean result when the latest job is failed, pending, or unavailable.
 */
export async function findLatestRemediationJobs(
  findingId: string,
  listPage: (cursor?: string) => Promise<JobCollection>,
  maxPages = 20,
): Promise<{ research: JobResource | null; plan: JobResource | null }> {
  let research: JobResource | null = null;
  let plan: JobResource | null = null;
  let cursor: string | undefined;
  const seenCursors = new Set<string>();
  for (let page = 0; page < maxPages; page += 1) {
    const response = await listPage(cursor);
    if (!response || !Array.isArray(response.items) || response.items.length > 100) {
      throw new Error('Invalid persisted remediation job history.');
    }
    for (const job of response.items) {
      if (!job || job.resource_type !== 'FINDING' || job.resource_id !== findingId) continue;
      if (job.work_kind === 'RESEARCH' && !research) research = job;
      if (job.work_kind === 'FIX_PLAN' && !plan) plan = job;
    }
    if (research && plan) return { research, plan };
    if (!response.next_cursor) return { research, plan };
    if (typeof response.next_cursor !== 'string' || seenCursors.has(response.next_cursor)) {
      throw new Error('Inconsistent persisted remediation job pagination.');
    }
    seenCursors.add(response.next_cursor);
    cursor = response.next_cursor;
  }
  throw new Error('Remediation job history exceeds the supported recovery limit.');
}
