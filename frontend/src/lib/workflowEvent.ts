import type { WorkflowEvent } from '@/types/domain';

/** Only strictly increasing database event IDs represent new progress.
 * Replayed terminal events and malformed payloads must never end a stream.
 */
export function isNewWorkflowEvent(
  candidate: unknown,
  previousId: number,
): candidate is WorkflowEvent {
  if (!candidate || typeof candidate !== 'object' || Array.isArray(candidate)) {
    return false;
  }
  const event = candidate as Record<string, unknown>;
  return (
    typeof event.id === 'number' &&
    Number.isSafeInteger(event.id) &&
    event.id > 0 &&
    event.id > previousId &&
    typeof event.event_type === 'string' &&
    event.event_type.length > 0
  );
}
