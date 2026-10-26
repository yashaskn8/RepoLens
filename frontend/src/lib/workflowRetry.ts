/** A bounded retry budget for reconnecting workflow event streams.
 * Opening an SSE socket is not proof that events can be received; only a
 * newer, validated event can reset consecutive failures.
 */
export class WorkflowRetryBudget {
  private consecutiveFailures = 0;

  constructor(private readonly maxFailures: number = 10) {
    if (!Number.isInteger(maxFailures) || maxFailures < 1) {
      throw new Error('The workflow retry limit must be a positive integer.');
    }
  }

  recordProgress(): void {
    this.consecutiveFailures = 0;
  }

  nextDelayMs(): number | null {
    if (this.consecutiveFailures >= this.maxFailures) return null;
    this.consecutiveFailures += 1;
    return Math.min(1000 * 2 ** this.consecutiveFailures, 10000);
  }
}
