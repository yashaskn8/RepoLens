/** Check account and request generation before publishing asynchronous UI data. */
export function isCurrentAccountResponse(
  requestedAccount: string | null,
  activeAccount: string | null,
  requestedGeneration: number,
  activeGeneration: number,
): boolean {
  return Boolean(
    requestedAccount &&
    requestedAccount === activeAccount &&
    requestedGeneration === activeGeneration
  );
}
