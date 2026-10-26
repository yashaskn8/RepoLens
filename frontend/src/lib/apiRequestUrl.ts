/** The API client must never forward browser cookies or CSRF headers to an
 * absolute URL supplied by another frontend component.
 */
export function buildApiRequestUrl(apiBase: string, input: string): string {
  if (
    typeof input !== 'string' ||
    !input.startsWith('/') ||
    input.startsWith('//') ||
    input.includes('\\') ||
    /[\u0000-\u001f\u007f]/.test(input)
  ) {
    throw new Error('Only application-relative API request paths are permitted.');
  }
  return `${apiBase}${input}`;
}
