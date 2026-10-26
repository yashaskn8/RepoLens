/** The change-analysis API accepts immutable commit IDs, not branch refs. */
export interface ExactChangeCommits {
  baseSha: string;
  headSha: string;
}

export function parseExactChangeCommits(base: string, head: string): ExactChangeCommits {
  const normalize = (value: string, label: string): string => {
    const sha = value.trim();
    if (!/^[0-9a-fA-F]{40}$/.test(sha)) {
      throw new Error(`${label} must be an exact 40-character hexadecimal commit SHA.`);
    }
    return sha.toLowerCase();
  };
  const baseSha = normalize(base, 'Base commit');
  const headSha = normalize(head, 'Head commit');
  if (baseSha === headSha) {
    throw new Error('Base and head commit SHAs must be different.');
  }
  return { baseSha, headSha };
}
