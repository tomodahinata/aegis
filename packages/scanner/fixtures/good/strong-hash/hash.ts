import { createHash } from 'node:crypto';

// SAFE: SHA-256 is appropriate for integrity/signatures; the rule only flags MD5/SHA-1.
export function fingerprint(payload: string): string {
  return createHash('sha256').update(payload).digest('hex');
}
