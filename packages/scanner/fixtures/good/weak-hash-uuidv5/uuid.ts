// SAFE: SHA-1 here builds an RFC-4122 v5 (deterministic) UUID — the spec mandates SHA-1, and the digest
// is a non-security identifier, not a signature/integrity/password hash. The analyzer must NOT flag this.
import { createHash } from 'node:crypto';

export function deterministicUuid(name: string): string {
  const bytes = createHash('sha1').update(name).digest().subarray(0, 16);
  const b = Buffer.from(bytes);
  b[6] = (b[6] & 0x0f) | 0x50; // version 5
  b[8] = (b[8] & 0x3f) | 0x80; // RFC-4122 variant
  const h = b.toString('hex');
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20, 32)}`;
}
