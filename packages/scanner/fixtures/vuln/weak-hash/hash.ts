import { createHash } from 'node:crypto';

// VULN: MD5 is cryptographically broken — unsuitable for signing or integrity. (And a plain hash is
// the wrong primitive for passwords regardless; use a KDF.)
export function sign(payload: string): string {
  return createHash('md5').update(payload).digest('hex');
}
