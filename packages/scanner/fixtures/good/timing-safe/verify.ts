import { timingSafeEqual } from 'node:crypto';

// SAFE: signatures are compared in constant time. The only ===/!== is a length guard on `.length`
// (not a secret), so the rule does not fire.
export function verifySignature(providedSignature: string, expectedSignature: string): boolean {
  const a = Buffer.from(providedSignature);
  const b = Buffer.from(expectedSignature);
  if (a.length !== b.length) {
    return false;
  }
  return timingSafeEqual(a, b);
}
