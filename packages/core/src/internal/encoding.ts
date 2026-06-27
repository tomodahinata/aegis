/**
 * Runtime-agnostic byte/base64url helpers. Uses only globals present on Node 24, the
 * edge runtime, and browsers (`btoa`, `globalThis.crypto`) — no `node:` imports — so
 * `@aegiskit/core` stays edge-safe.
 */

/** Encode bytes as URL-safe base64 (no padding). */
export function bytesToBase64Url(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/u, '');
}

/**
 * Cryptographically-strong random token, URL-safe base64. Throws if no CSPRNG is
 * available (fail-closed: callers must not fall back to a weak source for security tokens).
 */
export function randomBase64Url(byteLength: number): string {
  const bytes = new Uint8Array(byteLength);
  globalThis.crypto.getRandomValues(bytes);
  return bytesToBase64Url(bytes);
}

/** Constant-time string comparison; avoids leaking match position via timing. */
export function constantTimeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) {
    return false;
  }
  let mismatch = 0;
  for (let i = 0; i < a.length; i++) {
    mismatch |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return mismatch === 0;
}
