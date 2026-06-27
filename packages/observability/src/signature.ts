/**
 * `verifyBatchSignature` — the load-bearing verifier for the ingestion endpoint. The signer
 * (`@aegiskit/core` `createHttpSink`) HMACs `timestamp + "." + rawBody`; this recomputes and
 * compares (constant-time, via `subtle.verify`) AND enforces a replay window on the timestamp.
 *
 * Verify the RAW request bytes — never a re-serialized object (key ordering/whitespace differ
 * and a "verify the parsed object" shortcut is forgeable). Edge-safe: Web Crypto + `atob` only.
 */

export interface VerifyOptions {
  /** Max age of the signed timestamp. Default 300_000 ms (5 min). */
  readonly replayWindowMs?: number;
  readonly now?: () => number;
}

function base64UrlToBytes(value: string): Uint8Array<ArrayBuffer> {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalized + '='.repeat((4 - (normalized.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

export async function verifyBatchSignature(
  secret: string,
  rawBody: string,
  timestamp: string,
  header: string,
  options: VerifyOptions = {},
): Promise<boolean> {
  try {
    const nowMs = (options.now ?? Date.now)();
    const replayWindowMs = options.replayWindowMs ?? 300_000;
    const ts = Number(timestamp);
    if (!Number.isFinite(ts) || Math.abs(nowMs - ts) > replayWindowMs) {
      return false; // stale or malformed timestamp → reject (replay defense)
    }
    const mac = header.startsWith('sha256=') ? header.slice('sha256='.length) : header;
    const key = await globalThis.crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify'],
    );
    return await globalThis.crypto.subtle.verify(
      'HMAC',
      key,
      base64UrlToBytes(mac),
      new TextEncoder().encode(`${timestamp}.${rawBody}`),
    );
  } catch {
    return false; // bad base64 / missing crypto / anything → fail-secure
  }
}
