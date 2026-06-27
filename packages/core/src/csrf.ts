/**
 * CSRF defenses, as pure functions over header values (not framework Request objects, so
 * they're trivially testable).
 *
 *  - `verifyOrigin` — stateless same-origin check for custom Route Handlers, which (unlike
 *    Server Actions) have no built-in CSRF protection. Browsers always send `Origin` on
 *    cross-site mutating requests, so this catches form-based CSRF for free.
 *  - Double-submit token — for flows where `Origin` is unreliable/absent by design.
 *  - Signed token — stateless HMAC variant binding a token to a server secret.
 */

import { bytesToBase64Url, constantTimeEqual, randomBase64Url } from './internal/encoding';

export type SecFetchSite = 'same-origin' | 'same-site' | 'cross-site' | 'none';

export interface OriginCheckInput {
  /** The `Origin` request header, or `null`/`undefined` if absent. */
  readonly origin: string | null | undefined;
  /** The `Sec-Fetch-Site` request header, if present (fast-path). */
  readonly secFetchSite?: string | null | undefined;
  /** The request's own host (e.g. `app.example.com`). */
  readonly host: string;
}

export interface OriginCheckConfig {
  /** Hosts allowed as the request `Origin`. Defaults to `[input.host]` (strict same-origin). */
  readonly allowedHosts?: readonly string[];
  /** Allow requests with no `Origin` (e.g. trusted server-to-server). Default `false` (fail-closed). */
  readonly allowNullOrigin?: boolean;
}

export type OriginRejectionReason =
  | 'missing-origin'
  | 'bad-origin-url'
  | 'host-mismatch'
  | 'cross-site';

export type OriginVerdict =
  | { readonly ok: true }
  | { readonly ok: false; readonly reason: OriginRejectionReason };

const OK: OriginVerdict = { ok: true };

/** Fail-closed same-origin verifier. Prefers `Sec-Fetch-Site`, falls back to an `Origin` host check. */
export function verifyOrigin(
  input: OriginCheckInput,
  config: OriginCheckConfig = {},
): OriginVerdict {
  const allowedHosts = config.allowedHosts ?? [input.host];
  const allowNullOrigin = config.allowNullOrigin ?? false;

  // Fast path: the browser tells us the request's site relationship directly.
  if (input.secFetchSite === 'same-origin') {
    return OK;
  }
  if (input.secFetchSite === 'none') {
    // User-initiated (typed URL, bookmark) — not a cross-site attack vector.
    return OK;
  }
  if (input.secFetchSite === 'cross-site') {
    return { ok: false, reason: 'cross-site' };
  }
  // `same-site` or absent → fall through to the Origin host check.

  if (input.origin === null || input.origin === undefined || input.origin === '') {
    return allowNullOrigin ? OK : { ok: false, reason: 'missing-origin' };
  }

  let originHost: string;
  try {
    originHost = new URL(input.origin).host;
  } catch {
    return { ok: false, reason: 'bad-origin-url' };
  }

  return allowedHosts.includes(originHost) ? OK : { ok: false, reason: 'host-mismatch' };
}

// --- Double-submit cookie token -------------------------------------------------------

/** Generate a 256-bit CSRF token (URL-safe base64). */
export function generateCsrfToken(): string {
  return randomBase64Url(32);
}

/** Verify a double-submit token: cookie value and header/body value must be present and equal. */
export function verifyDoubleSubmitToken(
  cookieToken: string | null | undefined,
  requestToken: string | null | undefined,
): boolean {
  if (!cookieToken || !requestToken) {
    return false;
  }
  return constantTimeEqual(cookieToken, requestToken);
}

// --- Signed (stateless) token ---------------------------------------------------------

async function hmacSha256(secret: string, message: string): Promise<string> {
  const encoder = new TextEncoder();
  const key = await globalThis.crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const signature = await globalThis.crypto.subtle.sign('HMAC', key, encoder.encode(message));
  return bytesToBase64Url(new Uint8Array(signature));
}

/** Produce a `token.signature` value bound to `secret`. */
export async function signCsrfToken(token: string, secret: string): Promise<string> {
  const signature = await hmacSha256(secret, token);
  return `${token}.${signature}`;
}

/** Verify a `token.signature` value against `secret` (constant-time). */
export async function verifySignedCsrfToken(signed: string, secret: string): Promise<boolean> {
  const separator = signed.lastIndexOf('.');
  if (separator <= 0) {
    return false;
  }
  const token = signed.slice(0, separator);
  const signature = signed.slice(separator + 1);
  const expected = await hmacSha256(secret, token);
  return constantTimeEqual(signature, expected);
}
