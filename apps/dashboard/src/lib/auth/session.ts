import { signCsrfToken, verifySignedCsrfToken } from '@aegiskit/core';

/** A signed admin session token, built on `@aegiskit/core`'s HMAC token primitives (no new crypto). */
export interface SessionPayload {
  readonly sub: 'admin';
  /** Issued-at (epoch seconds). */
  readonly iat: number;
  /** Expiry (epoch seconds). */
  readonly exp: number;
}

export type SessionResult =
  | { readonly ok: true; readonly payload: SessionPayload }
  | { readonly ok: false; readonly reason: 'malformed' | 'bad-signature' | 'expired' };

function toBase64Url(value: string): string {
  return btoa(value).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/u, '');
}

function fromBase64Url(value: string): string {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
  return atob(normalized + '='.repeat((4 - (normalized.length % 4)) % 4));
}

export async function signSessionToken(payload: SessionPayload, secret: string): Promise<string> {
  // The token body has no '.', so the single dot in `body.signature` is an unambiguous separator.
  return signCsrfToken(toBase64Url(JSON.stringify(payload)), secret);
}

export async function verifySessionToken(
  signed: string,
  secret: string,
  now: number = Date.now(),
): Promise<SessionResult> {
  if (!(await verifySignedCsrfToken(signed, secret))) {
    return { ok: false, reason: 'bad-signature' };
  }
  const separator = signed.lastIndexOf('.');
  let payload: SessionPayload;
  try {
    payload = JSON.parse(fromBase64Url(signed.slice(0, separator))) as SessionPayload;
  } catch {
    return { ok: false, reason: 'malformed' };
  }
  if (typeof payload.exp !== 'number' || payload.exp * 1000 < now) {
    return { ok: false, reason: 'expired' };
  }
  return { ok: true, payload };
}
