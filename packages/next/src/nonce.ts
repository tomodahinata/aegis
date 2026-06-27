import type { Nonce } from '@aegiskit/core';
import { headers } from 'next/headers';
import { NONCE_HEADER } from './constants';

/**
 * Read the per-request CSP nonce inside a Server Component, e.g.
 * `<script nonce={await getNonce()} />`. Returns `undefined` if `secure()` is not installed.
 *
 * Note: reading the nonce opts a route into dynamic rendering (the nonce is per-request).
 * Use it only on routes that are already dynamic (e.g. the authenticated app segment); keep
 * static/marketing routes on a nonce-free hardened policy.
 */
export async function getNonce(): Promise<Nonce | undefined> {
  const headerStore = await headers();
  const value = headerStore.get(NONCE_HEADER);
  return value === null ? undefined : (value as Nonce);
}
