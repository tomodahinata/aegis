/**
 * Scope confinement — the single, pure, fail-closed authority answering "may I send to this URL?".
 * Every probe request and every captured redirect `Location` funnels through `checkScope`, so a buggy
 * probe cannot reach a host the run is not confined to. On any ambiguity it DENIES (fail secure).
 *
 * Two threats it defends against: (1) weaponization against a third party — non-loopback hosts need
 * explicit consent; (2) SSRF-into-the-scanner — a hostile app under test returning a redirect to cloud
 * metadata / a private host can never be followed (link-local + metadata IPs are denied unconditionally,
 * and off-origin hosts are denied).
 */

/** Hosts allowed without consent — loopback + the Next dev bind address. */
export const LOOPBACK_HOSTS: ReadonlySet<string> = new Set([
  'localhost',
  '127.0.0.1',
  '::1',
  '[::1]',
  '0.0.0.0',
]);

export type ScopeDenyReason =
  | 'malformed-url'
  | 'disallowed-scheme'
  | 'link-local-or-metadata'
  | 'non-loopback-without-consent'
  | 'off-origin';

export type ScopeDecision =
  | { readonly ok: true }
  | { readonly ok: false; readonly reason: ScopeDenyReason };

export interface ScopePolicy {
  /** Normalized target origin, e.g. `http://localhost:3000`. */
  readonly origin: string;
  /** Lower-cased host of the target origin. */
  readonly originHost: string;
  /** True only when a valid remote authorization unlocked non-loopback targets. */
  readonly remoteConsented: boolean;
  /** Hosts a request may reach — the target host (plus any explicitly consented extras). */
  readonly allowHosts: ReadonlySet<string>;
}

/** 127.0.0.0/8 + IPv6 loopback + the dev bind address — same machine, always allowed. */
export function isLoopbackHost(host: string): boolean {
  return LOOPBACK_HOSTS.has(host) || /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host);
}

/**
 * Link-local (169.254/16, incl. the 169.254.169.254 cloud-metadata IP) and IPv6 link-local/ULA, plus
 * the GCP metadata hostname. These have no legitimate use as an app target and are the canonical SSRF
 * pivot — denied unconditionally, even under consent.
 */
export function isLinkLocalOrMetadata(host: string): boolean {
  return (
    host === 'metadata.google.internal' ||
    /^169\.254\.\d{1,3}\.\d{1,3}$/.test(host) ||
    host.startsWith('[fe80') ||
    host.startsWith('[fc') ||
    host.startsWith('[fd')
  );
}

/** Decide whether `rawUrl` is in scope for `policy`. Total + fail-closed: any parse failure denies. */
export function checkScope(rawUrl: string, policy: ScopePolicy): ScopeDecision {
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    return { ok: false, reason: 'malformed-url' };
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    return { ok: false, reason: 'disallowed-scheme' };
  }
  const host = url.hostname.toLowerCase();
  if (isLinkLocalOrMetadata(host)) {
    return { ok: false, reason: 'link-local-or-metadata' };
  }
  if (!policy.remoteConsented && !isLoopbackHost(host)) {
    return { ok: false, reason: 'non-loopback-without-consent' };
  }
  if (host !== policy.originHost && !policy.allowHosts.has(host)) {
    return { ok: false, reason: 'off-origin' };
  }
  return { ok: true };
}
