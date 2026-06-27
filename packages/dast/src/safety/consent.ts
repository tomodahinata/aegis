/**
 * The remote-target consent gate. Loopback needs nothing. Any other host requires TWO independent
 * signals — an explicit `--allow-remote` flag AND an ownership attestation whose origin exactly
 * matches the target — because a single flag is too easy to fat-finger into attacking a third party.
 * Fail-closed: missing either signal throws `ScopeError` before a single request is built.
 */

import { isLinkLocalOrMetadata, isLoopbackHost, type ScopePolicy } from './scope';

/** The operator's attestation that they own / are authorized to test `origin`. Logged into the report. */
export interface AuthorizationAck {
  /** Must string-match the resolved target origin, so an ack for one host can't authorize another. */
  readonly origin: string;
  /** Free-text the operator typed, e.g. "I own staging.acme.com". */
  readonly statement: string;
}

export interface RemoteConsent {
  /** `--allow-remote`. Necessary, not sufficient. */
  readonly allowRemote: boolean;
  /** The ownership acknowledgment. Origin must equal the target origin. */
  readonly ack?: AuthorizationAck;
}

/** Thrown when a target is out of scope — surfaced by the CLI as a usage error (exit 2). */
export class ScopeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ScopeError';
  }
}

/** Normalize a target URL to its origin, or throw `ScopeError` on a malformed/unsupported one. */
export function normalizeOrigin(rawUrl: string): { origin: string; host: string } {
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    throw new ScopeError(`invalid target URL: ${rawUrl}`);
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new ScopeError(`target must be http(s), got ${url.protocol}`);
  }
  return { origin: url.origin, host: url.hostname.toLowerCase() };
}

/**
 * Resolve the scope policy for a target origin. Fail-closed: returns a consented policy ONLY for a
 * loopback origin, or for a remote origin with both `allowRemote` and a matching `ack`. Otherwise throws.
 */
export function resolveScopePolicy(
  rawUrl: string,
  consent: RemoteConsent | undefined,
): ScopePolicy {
  const { origin, host } = normalizeOrigin(rawUrl);
  if (isLinkLocalOrMetadata(host)) {
    throw new ScopeError(`${host} is a link-local/metadata address and is never a valid target`);
  }
  if (isLoopbackHost(host)) {
    return { origin, originHost: host, remoteConsented: false, allowHosts: new Set([host]) };
  }
  if (consent?.allowRemote !== true || consent.ack === undefined) {
    throw new ScopeError(
      `refusing to probe non-loopback host "${host}". To probe a host you OWN, pass --allow-remote and --i-own "<attestation>".`,
    );
  }
  if (consent.ack.origin !== origin) {
    throw new ScopeError(
      `authorization is for "${consent.ack.origin}" but the target origin is "${origin}" — they must match.`,
    );
  }
  return { origin, originHost: host, remoteConsented: true, allowHosts: new Set([host]) };
}
