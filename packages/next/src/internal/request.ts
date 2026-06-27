import type { NextRequest } from 'next/server';

/** Methods that mutate state and therefore warrant origin/CSRF checks. */
export const MUTATING_METHODS: ReadonlySet<string> = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

export function isMutating(method: string): boolean {
  return MUTATING_METHODS.has(method.toUpperCase());
}

/**
 * Best-effort client IP from standard proxy headers; `'unknown'` when unavailable.
 *
 * SECURITY — READ BEFORE USING THIS AS A RATE-LIMIT KEY:
 * `X-Forwarded-For` is a CLIENT-CONTROLLED header. Every value an untrusted client sends is
 * appended to the LEFT of the chain; only entries your trusted proxy appended (on the RIGHT)
 * are non-spoofable. We therefore select from the RIGHT: with `trustedProxyHops = n` we return
 * `parts[parts.length - n]` — the address your n-th-from-the-edge trusted proxy observed and
 * recorded. The default `n = 1` matches the typical single-proxy SaaS deployment (one CDN /
 * load balancer in front of the app).
 *
 * This value is ONLY trustworthy when a trusted proxy actually sets or rewrites
 * `X-Forwarded-For`, AND `trustedProxyHops` matches the number of trusted proxies in front of
 * this app. If those assumptions do not hold, header-derived IPs are spoofable: an attacker can
 * rotate the header to mint unlimited rate-limit keys and bypass per-IP throttling. With NO
 * trusted proxy, DO NOT rely on IP rate limiting — supply a custom key instead
 * (`keyFromRequest` / `rateLimit.key`).
 *
 * @param opts.trustedProxyHops Number of trusted proxies in front of the app (default `1`).
 *   Clamped to the chain length: if it exceeds the number of entries, the leftmost entry is
 *   used as a best-effort fallback.
 */
export function clientIp(req: NextRequest, opts?: { trustedProxyHops?: number }): string {
  const forwarded = req.headers.get('x-forwarded-for');
  if (forwarded) {
    const parts = forwarded
      .split(',')
      .map((p) => p.trim())
      .filter((p) => p.length > 0);
    if (parts.length > 0) {
      const hops = opts?.trustedProxyHops ?? 1;
      // Count from the right; the rightmost entry was appended by our trusted proxy and cannot
      // be client-spoofed. Clamp to the chain length (best-effort) so n >= length → leftmost.
      const index = hops >= parts.length ? 0 : parts.length - hops;
      const selected = parts[index];
      if (selected) {
        return selected;
      }
    }
  }
  return req.headers.get('x-real-ip') ?? 'unknown';
}
