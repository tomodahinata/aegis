/**
 * `secure()` — a composable middleware/proxy factory for Next.js (App Router). Place the
 * returned function in `middleware.ts` OR `proxy.ts`; the signature is identical.
 *
 * It is the SINGLE place a CSP header is produced: it mints one nonce per request, exposes it
 * to Server Components via a request header, and stamps the CSP + security headers on every
 * outgoing response. Do NOT also emit a CSP from `next.config` — that split (a static policy
 * shadowing a per-request nonce) is exactly the bug this design eliminates.
 */

import {
  buildCspHeader,
  buildSecurityHeaders,
  type CspMode,
  type CspPolicyConfig,
  createNoopSink,
  generateNonce,
  HARDENED_HEADERS,
  hardenedCspPolicy,
  type Nonce,
  type OriginCheckConfig,
  RATE_LIMIT_PRESETS,
  type RateLimiter,
  type RateLimitRule,
  type SecurityHeadersConfig,
  type SecuritySink,
  safeEmit,
  verifyOrigin,
} from '@aegiskit/core';
import type { NextRequest } from 'next/server';
import { NextResponse } from 'next/server';
import { NONCE_HEADER } from './constants';
import { clientIp, isMutating } from './internal/request';

export interface SecureRateLimitConfig {
  readonly limiter: RateLimiter;
  /** Rule to apply. Default `RATE_LIMIT_PRESETS.ip`. */
  readonly rule?: RateLimitRule;
  /** Derive the limit key from the request. Default: client IP. */
  readonly keyFromRequest?: (req: NextRequest) => string;
  /** Limit only requests matching this predicate. Default: all requests. */
  readonly match?: (req: NextRequest) => boolean;
  /** Label used in emitted `rate_limit_block` events. */
  readonly name?: string;
}

export interface SecureChainContext {
  readonly nonce: Nonce;
  /** Request headers (already carrying the nonce) to pass to `NextResponse.next({ request })`. */
  readonly requestHeaders: Headers;
}

export interface SecureConfig {
  /** CSP policy, or `false` to disable CSP. Default: `hardenedCspPolicy()`. */
  readonly csp?: CspPolicyConfig | false;
  /**
   * Path the browser POSTs CSP violations to (e.g. `/api/aegis/csp-report`). When set AND `csp`
   * is left as the default, `secure()` points `report-uri`/`report-to` here automatically (pair
   * it with `createCspReportHandler`). Ignored if you pass an explicit `csp` — then you own the
   * report wiring.
   */
  readonly cspReportEndpoint?: string;
  /**
   * CSP mode. Default: `'report-only'` (fail-safe). To drive this from an environment variable,
   * pass a value resolved from your OWN typed env boundary (`defineServerEnv` / `@aegiskit/core`'s
   * `defineEnv`) — e.g. `cspMode: resolveCspMode(env.NEXT_PUBLIC_CSP_MODE)`. Aegis does not read
   * `process.env` here, per its own "never read process.env outside the typed env boundary" rule.
   */
  readonly cspMode?: CspMode;
  /** Security headers. Default: `HARDENED_HEADERS`. */
  readonly headers?: SecurityHeadersConfig;
  readonly rateLimit?: SecureRateLimitConfig;
  /** Origin check for mutating requests, or `false` to disable. Default: enabled, strict same-origin. */
  readonly origin?: OriginCheckConfig | false;
  readonly sink?: SecuritySink;
  /**
   * The host app's own middleware (session refresh, i18n). Receives the nonce + request headers
   * and returns the response to decorate. When omitted, a `NextResponse.next()` carrying the
   * nonce is used.
   */
  readonly chain?: (
    req: NextRequest,
    ctx: SecureChainContext,
  ) => NextResponse | Promise<NextResponse>;
}

export type AegisMiddleware = (req: NextRequest) => Promise<NextResponse>;

export function secure(config: SecureConfig = {}): AegisMiddleware {
  const sink = config.sink ?? createNoopSink();
  const securityHeaders = buildSecurityHeaders(config.headers ?? HARDENED_HEADERS);
  const cspPolicy: CspPolicyConfig | false =
    config.csp ??
    hardenedCspPolicy(
      config.cspReportEndpoint !== undefined
        ? { reportTo: 'aegis', reportEndpoint: config.cspReportEndpoint }
        : {},
    );
  const cspMode: CspMode = config.cspMode ?? 'report-only';

  function finalize(response: NextResponse, nonce: Nonce): NextResponse {
    for (const [name, value] of securityHeaders) {
      response.headers.set(name, value);
    }
    if (cspPolicy !== false) {
      const built = buildCspHeader(cspPolicy, nonce, cspMode);
      if (built) {
        response.headers.set(built.name, built.value);
        if (built.reportingEndpoints) {
          response.headers.set('Reporting-Endpoints', built.reportingEndpoints);
        }
      }
    }
    response.headers.set(NONCE_HEADER, nonce);
    return response;
  }

  return async function aegisMiddleware(req: NextRequest): Promise<NextResponse> {
    const nonce = generateNonce();
    const at = Date.now();
    const path = req.nextUrl.pathname;

    // 1. Origin check for mutating requests — the cheapest rejection, done first.
    if (config.origin !== false && isMutating(req.method)) {
      const origin = req.headers.get('origin');
      const verdict = verifyOrigin(
        { origin, secFetchSite: req.headers.get('sec-fetch-site'), host: req.nextUrl.host },
        config.origin ?? {},
      );
      if (!verdict.ok) {
        safeEmit(sink, {
          type: 'origin_block',
          at,
          ip: clientIp(req),
          path,
          method: req.method,
          origin,
          reason: verdict.reason,
        });
        return finalize(new NextResponse('Forbidden', { status: 403 }), nonce);
      }
    }

    // 2. Rate limit.
    const rl = config.rateLimit;
    if (rl && (rl.match?.(req) ?? true)) {
      const key = rl.keyFromRequest?.(req) ?? clientIp(req);
      const rule: RateLimitRule = rl.rule ?? RATE_LIMIT_PRESETS.ip;
      const result = await rl.limiter.limit(key, rule);
      if (!result.success) {
        safeEmit(sink, {
          type: 'rate_limit_block',
          at,
          ip: clientIp(req),
          path,
          method: req.method,
          key,
          rule: rl.name ?? rule.prefix ?? 'ip',
          limit: result.limit,
        });
        const blocked = new NextResponse('Too Many Requests', { status: 429 });
        blocked.headers.set('Retry-After', String(result.retryAfter));
        blocked.headers.set('X-RateLimit-Limit', String(result.limit));
        blocked.headers.set('X-RateLimit-Remaining', String(result.remaining));
        blocked.headers.set('X-RateLimit-Reset', String(result.reset));
        return finalize(blocked, nonce);
      }
    }

    // 3. Expose the nonce to Server Components and build the downstream response.
    const requestHeaders = new Headers(req.headers);
    requestHeaders.set(NONCE_HEADER, nonce);
    const response = config.chain
      ? await config.chain(req, { nonce, requestHeaders })
      : NextResponse.next({ request: { headers: requestHeaders } });

    return finalize(response, nonce);
  };
}
