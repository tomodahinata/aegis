/**
 * `secureRoute()` — a typed wrapper for App Router Route Handlers (which, unlike Server
 * Actions, have NO built-in CSRF protection). It enforces, in fail-secure order:
 *   method → origin (for mutating requests) → rate limit → Zod validation
 * then calls the handler with fully-inferred `body`/`query`/`params`. Failures return a
 * structured JSON error and emit the matching security event.
 */

import {
  createNoopSink,
  type OriginCheckConfig,
  type RateLimiter,
  type RateLimitRule,
  type SecuritySink,
  safeEmit,
  verifyOrigin,
} from '@aegiskit/core';
import type { NextRequest } from 'next/server';
import { NextResponse } from 'next/server';
import type { z } from 'zod';
import { clientIp, isMutating } from './internal/request';

export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE' | 'OPTIONS' | 'HEAD';

export interface RouteRateLimitConfig {
  readonly limiter: RateLimiter;
  readonly rule: RateLimitRule;
  /** Derive the limit key from the request. Default: client IP. */
  readonly key?: (req: NextRequest) => string;
}

export interface RouteSchemas<B extends z.ZodType, Q extends z.ZodType, P extends z.ZodType> {
  readonly body?: B;
  readonly query?: Q;
  readonly params?: P;
  /** Allowed method(s). A mismatch returns 405. */
  readonly method?: HttpMethod | readonly HttpMethod[];
  readonly rateLimit?: RouteRateLimitConfig;
  /** Origin check for mutating methods, or `false` to disable. Default: enabled. */
  readonly origin?: OriginCheckConfig | false;
  readonly sink?: SecuritySink;
}

export interface RouteContext {
  readonly params?: Promise<Record<string, string | string[]>>;
}

type InferOr<T extends z.ZodType, Fallback> = [T] extends [z.ZodNever] ? Fallback : z.infer<T>;

export interface ValidatedInput<B extends z.ZodType, Q extends z.ZodType, P extends z.ZodType> {
  readonly req: NextRequest;
  readonly body: InferOr<B, undefined>;
  readonly query: InferOr<Q, undefined>;
  readonly params: InferOr<P, undefined>;
}

function errorResponse(
  status: number,
  error: Record<string, unknown>,
  headers?: Record<string, string>,
): NextResponse {
  return NextResponse.json({ error }, { status, ...(headers ? { headers } : {}) });
}

async function readJsonBody(req: NextRequest): Promise<unknown> {
  try {
    return await req.json();
  } catch {
    return undefined;
  }
}

function validationError(
  error: z.ZodError,
  sink: SecuritySink,
  at: number,
  path: string,
  method: string,
): NextResponse {
  const issues = error.issues.map((issue) => ({
    path: issue.path.map(String).join('.'),
    message: issue.message,
  }));
  safeEmit(sink, { type: 'validation_error', at, path, method, issues });
  return errorResponse(400, { code: 'invalid_input', issues });
}

export function secureRoute<
  B extends z.ZodType = z.ZodNever,
  Q extends z.ZodType = z.ZodNever,
  P extends z.ZodType = z.ZodNever,
>(
  schemas: RouteSchemas<B, Q, P>,
  handler: (input: ValidatedInput<B, Q, P>) => Response | Promise<Response>,
): (req: NextRequest, context?: RouteContext) => Promise<Response> {
  const sink = schemas.sink ?? createNoopSink();
  const allowedMethods = schemas.method
    ? new Set<string>(Array.isArray(schemas.method) ? schemas.method : [schemas.method])
    : null;

  return async (req: NextRequest, context?: RouteContext): Promise<Response> => {
    const at = Date.now();
    const url = new URL(req.url);
    const path = url.pathname;

    if (allowedMethods && !allowedMethods.has(req.method)) {
      return errorResponse(405, { code: 'method_not_allowed' });
    }

    if (schemas.origin !== false && isMutating(req.method)) {
      const verdict = verifyOrigin(
        {
          origin: req.headers.get('origin'),
          secFetchSite: req.headers.get('sec-fetch-site'),
          host: url.host,
        },
        schemas.origin ?? {},
      );
      if (!verdict.ok) {
        safeEmit(sink, {
          type: 'csrf_block',
          at,
          ip: clientIp(req),
          path,
          method: req.method,
          reason: verdict.reason,
        });
        return errorResponse(403, { code: 'forbidden', reason: verdict.reason });
      }
    }

    if (schemas.rateLimit) {
      const key = schemas.rateLimit.key?.(req) ?? clientIp(req);
      const result = await schemas.rateLimit.limiter.limit(key, schemas.rateLimit.rule);
      if (!result.success) {
        safeEmit(sink, {
          type: 'rate_limit_block',
          at,
          ip: clientIp(req),
          path,
          method: req.method,
          key,
          rule: schemas.rateLimit.rule.prefix ?? 'route',
          limit: result.limit,
        });
        return errorResponse(
          429,
          { code: 'rate_limited' },
          { 'Retry-After': String(result.retryAfter) },
        );
      }
    }

    let body: unknown;
    let query: unknown;
    let params: unknown;

    if (schemas.body) {
      const parsed = schemas.body.safeParse(await readJsonBody(req));
      if (!parsed.success) {
        return validationError(parsed.error, sink, at, path, req.method);
      }
      body = parsed.data;
    }
    if (schemas.query) {
      const parsed = schemas.query.safeParse(Object.fromEntries(url.searchParams));
      if (!parsed.success) {
        return validationError(parsed.error, sink, at, path, req.method);
      }
      query = parsed.data;
    }
    if (schemas.params) {
      const raw = context?.params ? await context.params : {};
      const parsed = schemas.params.safeParse(raw);
      if (!parsed.success) {
        return validationError(parsed.error, sink, at, path, req.method);
      }
      params = parsed.data;
    }

    return handler({ req, body, query, params } as ValidatedInput<B, Q, P>);
  };
}

/** Alias for `secureRoute` when you only want validation/rate-limit/origin on a handler. */
export const withValidation = secureRoute;
