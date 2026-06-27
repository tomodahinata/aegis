/**
 * `createCspReportHandler` — a Route Handler that ingests CSP violation reports. Browsers POST
 * here because `hardenedCspPolicy`/`secure({ cspReportEndpoint })` wired `report-uri`/`report-to`.
 *
 * The body is attacker-influenceable, so every byte is treated as hostile: a hard size cap
 * (stream-counted, not Content-Length-trusted), `safeParse` of every report, an array cap for
 * the Reporting-API form, optional rate-limiting, and a 204 that never reflects input.
 */

import {
  type CspReport,
  cspReportSchema,
  type RateLimiter,
  type RateLimitRule,
  type SecuritySink,
  safeEmit,
} from '@aegiskit/core';

export interface CspReportHandlerOptions {
  readonly sink: SecuritySink;
  /** Max body bytes before a 413. Default 16384. */
  readonly maxBodyBytes?: number;
  /** Cap on reports in one Reporting-API array. Default 50. */
  readonly maxReports?: number;
  /** Optional per-IP limiter to blunt report floods. */
  readonly rateLimit?: { readonly limiter: RateLimiter; readonly rule: RateLimitRule };
}

const LEGACY_TYPE = 'application/csp-report';
const REPORTS_TYPE = 'application/reports+json';

function ipOf(req: Request): string {
  const forwarded = req.headers.get('x-forwarded-for');
  if (forwarded) {
    const first = forwarded.split(',')[0]?.trim();
    if (first) {
      return first;
    }
  }
  return req.headers.get('x-real-ip') ?? 'unknown';
}

/** Read the body, aborting (→ null) past `max` bytes — never buffers a hostile body whole. */
async function readCapped(req: Request, max: number): Promise<string | null> {
  const reader = req.body?.getReader();
  if (!reader) {
    return null;
  }
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) {
      break;
    }
    size += value.byteLength;
    if (size > max) {
      await reader.cancel();
      return null;
    }
    chunks.push(value);
  }
  const merged = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(merged);
}

function normalizeReportsApiBody(body: unknown): unknown {
  const record = (body ?? {}) as Record<string, unknown>;
  return {
    'csp-report': {
      'effective-directive': record['effectiveDirective'],
      'violated-directive': record['violatedDirective'],
      'blocked-uri': record['blockedURL'],
      'document-uri': record['documentURL'],
    },
  };
}

function extractReports(json: unknown, contentType: string, maxReports: number): CspReport[] {
  const reports: CspReport[] = [];
  if (contentType === REPORTS_TYPE && Array.isArray(json)) {
    for (const entry of json.slice(0, maxReports)) {
      const record = entry as { type?: unknown; body?: unknown };
      if (record.type !== 'csp-violation') {
        continue;
      }
      const parsed = cspReportSchema.safeParse(normalizeReportsApiBody(record.body));
      if (parsed.success) {
        reports.push(parsed.data);
      }
    }
  } else {
    const parsed = cspReportSchema.safeParse(json);
    if (parsed.success) {
      reports.push(parsed.data);
    }
  }
  return reports;
}

export function createCspReportHandler(
  options: CspReportHandlerOptions,
): (req: Request) => Promise<Response> {
  const maxBodyBytes = options.maxBodyBytes ?? 16_384;
  const maxReports = options.maxReports ?? 50;
  const { sink, rateLimit } = options;

  return async (req: Request): Promise<Response> => {
    if (req.method !== 'POST') {
      return new Response(null, { status: 405 });
    }
    const contentType =
      (req.headers.get('content-type') ?? '').split(';')[0]?.trim().toLowerCase() ?? '';
    if (contentType !== LEGACY_TYPE && contentType !== REPORTS_TYPE) {
      return new Response(null, { status: 415 });
    }

    if (rateLimit) {
      const result = await rateLimit.limiter.limit(ipOf(req), rateLimit.rule);
      if (!result.success) {
        return new Response(null, {
          status: 429,
          headers: { 'Retry-After': String(result.retryAfter) },
        });
      }
    }

    const raw = await readCapped(req, maxBodyBytes);
    if (raw === null) {
      return new Response(null, { status: 413 });
    }

    let json: unknown;
    try {
      json = JSON.parse(raw);
    } catch {
      return new Response(null, { status: 204 }); // malformed → swallow, never 500 on hostile input
    }

    const at = Date.now();
    const ip = ipOf(req);
    for (const report of extractReports(json, contentType, maxReports)) {
      safeEmit(sink, {
        type: 'csp_violation',
        at,
        ip,
        ...(report.documentUri !== undefined ? { path: report.documentUri } : {}),
        directive: report.directive,
        blockedUri: report.blockedUri,
      });
    }
    return new Response(null, { status: 204 });
  };
}
