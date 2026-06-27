/**
 * Security event model. A discriminated union + a `SecuritySink` interface is the seam that
 * lets adapters emit structured events today (console) and a dashboard/SaaS consume them
 * later — with no change to any call site. Emission is fire-and-forget; adapters must never
 * await a sink on the request hot path.
 */

import { z } from 'zod';

interface SecurityEventBase {
  /** Epoch ms. */
  readonly at: number;
  readonly ip?: string;
  readonly path?: string;
  readonly method?: string;
  readonly requestId?: string;
}

export type SecurityEvent =
  | (SecurityEventBase & {
      readonly type: 'rate_limit_block';
      readonly key: string;
      readonly rule: string;
      readonly limit: number;
    })
  | (SecurityEventBase & {
      readonly type: 'csrf_block';
      readonly reason: string;
    })
  | (SecurityEventBase & {
      readonly type: 'origin_block';
      readonly origin: string | null;
      readonly reason: string;
    })
  | (SecurityEventBase & {
      readonly type: 'csp_violation';
      readonly directive: string;
      readonly blockedUri: string;
    })
  | (SecurityEventBase & {
      readonly type: 'validation_error';
      readonly issues: readonly { readonly path: string; readonly message: string }[];
    })
  | (SecurityEventBase & {
      readonly type: 'suspicious_request';
      readonly signal: string;
      readonly detail?: string;
    });

export type SecurityEventType = SecurityEvent['type'];

export interface SecuritySink {
  emit(event: SecurityEvent): void | Promise<void>;
}

export interface ConsoleSinkOptions {
  /** Emit one JSON object per event (default) vs. a human-readable line. */
  readonly json?: boolean;
  /** Sink override for tests; defaults to `console.error` (events go to stderr). */
  readonly write?: (line: string) => void;
}

/** Structured-log sink. Writes one JSON line per event to stderr by default. */
export function createConsoleSink(options: ConsoleSinkOptions = {}): SecuritySink {
  const json = options.json ?? true;
  const write = options.write ?? ((line: string) => console.error(line));
  return {
    emit(event: SecurityEvent): void {
      write(
        json
          ? JSON.stringify({ source: 'aegis', ...event })
          : `[aegis] ${event.type} ${JSON.stringify(event)}`,
      );
    },
  };
}

/** Fan an event out to several sinks. A throwing sink never breaks the others (or the request). */
export function createMultiSink(...sinks: readonly SecuritySink[]): SecuritySink {
  return {
    async emit(event: SecurityEvent): Promise<void> {
      // `Promise.resolve().then(...)` converts a *synchronous* throw inside a sink into a
      // rejected promise so `allSettled` absorbs it — one bad sink can't break the others.
      await Promise.allSettled(sinks.map((sink) => Promise.resolve().then(() => sink.emit(event))));
    },
  };
}

/** A sink that discards everything (default when observability is unconfigured). */
export function createNoopSink(): SecuritySink {
  return { emit: () => {} };
}

/**
 * Safely emit to a sink from the request path: never throws, never blocks. Wrap every
 * adapter-side emission with this so a misbehaving sink can't fail or slow a request.
 */
export function safeEmit(sink: SecuritySink, event: SecurityEvent): void {
  try {
    const result = sink.emit(event);
    if (result instanceof Promise) {
      result.catch(() => {});
    }
  } catch {
    // A security sink must never be able to break the request it is observing.
  }
}

/**
 * Schema for an untrusted CSP violation report body (the legacy `report-uri` shape). CSP
 * reports are attacker-influenceable, so always `safeParse` before constructing an event.
 */
export const cspReportSchema = z
  .object({
    'csp-report': z
      .object({
        'effective-directive': z.string().max(256).optional(),
        'violated-directive': z.string().max(256).optional(),
        'blocked-uri': z.string().max(2048).optional(),
        'document-uri': z.string().max(2048).optional(),
      })
      .loose(),
  })
  .transform((report) => {
    const body = report['csp-report'];
    return {
      directive: body['effective-directive'] ?? body['violated-directive'] ?? 'unknown',
      blockedUri: body['blocked-uri'] ?? 'unknown',
      documentUri: body['document-uri'],
    };
  });

export type CspReport = z.infer<typeof cspReportSchema>;
