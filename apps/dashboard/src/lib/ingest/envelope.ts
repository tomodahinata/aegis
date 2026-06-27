import { z } from 'zod';

// The UNTRUSTED ingestion boundary: every field is length-bounded (the store is in memory, so
// an unbounded string is a memory-DoS vector). Mirrors `SecurityEvent` + the sink's `id`.
const base = z.object({
  id: z.string().min(1).max(128),
  at: z.number().int().nonnegative(),
  ip: z.string().max(64).optional(),
  path: z.string().max(2048).optional(),
  method: z.string().max(16).optional(),
  requestId: z.string().max(128).optional(),
});

const wireEvent = z.discriminatedUnion('type', [
  base.extend({
    type: z.literal('rate_limit_block'),
    key: z.string().max(256),
    rule: z.string().max(128),
    limit: z.number().int(),
  }),
  base.extend({ type: z.literal('csrf_block'), reason: z.string().max(128) }),
  base.extend({
    type: z.literal('origin_block'),
    origin: z.string().max(2048).nullable(),
    reason: z.string().max(128),
  }),
  base.extend({
    type: z.literal('csp_violation'),
    directive: z.string().max(256),
    blockedUri: z.string().max(2048),
  }),
  base.extend({
    type: z.literal('validation_error'),
    issues: z.array(z.object({ path: z.string().max(256), message: z.string().max(512) })).max(100),
  }),
  base.extend({
    type: z.literal('suspicious_request'),
    signal: z.string().max(128),
    detail: z.string().max(512).optional(),
  }),
]);

export const eventBatchSchema = z.object({
  events: z.array(wireEvent).min(1).max(500),
});

export type WireEvent = z.infer<typeof wireEvent>;
