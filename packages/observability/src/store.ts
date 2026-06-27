import type { SecurityEvent, SecurityEventType } from '@aegiskit/core';
import { EVENT_SEVERITY, SEVERITY_WEIGHT, type Severity } from './severity';

/** A persisted event: the wire event + server-assigned identity & receipt time. */
export type StoredEvent = SecurityEvent & {
  /** Idempotency key minted by the sink; the store's dedupe key. */
  readonly id: string;
  /** Server receive time (epoch ms), distinct from `at` (client/edge emit time). */
  readonly receivedAt: number;
};

export interface EventQuery {
  readonly type?: SecurityEventType | readonly SecurityEventType[];
  readonly path?: string;
  readonly since?: number;
  readonly until?: number;
  readonly limit?: number;
}

export interface PostureBucket {
  readonly start: number;
  readonly count: number;
  /** Severity-weighted event volume in this bucket (the input to the posture score). */
  readonly weightedVolume: number;
}

export interface PostureSummary {
  readonly window: { readonly since: number; readonly until: number };
  readonly total: number;
  readonly byType: Readonly<Record<SecurityEventType, number>>;
  readonly bySeverity: Readonly<Record<Severity, number>>;
  /** Blocking events (origin/csrf/rate-limit) ÷ total; 0 when total is 0. */
  readonly blockRate: number;
  readonly buckets: readonly PostureBucket[];
}

export interface SummaryWindow {
  readonly since: number;
  readonly until: number;
  /** Number of equal-width time buckets. Default 24. */
  readonly bucketCount?: number;
}

export interface EventStore {
  /** Append a batch. MUST be idempotent on `id`. */
  append(events: readonly StoredEvent[]): Promise<void>;
  /** Query, newest-first by `receivedAt`. */
  query(filter?: EventQuery): Promise<StoredEvent[]>;
  /** Aggregate over a window for the dashboard / posture score. */
  summary(window: SummaryWindow): Promise<PostureSummary>;
}

const BLOCKING: ReadonlySet<SecurityEventType> = new Set([
  'origin_block',
  'csrf_block',
  'rate_limit_block',
]);
const QUERY_LIMIT_MAX = 1000;

function emptyByType(): Record<SecurityEventType, number> {
  return {
    rate_limit_block: 0,
    csrf_block: 0,
    origin_block: 0,
    csp_violation: 0,
    validation_error: 0,
    suspicious_request: 0,
  };
}

/** Pure aggregation over events in `[since, until)`. Adapters may reuse this or push it into SQL. */
export function summarize(events: readonly StoredEvent[], window: SummaryWindow): PostureSummary {
  const { since, until } = window;
  const bucketCount = Math.max(1, window.bucketCount ?? 24);
  const width = Math.max(1, (until - since) / bucketCount);

  const byType = emptyByType();
  const bySeverity: Record<Severity, number> = { low: 0, medium: 0, high: 0 };
  const bucketCounts = new Array<number>(bucketCount).fill(0);
  const bucketVolumes = new Array<number>(bucketCount).fill(0);
  let total = 0;
  let blockCount = 0;

  for (const event of events) {
    if (event.receivedAt < since || event.receivedAt >= until) {
      continue;
    }
    total += 1;
    byType[event.type] += 1;
    const severity = EVENT_SEVERITY[event.type];
    bySeverity[severity] += 1;
    if (BLOCKING.has(event.type)) {
      blockCount += 1;
    }
    const index = Math.min(
      bucketCount - 1,
      Math.max(0, Math.floor((event.receivedAt - since) / width)),
    );
    bucketCounts[index] = (bucketCounts[index] ?? 0) + 1;
    bucketVolumes[index] = (bucketVolumes[index] ?? 0) + SEVERITY_WEIGHT[severity];
  }

  const buckets: PostureBucket[] = [];
  for (let i = 0; i < bucketCount; i++) {
    buckets.push({
      start: since + i * width,
      count: bucketCounts[i] ?? 0,
      weightedVolume: bucketVolumes[i] ?? 0,
    });
  }

  return {
    window: { since, until },
    total,
    byType,
    bySeverity,
    blockRate: total > 0 ? blockCount / total : 0,
    buckets,
  };
}

export interface MemoryEventStoreOptions {
  /** Ring-buffer capacity; oldest evicted past this. Default 10_000. */
  readonly capacity?: number;
}

/**
 * In-memory `EventStore`. **Single-instance only** (a ring buffer in one process) — perfect for
 * local/self-host, but use a distributed adapter (e.g. `@aegiskit/store-supabase`) for production
 * so events survive restarts and aggregate across instances.
 */
export function createMemoryEventStore(options: MemoryEventStoreOptions = {}): EventStore {
  const capacity = options.capacity ?? 10_000;
  const events: StoredEvent[] = [];
  const seen = new Set<string>();

  return {
    append(batch: readonly StoredEvent[]): Promise<void> {
      for (const event of batch) {
        if (seen.has(event.id)) {
          continue; // idempotent
        }
        seen.add(event.id);
        events.push(event);
        if (events.length > capacity) {
          const removed = events.shift();
          if (removed) {
            seen.delete(removed.id);
          }
        }
      }
      return Promise.resolve();
    },

    query(filter: EventQuery = {}): Promise<StoredEvent[]> {
      const types =
        filter.type === undefined
          ? undefined
          : new Set<SecurityEventType>(
              typeof filter.type === 'string' ? [filter.type] : filter.type,
            );
      const matched = events
        .filter(
          (event) =>
            (types === undefined || types.has(event.type)) &&
            (filter.path === undefined || event.path === filter.path) &&
            (filter.since === undefined || event.receivedAt >= filter.since) &&
            (filter.until === undefined || event.receivedAt < filter.until),
        )
        .sort((a, b) => b.receivedAt - a.receivedAt);
      const limit = Math.min(filter.limit ?? 100, QUERY_LIMIT_MAX);
      return Promise.resolve(matched.slice(0, limit));
    },

    summary(window: SummaryWindow): Promise<PostureSummary> {
      return Promise.resolve(summarize(events, window));
    },
  };
}
