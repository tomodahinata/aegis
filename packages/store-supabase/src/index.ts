/**
 * `@aegiskit/store-supabase` — a persistent `EventStore` backed by Supabase/Postgres.
 *
 * The store is defined against a minimal structural view of the Supabase client (so it isn't
 * coupled to a version), maps `StoredEvent` ↔ table row, and relies on the shipped migration's
 * RLS for the access-control boundary. Idempotency is the table's primary key (`insert … on
 * conflict do nothing`, expressed as `upsert({ ignoreDuplicates })`).
 */

import {
  type EventQuery,
  type EventStore,
  type PostureSummary,
  type StoredEvent,
  type SummaryWindow,
  summarize,
} from '@aegiskit/observability';

export interface AegisEventRow {
  id: string;
  type: string;
  received_at: string;
  at: number;
  ip: string | null;
  path: string | null;
  method: string | null;
  request_id: string | null;
  data: Record<string, unknown>;
}

export interface PostgrestResult<T> {
  readonly data: T | null;
  readonly error: { readonly message: string } | null;
}

/** The chained filter/order/limit builder we use — a real `PostgrestFilterBuilder` satisfies this. */
export interface AegisSelectBuilder extends PromiseLike<PostgrestResult<AegisEventRow[]>> {
  eq(column: string, value: string): AegisSelectBuilder;
  in(column: string, values: readonly string[]): AegisSelectBuilder;
  gte(column: string, value: string): AegisSelectBuilder;
  lt(column: string, value: string): AegisSelectBuilder;
  order(column: string, options: { ascending: boolean }): AegisSelectBuilder;
  limit(count: number): AegisSelectBuilder;
}

export interface AegisTableClient {
  upsert(
    rows: readonly AegisEventRow[],
    options: { onConflict: string; ignoreDuplicates: boolean },
  ): PromiseLike<PostgrestResult<unknown>>;
  select(columns: string): AegisSelectBuilder;
}

/** Minimal structural view of a Supabase client. A real `SupabaseClient` is assignable. */
export interface SupabaseEventClient {
  from(table: string): AegisTableClient;
}

export interface SupabaseEventStoreOptions {
  readonly client: SupabaseEventClient;
  /** Table name. Default `aegis_events`. */
  readonly tableName?: string;
  /** Max rows fetched to compute a summary window. Default 10_000. */
  readonly summaryFetchLimit?: number;
}

const BASE_KEYS: ReadonlySet<string> = new Set([
  'id',
  'receivedAt',
  'type',
  'at',
  'ip',
  'path',
  'method',
  'requestId',
]);

export function eventToRow(event: StoredEvent): AegisEventRow {
  const record = event as unknown as Record<string, unknown>;
  const data: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(record)) {
    if (!BASE_KEYS.has(key)) {
      data[key] = value;
    }
  }
  return {
    id: event.id,
    type: event.type,
    received_at: new Date(event.receivedAt).toISOString(),
    at: event.at,
    ip: event.ip ?? null,
    path: event.path ?? null,
    method: event.method ?? null,
    request_id: event.requestId ?? null,
    data,
  };
}

export function rowToEvent(row: AegisEventRow): StoredEvent {
  return {
    id: row.id,
    receivedAt: Date.parse(row.received_at),
    type: row.type,
    at: row.at,
    ...(row.ip !== null ? { ip: row.ip } : {}),
    ...(row.path !== null ? { path: row.path } : {}),
    ...(row.method !== null ? { method: row.method } : {}),
    ...(row.request_id !== null ? { requestId: row.request_id } : {}),
    ...row.data,
  } as unknown as StoredEvent;
}

const QUERY_LIMIT_MAX = 1000;

export function createSupabaseEventStore(options: SupabaseEventStoreOptions): EventStore {
  const table = options.tableName ?? 'aegis_events';
  const summaryFetchLimit = options.summaryFetchLimit ?? 10_000;
  const { client } = options;

  return {
    async append(events: readonly StoredEvent[]): Promise<void> {
      if (events.length === 0) {
        return;
      }
      const { error } = await client
        .from(table)
        .upsert(events.map(eventToRow), { onConflict: 'id', ignoreDuplicates: true });
      if (error) {
        throw new Error(`@aegiskit/store-supabase: append failed: ${error.message}`);
      }
    },

    async query(filter: EventQuery = {}): Promise<StoredEvent[]> {
      let builder = client.from(table).select('*');
      if (filter.type !== undefined) {
        builder =
          typeof filter.type === 'string'
            ? builder.eq('type', filter.type)
            : builder.in('type', [...filter.type]);
      }
      if (filter.path !== undefined) {
        builder = builder.eq('path', filter.path);
      }
      if (filter.since !== undefined) {
        builder = builder.gte('received_at', new Date(filter.since).toISOString());
      }
      if (filter.until !== undefined) {
        builder = builder.lt('received_at', new Date(filter.until).toISOString());
      }
      const { data, error } = await builder
        .order('received_at', { ascending: false })
        .limit(Math.min(filter.limit ?? 100, QUERY_LIMIT_MAX));
      if (error) {
        throw new Error(`@aegiskit/store-supabase: query failed: ${error.message}`);
      }
      return (data ?? []).map(rowToEvent);
    },

    async summary(window: SummaryWindow): Promise<PostureSummary> {
      const { data, error } = await client
        .from(table)
        .select('*')
        .gte('received_at', new Date(window.since).toISOString())
        .lt('received_at', new Date(window.until).toISOString())
        .order('received_at', { ascending: false })
        .limit(summaryFetchLimit);
      if (error) {
        throw new Error(`@aegiskit/store-supabase: summary failed: ${error.message}`);
      }
      return summarize((data ?? []).map(rowToEvent), window);
    },
  };
}
