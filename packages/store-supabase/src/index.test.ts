import type { StoredEvent } from '@aegiskit/observability';
import { describe, expect, it } from 'vitest';
import {
  type AegisEventRow,
  type AegisSelectBuilder,
  createSupabaseEventStore,
  eventToRow,
  rowToEvent,
  type SupabaseEventClient,
} from './index';

function rlb(id: string, receivedAt: number): StoredEvent {
  return {
    type: 'rate_limit_block',
    at: receivedAt,
    key: 'k',
    rule: 'ip',
    limit: 60,
    id,
    receivedAt,
  };
}
function originBlock(id: string, receivedAt: number): StoredEvent {
  return {
    type: 'origin_block',
    at: receivedAt,
    origin: 'https://evil',
    reason: 'host-mismatch',
    id,
    receivedAt,
  };
}

function column(row: AegisEventRow, name: string): string {
  return String((row as unknown as Record<string, unknown>)[name] ?? '');
}

/** A faithful-enough in-memory Supabase double supporting the chain the store uses. */
function fakeClient(): { client: SupabaseEventClient; rows: AegisEventRow[] } {
  const rows: AegisEventRow[] = [];
  const select = (): AegisSelectBuilder => {
    const predicates: Array<(r: AegisEventRow) => boolean> = [];
    let descending = false;
    let max = Number.POSITIVE_INFINITY;
    const run = () => {
      let result = rows.filter((r) => predicates.every((p) => p(r)));
      if (descending) {
        result = [...result].sort((a, b) =>
          a.received_at < b.received_at ? 1 : a.received_at > b.received_at ? -1 : 0,
        );
      }
      if (Number.isFinite(max)) {
        result = result.slice(0, max);
      }
      return { data: result, error: null };
    };
    const builder = {
      eq: (c: string, v: string) => {
        predicates.push((r) => column(r, c) === v);
        return builder;
      },
      in: (c: string, v: readonly string[]) => {
        predicates.push((r) => v.includes(column(r, c)));
        return builder;
      },
      gte: (c: string, v: string) => {
        predicates.push((r) => column(r, c) >= v);
        return builder;
      },
      lt: (c: string, v: string) => {
        predicates.push((r) => column(r, c) < v);
        return builder;
      },
      order: (_c: string, o: { ascending: boolean }) => {
        descending = !o.ascending;
        return builder;
      },
      limit: (n: number) => {
        max = n;
        return builder;
      },
      // biome-ignore lint/suspicious/noThenProperty: this fake deliberately mimics Supabase's thenable PostgrestFilterBuilder.
      then: (
        onf?: ((v: ReturnType<typeof run>) => unknown) | null,
        onr?: ((reason: unknown) => unknown) | null,
      ) => Promise.resolve(run()).then(onf, onr),
    };
    return builder as unknown as AegisSelectBuilder;
  };
  const client: SupabaseEventClient = {
    from: () => ({
      upsert: (newRows: readonly AegisEventRow[]) => {
        for (const row of newRows) {
          if (!rows.some((existing) => existing.id === row.id)) {
            rows.push(row);
          }
        }
        return Promise.resolve({ data: null, error: null });
      },
      select,
    }),
  };
  return { client, rows };
}

describe('eventToRow / rowToEvent', () => {
  it('round-trips a StoredEvent through the row shape', () => {
    const event = rlb('a', 1_700_000);
    expect(rowToEvent(eventToRow(event))).toEqual(event);
  });
});

describe('createSupabaseEventStore', () => {
  it('appends idempotently and queries newest-first', async () => {
    const store = createSupabaseEventStore({ client: fakeClient().client });
    await store.append([rlb('a', 10), originBlock('b', 20)]);
    await store.append([rlb('a', 10)]); // duplicate id ignored
    const all = await store.query();
    expect(all).toHaveLength(2);
    expect(all[0]?.id).toBe('b');
  });

  it('filters by type and time window', async () => {
    const store = createSupabaseEventStore({ client: fakeClient().client });
    await store.append([rlb('a', 10), originBlock('b', 20), rlb('c', 30)]);
    expect(await store.query({ type: 'origin_block' })).toHaveLength(1);
    expect(await store.query({ since: 25 })).toHaveLength(1);
  });

  it('summarizes a window', async () => {
    const store = createSupabaseEventStore({ client: fakeClient().client });
    await store.append([originBlock('a', 5), rlb('b', 50)]);
    const summary = await store.summary({ since: 0, until: 100, bucketCount: 10 });
    expect(summary.total).toBe(2);
    expect(summary.byType.origin_block).toBe(1);
  });

  it('throws on a Postgrest error (fail-loud, never silent)', async () => {
    const client: SupabaseEventClient = {
      from: () => ({
        upsert: () => Promise.resolve({ data: null, error: { message: 'permission denied' } }),
        select: () => ({}) as unknown as AegisSelectBuilder,
      }),
    };
    await expect(createSupabaseEventStore({ client }).append([rlb('a', 1)])).rejects.toThrow(
      'permission denied',
    );
  });
});
