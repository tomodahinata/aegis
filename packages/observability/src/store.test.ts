import type { SecurityEventType } from '@aegiskit/core';
import { describe, expect, it } from 'vitest';
import { createMemoryEventStore, type StoredEvent, summarize } from './store';

function mk(type: SecurityEventType, receivedAt: number, id: string): StoredEvent {
  const base = { at: receivedAt, receivedAt, id };
  switch (type) {
    case 'csrf_block':
      return { ...base, type, reason: 'r' };
    case 'origin_block':
      return { ...base, type, origin: null, reason: 'r' };
    case 'csp_violation':
      return { ...base, type, directive: 'script-src', blockedUri: 'u' };
    case 'validation_error':
      return { ...base, type, issues: [] };
    case 'suspicious_request':
      return { ...base, type, signal: 's' };
    default:
      return { ...base, type: 'rate_limit_block', key: 'k', rule: 'ip', limit: 60 };
  }
}

describe('createMemoryEventStore', () => {
  it('is idempotent on id', async () => {
    const store = createMemoryEventStore();
    await store.append([mk('rate_limit_block', 1, 'a')]);
    await store.append([mk('rate_limit_block', 1, 'a')]);
    expect(await store.query()).toHaveLength(1);
  });

  it('queries newest-first with filters and a capped limit', async () => {
    const store = createMemoryEventStore();
    await store.append([
      mk('rate_limit_block', 10, 'a'),
      mk('origin_block', 20, 'b'),
      mk('rate_limit_block', 30, 'c'),
    ]);
    expect((await store.query())[0]?.id).toBe('c'); // newest-first
    expect(await store.query({ type: 'origin_block' })).toHaveLength(1);
    expect(await store.query({ since: 25 })).toHaveLength(1);
    expect(await store.query({ until: 25 })).toHaveLength(2);
    expect(await store.query({ limit: 1 })).toHaveLength(1);
  });

  it('evicts oldest past capacity', async () => {
    const store = createMemoryEventStore({ capacity: 2 });
    await store.append([mk('rate_limit_block', 1, 'a')]);
    await store.append([mk('rate_limit_block', 2, 'b')]);
    await store.append([mk('rate_limit_block', 3, 'c')]); // evicts 'a'
    const ids = (await store.query()).map((e) => e.id);
    expect(ids).toEqual(['c', 'b']);
  });
});

describe('summarize', () => {
  it('counts by type and severity, computes block-rate and buckets', () => {
    const events = [
      mk('origin_block', 5, 'a'), // high, blocking
      mk('csp_violation', 50, 'b'), // low, non-blocking
      mk('rate_limit_block', 95, 'c'), // medium, blocking
    ];
    const summary = summarize(events, { since: 0, until: 100, bucketCount: 10 });
    expect(summary.total).toBe(3);
    expect(summary.byType.origin_block).toBe(1);
    expect(summary.bySeverity).toEqual({ high: 1, medium: 1, low: 1 });
    expect(summary.blockRate).toBeCloseTo(2 / 3);
    expect(summary.buckets).toHaveLength(10);
    expect(summary.buckets[0]?.weightedVolume).toBe(10); // the high event
    expect(summary.buckets[9]?.weightedVolume).toBe(3); // the medium event
  });

  it('ignores events outside the window', () => {
    const summary = summarize([mk('origin_block', 200, 'a')], { since: 0, until: 100 });
    expect(summary.total).toBe(0);
  });
});
