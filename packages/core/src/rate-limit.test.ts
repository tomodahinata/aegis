import fc from 'fast-check';
import { describe, expect, it, vi } from 'vitest';
import {
  createMemoryStore,
  RATE_LIMIT_PRESETS,
  RateLimiter,
  type RateLimitStore,
} from './rate-limit';

function fixedClock(at: number): () => number {
  return () => at;
}

/** A clock whose value can be advanced between `limit()` calls, for window-boundary tests. */
function mutableClock(start: number): { now: () => number; set: (at: number) => void } {
  let value = start;
  return { now: () => value, set: (at: number) => (value = at) };
}

describe('RateLimiter', () => {
  it('admits exactly `limit` requests, then blocks (fixed-window)', async () => {
    const limiter = new RateLimiter({ store: createMemoryStore(), now: fixedClock(1_000_000) });
    const rule = { limit: 5, windowMs: 60_000, algorithm: 'fixed-window' as const };

    const results = [];
    for (let i = 0; i < 7; i++) {
      results.push(await limiter.limit('user:1', rule));
    }

    expect(results.slice(0, 5).every((r) => r.success)).toBe(true);
    expect(results[5]?.success).toBe(false);
    expect(results[6]?.success).toBe(false);
    expect(results[4]?.remaining).toBe(0);
    expect(results[5]?.retryAfter).toBeGreaterThan(0);
  });

  it('reports a correct Retry-After and reset', async () => {
    const now = 1_000_000;
    const limiter = new RateLimiter({ store: createMemoryStore(), now: fixedClock(now) });
    const rule = { limit: 1, windowMs: 60_000, algorithm: 'fixed-window' as const };
    await limiter.limit('k', rule);
    const blocked = await limiter.limit('k', rule);
    expect(blocked.success).toBe(false);
    expect(blocked.reset).toBe(Math.floor(now / 60_000) * 60_000 + 60_000);
    expect(blocked.retryAfter).toBeLessThanOrEqual(60);
  });

  it('isolates separate keys', async () => {
    const limiter = new RateLimiter({ store: createMemoryStore(), now: fixedClock(1_000_000) });
    const rule = { limit: 1, windowMs: 60_000 };
    expect((await limiter.limit('a', rule)).success).toBe(true);
    expect((await limiter.limit('b', rule)).success).toBe(true);
    expect((await limiter.limit('a', rule)).success).toBe(false);
  });

  it('fails open by default but reports the error', async () => {
    const onStoreError = vi.fn();
    const brokenStore: RateLimitStore = {
      increment: () => Promise.reject(new Error('redis down')),
      get: () => Promise.reject(new Error('redis down')),
    };
    const limiter = new RateLimiter({ store: brokenStore, onStoreError });
    const result = await limiter.limit('k', RATE_LIMIT_PRESETS.api);
    expect(result.success).toBe(true);
    expect(onStoreError).toHaveBeenCalledOnce();
  });

  it('fails closed when configured to', async () => {
    const brokenStore: RateLimitStore = {
      increment: () => Promise.reject(new Error('redis down')),
      get: () => Promise.reject(new Error('redis down')),
    };
    const limiter = new RateLimiter({ store: brokenStore, failureMode: 'closed' });
    const result = await limiter.limit('k', RATE_LIMIT_PRESETS.api);
    expect(result.success).toBe(false);
    expect(result.retryAfter).toBeGreaterThan(0);
  });

  it('sliding-window: a decayed previous window still blocks mid-window', async () => {
    const window = 60_000;
    const limit = 10;
    const clock = mutableClock(window); // start inside window index 1
    const limiter = new RateLimiter({ store: createMemoryStore(), now: clock.now });
    const rule = { limit, windowMs: window }; // default sliding-window-counter

    // Saturate window index 1 to exactly `limit` requests.
    for (let i = 0; i < limit; i++) {
      expect((await limiter.limit('user:1', rule)).success).toBe(true);
    }

    // Advance one tick into window index 2 (10% elapsed). The previous window contributes
    // 10 * (1 - 0.1) = 9, plus this request's current count of 1 → estimated 10 ≤ limit, so
    // this single request is still admitted at the boundary.
    clock.set(2 * window + window * 0.1);
    expect((await limiter.limit('user:1', rule)).success).toBe(true);

    // A second request in the same position: 9 (decayed) + 2 = 11 > 10 → blocked. The decayed
    // previous-window estimate is what enforces this; a naive fixed-window would have reset.
    expect((await limiter.limit('user:1', rule)).success).toBe(false);

    // Far into the window the previous contribution decays away and requests flow again.
    clock.set(2 * window + window * 0.95); // 5% of window left → previous weight ~0.05
    expect((await limiter.limit('user:1', rule)).success).toBe(true);
  });

  it('a rule-level failureMode overrides the limiter default on store error', async () => {
    const onStoreError = vi.fn();
    const brokenStore: RateLimitStore = {
      increment: () => Promise.reject(new Error('redis down')),
      get: () => Promise.reject(new Error('redis down')),
    };
    // Limiter default is open (the unsafe-but-available posture).
    const limiter = new RateLimiter({ store: brokenStore, failureMode: 'open', onStoreError });

    // A rule that opts into fail-closed denies despite the open default.
    const closedRule = { limit: 5, windowMs: 60_000, failureMode: 'closed' as const };
    const closed = await limiter.limit('k', closedRule);
    expect(closed.success).toBe(false);
    expect(closed.retryAfter).toBeGreaterThan(0);

    // A rule without an override still follows the limiter default (open).
    const defaultRule = { limit: 5, windowMs: 60_000 };
    expect((await limiter.limit('k', defaultRule)).success).toBe(true);
  });

  it('property: remaining is non-increasing and success flips exactly at limit+1', async () => {
    await fc.assert(
      fc.asyncProperty(fc.integer({ min: 1, max: 30 }), async (limit) => {
        const limiter = new RateLimiter({ store: createMemoryStore(), now: fixedClock(5_000_000) });
        const rule = { limit, windowMs: 60_000, algorithm: 'fixed-window' as const };
        let previousRemaining = Number.POSITIVE_INFINITY;
        for (let i = 1; i <= limit + 3; i++) {
          const result = await limiter.limit('key', rule);
          expect(result.remaining).toBeLessThanOrEqual(previousRemaining);
          previousRemaining = result.remaining;
          expect(result.success).toBe(i <= limit);
        }
      }),
      { numRuns: 25 },
    );
  });
});

describe('createMemoryStore', () => {
  it('increments atomically within a process and reads back counts', async () => {
    const store = createMemoryStore();
    expect(await store.get('k:0')).toBe(0);
    expect(await store.increment('k:0', 1000)).toBe(1);
    expect(await store.increment('k:0', 1000)).toBe(2);
    expect(await store.get('k:0')).toBe(2);
  });

  it('evicts least-recently-used keys past maxEntries', async () => {
    const store = createMemoryStore({ maxEntries: 2 });
    await store.increment('a', 1000);
    await store.increment('b', 1000);
    await store.increment('c', 1000); // evicts 'a'
    expect(await store.get('a')).toBe(0);
    expect(await store.get('c')).toBe(1);
  });
});
