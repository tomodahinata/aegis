import { RateLimiter } from '@aegiskit/core';
import type { Redis } from '@upstash/redis';
import { describe, expect, it } from 'vitest';
import { createUpstashStore, type UpstashRedisLike } from './index';

/** In-memory double emulating the one Lua script this store uses (INCR + first-hit PEXPIRE). */
class FakeRedis implements UpstashRedisLike {
  private readonly store = new Map<string, number>();
  /** Every key this client has been asked to touch, in order — for namespacing assertions. */
  readonly seenKeys: string[] = [];

  eval(_script: string, keys: string[], _args: (string | number)[]): Promise<unknown> {
    const key = keys[0];
    if (key === undefined) {
      return Promise.resolve(0);
    }
    this.seenKeys.push(key);
    const next = (this.store.get(key) ?? 0) + 1;
    this.store.set(key, next);
    return Promise.resolve(next);
  }

  get<TData = unknown>(key: string): Promise<TData | null> {
    this.seenKeys.push(key);
    const value = this.store.get(key);
    return Promise.resolve((value ?? null) as TData | null);
  }
}

/** A client whose every reply is a shape `Number()` can't make finite (object / `"abc"`). */
class NonNumericRedis implements UpstashRedisLike {
  eval(): Promise<unknown> {
    return Promise.resolve({ unexpected: 'shape' });
  }
  get<TData = unknown>(): Promise<TData | null> {
    return Promise.resolve('abc' as unknown as TData);
  }
}

/** A client that never settles, to exercise the per-call timeout. */
class HangingRedis implements UpstashRedisLike {
  eval(): Promise<unknown> {
    return new Promise(() => {});
  }
  get<TData = unknown>(): Promise<TData | null> {
    return new Promise(() => {});
  }
}

describe('createUpstashStore', () => {
  it('increments a namespaced key and reads it back', async () => {
    const redis = new FakeRedis();
    const store = createUpstashStore({ redis });
    expect(await store.get('k:0')).toBe(0);
    expect(await store.increment('k:0', 1000)).toBe(1);
    expect(await store.increment('k:0', 1000)).toBe(2);
    expect(await store.get('k:0')).toBe(2);
    // Every real key Redis saw must carry the default namespace, never the bare windowKey.
    expect(redis.seenKeys.length).toBeGreaterThan(0);
    for (const key of redis.seenKeys) {
      expect(key.startsWith('aegis:rl:')).toBe(true);
    }
    expect(redis.seenKeys).toContain('aegis:rl:k:0');
  });

  it('applies a custom keyPrefix to both increment and get', async () => {
    const redis = new FakeRedis();
    const store = createUpstashStore({ redis, keyPrefix: 'tenant-a:' });
    await store.increment('k:0', 1000);
    await store.get('k:0');
    expect(redis.seenKeys).toEqual(['tenant-a:k:0', 'tenant-a:k:0']);
  });

  it('isolates counters across stores with different prefixes for the same windowKey', async () => {
    const redis = new FakeRedis();
    const storeA = createUpstashStore({ redis, keyPrefix: 'a:' });
    const storeB = createUpstashStore({ redis, keyPrefix: 'b:' });
    await storeA.increment('k:0', 1000);
    await storeA.increment('k:0', 1000);
    await storeB.increment('k:0', 1000);
    // Same windowKey, different prefix → separate counters, no collision.
    expect(await storeA.get('k:0')).toBe(2);
    expect(await storeB.get('k:0')).toBe(1);
  });

  it('rejects (rather than yielding NaN) when Redis returns a non-numeric reply', async () => {
    const store = createUpstashStore({ redis: new NonNumericRedis() });
    // A NaN here would silently produce `X-RateLimit-Remaining: NaN` and bypass onStoreError;
    // throwing routes the anomaly through the limiter's failureMode path.
    await expect(store.increment('k:0', 1000)).rejects.toThrow(/non-numeric/);
    await expect(store.get('k:0')).rejects.toThrow(/non-numeric/);
  });

  it('rejects after timeoutMs when Redis never responds (no unbounded hang)', async () => {
    const store = createUpstashStore({ redis: new HangingRedis(), timeoutMs: 20 });
    await expect(store.increment('k:0', 1000)).rejects.toThrow(/timeout/);
    await expect(store.get('k:0')).rejects.toThrow(/timeout/);
  });

  it('admits EXACTLY `limit` under 100 concurrent requests (the serverless-correctness guarantee)', async () => {
    const store = createUpstashStore({ redis: new FakeRedis() });
    const limiter = new RateLimiter({ store, now: () => 1_000_000 });
    const rule = { limit: 10, windowMs: 60_000, algorithm: 'fixed-window' as const };

    const results = await Promise.all(
      Array.from({ length: 100 }, () => limiter.limit('user:42', rule)),
    );

    expect(results.filter((r) => r.success).length).toBe(10);
  });

  it('is structurally compatible with a real @upstash/redis client', () => {
    // Compile-time assertion: if `Redis` ever stops satisfying `UpstashRedisLike`, this fails.
    const compatible: Redis extends UpstashRedisLike ? true : false = true;
    expect(compatible).toBe(true);
  });
});
