/**
 * `@aegiskit/store-upstash` — an atomic `RateLimitStore` backed by Upstash Redis.
 *
 * This is the store that makes Aegis rate limiting correct on serverless: the increment is a
 * single atomic Redis operation (a Lua `INCR` + first-hit `PEXPIRE`), so concurrent function
 * invocations share one counter — unlike an in-process map, which resets per instance and
 * never actually limits.
 */

import type { RateLimitStore } from '@aegiskit/core';

/**
 * Minimal structural view of an Upstash Redis client. Depending on the shape (not the exact
 * package version) keeps this store decoupled — any `@upstash/redis` `Redis` instance fits.
 */
export interface UpstashRedisLike {
  eval(script: string, keys: string[], args: (string | number)[]): Promise<unknown>;
  get<TData = unknown>(key: string): Promise<TData | null>;
}

export interface UpstashStoreOptions {
  readonly redis: UpstashRedisLike;
  /** Key namespace, so multiple apps can share one Redis. Default `aegis:rl:`. */
  readonly keyPrefix?: string;
  /**
   * Per-call deadline for each remote Redis op. A stalled Redis must not hang the request
   * forever — on expiry the call rejects, so the limiter's `failureMode` engages. Default
   * `1000` ms.
   */
  readonly timeoutMs?: number;
}

// Atomic: increment the counter and, only when it is newly created, set its TTL. One round trip.
const INCREMENT_SCRIPT = `local count = redis.call('INCR', KEYS[1])
if count == 1 then
  redis.call('PEXPIRE', KEYS[1], ARGV[1])
end
return count`;

/**
 * Race `promise` against a deadline, rejecting (never resolving) on expiry so a stalled Redis
 * surfaces as a store error instead of an unbounded hang. The timer is always cleared on settle,
 * so no timer leaks regardless of which side wins.
 */
function withTimeout<T>(promise: Promise<T>, ms: number, label: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout>;
  const deadline = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(
      () => reject(new Error(`upstash: store timeout after ${ms}ms (${label})`)),
      ms,
    );
  });
  return Promise.race([promise, deadline]).finally(() => clearTimeout(timer));
}

/**
 * Coerce a Redis reply to a finite number, throwing on anything else. An unexpected reply shape
 * (object, non-numeric string) would otherwise become `NaN` and silently degrade every request
 * without ever reaching the limiter's `onStoreError`/`failureMode` path — so we fail loud.
 */
function toFiniteNumber(value: unknown): number {
  const n = Number(value);
  if (!Number.isFinite(n)) {
    throw new Error('upstash: non-numeric reply from store');
  }
  return n;
}

/** Create a `RateLimitStore` backed by an Upstash Redis client. */
export function createUpstashStore(options: UpstashStoreOptions): RateLimitStore {
  const { redis } = options;
  const prefix = options.keyPrefix ?? 'aegis:rl:';
  const timeoutMs = options.timeoutMs ?? 1000;

  return {
    async increment(windowKey: string, ttlMs: number): Promise<number> {
      const result = await withTimeout(
        redis.eval(INCREMENT_SCRIPT, [prefix + windowKey], [Math.ceil(ttlMs)]),
        timeoutMs,
        'increment',
      );
      return toFiniteNumber(result);
    },
    async get(windowKey: string): Promise<number> {
      const value = await withTimeout(
        redis.get<number | string | null>(prefix + windowKey),
        timeoutMs,
        'get',
      );
      return value === null || value === undefined ? 0 : toFiniteNumber(value);
    },
  };
}
