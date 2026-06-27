/**
 * Rate limiting as pure window math over a tiny, atomic store contract.
 *
 * The store owns atomicity (one `INCR`-style op); the limiter owns the algorithm. This split
 * is what fixes the classic serverless bug where an in-process counter resets every
 * invocation and never actually limits — make the store distributed (e.g. Redis) and the
 * exact same limiter becomes correct under concurrency. Returns a full result shape
 * (`limit/remaining/reset/retryAfter`), not a bare boolean.
 */

export interface RateLimitResult {
  readonly success: boolean;
  readonly limit: number;
  readonly remaining: number;
  /** Epoch ms when the current window frees up. */
  readonly reset: number;
  /** Seconds to wait before retrying; `0` when allowed. Use for the `Retry-After` header. */
  readonly retryAfter: number;
}

/**
 * Atomic counter store. Implementations MUST make `increment` atomic (no lost updates under
 * concurrency). Keys are already namespaced to a specific time window by the limiter.
 */
export interface RateLimitStore {
  /** Atomically increment `windowKey`, (re)setting its TTL, and return the post-increment count. */
  increment(windowKey: string, ttlMs: number): Promise<number>;
  /** Read a counter without incrementing; returns 0 if absent/expired. */
  get(windowKey: string): Promise<number>;
}

export type RateLimitAlgorithm = 'sliding-window-counter' | 'fixed-window';

export interface RateLimitRule {
  readonly limit: number;
  readonly windowMs: number;
  /** Default: `sliding-window-counter`. */
  readonly algorithm?: RateLimitAlgorithm;
  /** Optional key namespace so multiple rules can share one store without collision. */
  readonly prefix?: string;
  /**
   * Per-rule override of the limiter-level `failureMode`. Security-critical rules should fail
   * closed.
   */
  readonly failureMode?: 'open' | 'closed';
}

export interface RateLimiterConfig {
  readonly store: RateLimitStore;
  /**
   * Behavior when the store throws (e.g. Redis down): `open` allows the request (favor
   * availability), `closed` denies it (favor safety). Default `open` — but always reported
   * via `onStoreError` so a silent outage can't hide. Individual rules can override this
   * per-rule via `RateLimitRule.failureMode`.
   */
  readonly failureMode?: 'open' | 'closed';
  readonly onStoreError?: (error: unknown, key: string) => void;
  /** Injectable clock for deterministic tests. Defaults to `Date.now`. */
  readonly now?: () => number;
}

/** Sensible presets. Override per call by spreading: `{ ...RATE_LIMIT_PRESETS.ai, limit: 50 }`. */
export const RATE_LIMIT_PRESETS = {
  /** Brute-force protection for login/signup. Fails closed: a store outage must not open the gate. */
  auth: { limit: 5, windowMs: 60_000, failureMode: 'closed' },
  /** General API throughput. Availability-oriented (default fail-open). */
  api: { limit: 100, windowMs: 60_000 },
  /** Expensive LLM/AI calls (cost-runaway protection). Fails closed to cap spend during an outage. */
  ai: { limit: 20, windowMs: 60_000, failureMode: 'closed' },
  /** Coarse per-IP ceiling. Availability-oriented (default fail-open). */
  ip: { limit: 60, windowMs: 60_000 },
} as const satisfies Record<string, RateLimitRule>;

export class RateLimiter {
  readonly #store: RateLimitStore;
  readonly #failureMode: 'open' | 'closed';
  readonly #onStoreError: ((error: unknown, key: string) => void) | undefined;
  readonly #now: () => number;

  constructor(config: RateLimiterConfig) {
    this.#store = config.store;
    this.#failureMode = config.failureMode ?? 'open';
    this.#onStoreError = config.onStoreError;
    this.#now = config.now ?? Date.now;
  }

  async limit(key: string, rule: RateLimitRule): Promise<RateLimitResult> {
    const algorithm = rule.algorithm ?? 'sliding-window-counter';
    const now = this.#now();
    const window = rule.windowMs;
    const prefix = rule.prefix ? `${rule.prefix}:` : '';
    const currentIndex = Math.floor(now / window);
    const reset = (currentIndex + 1) * window;
    const currentKey = `${prefix}${key}:${currentIndex}`;

    try {
      let estimated: number;
      if (algorithm === 'sliding-window-counter') {
        const previousKey = `${prefix}${key}:${currentIndex - 1}`;
        // The two ops are independent (different keys, atomicity is per-op), so run them
        // concurrently: a remote store then pays one round-trip of latency, not two.
        const [previousCount, currentCount] = await Promise.all([
          this.#store.get(previousKey),
          this.#store.increment(currentKey, window * 2),
        ]);
        const elapsedFraction = (now - currentIndex * window) / window;
        estimated = previousCount * (1 - elapsedFraction) + currentCount;
      } else {
        estimated = await this.#store.increment(currentKey, window);
      }

      const success = estimated <= rule.limit;
      const remaining = Math.max(0, Math.floor(rule.limit - estimated));
      const retryAfter = success ? 0 : Math.max(1, Math.ceil((reset - now) / 1000));
      return { success, limit: rule.limit, remaining, reset, retryAfter };
    } catch (error) {
      this.#onStoreError?.(error, key);
      const failureMode = rule.failureMode ?? this.#failureMode;
      if (failureMode === 'closed') {
        return {
          success: false,
          limit: rule.limit,
          remaining: 0,
          reset,
          retryAfter: Math.max(1, Math.ceil(window / 1000)),
        };
      }
      return { success: true, limit: rule.limit, remaining: rule.limit, reset, retryAfter: 0 };
    }
  }
}

/**
 * In-memory store. **Development / single-instance only.** Each serverless instance has its
 * own memory, so under concurrency this does NOT enforce a shared limit — use a distributed
 * store (e.g. `@aegiskit/store-upstash`) in production. Window separation is by key, so counts
 * are correct within one process; old windows are evicted by an LRU bound.
 */
export function createMemoryStore(options: { maxEntries?: number } = {}): RateLimitStore {
  const maxEntries = options.maxEntries ?? 10_000;
  const counts = new Map<string, number>();

  return {
    increment(windowKey: string): Promise<number> {
      const next = (counts.get(windowKey) ?? 0) + 1;
      // Re-insert to mark most-recently-used for LRU eviction order.
      counts.delete(windowKey);
      counts.set(windowKey, next);
      if (counts.size > maxEntries) {
        const oldest = counts.keys().next().value;
        if (oldest !== undefined) {
          counts.delete(oldest);
        }
      }
      return Promise.resolve(next);
    },
    get(windowKey: string): Promise<number> {
      return Promise.resolve(counts.get(windowKey) ?? 0);
    },
  };
}
