/**
 * The resource budget — hard ceilings that make it impossible to DoS the target. The `RequestLedger`
 * is the shared choke point that enforces `maxRequests`: every request reserves a slot, and once the
 * cap is hit the run stops cleanly (over-budget is recorded as `skipped`, never silently turned into a
 * false "clean").
 */

export interface Budget {
  /** Hard cap on total requests across the whole run. */
  readonly maxRequests: number;
  /** Max concurrent in-flight requests — protects a dev server from a connection storm. */
  readonly concurrency: number;
  /** Per-request timeout (AbortSignal.timeout). */
  readonly perRequestTimeoutMs: number;
  /** Global wall-clock deadline for the entire run. */
  readonly deadlineMs: number;
  /** Minimum gap between successive request starts — the self-rate-limit. */
  readonly minIntervalMs: number;
}

export const DEFAULT_BUDGET: Budget = {
  maxRequests: 500,
  concurrency: 4,
  perRequestTimeoutMs: 5000,
  deadlineMs: 120_000,
  minIntervalMs: 50,
};

function clampInt(value: number | undefined, fallback: number, min: number, max: number): number {
  if (value === undefined || !Number.isFinite(value)) {
    return fallback;
  }
  return Math.max(min, Math.min(max, Math.trunc(value)));
}

/** Merge a partial budget over the defaults, clamping each field into a safe range. */
export function resolveBudget(partial?: Partial<Budget>): Budget {
  return {
    maxRequests: clampInt(partial?.maxRequests, DEFAULT_BUDGET.maxRequests, 1, 100_000),
    concurrency: clampInt(partial?.concurrency, DEFAULT_BUDGET.concurrency, 1, 32),
    perRequestTimeoutMs: clampInt(
      partial?.perRequestTimeoutMs,
      DEFAULT_BUDGET.perRequestTimeoutMs,
      100,
      60_000,
    ),
    deadlineMs: clampInt(partial?.deadlineMs, DEFAULT_BUDGET.deadlineMs, 1000, 3_600_000),
    minIntervalMs: clampInt(partial?.minIntervalMs, DEFAULT_BUDGET.minIntervalMs, 0, 10_000),
  };
}

export interface RequestLedger {
  /** Reserve one request slot. Returns false once `maxRequests` is exhausted — the caller must stop. */
  tryReserve(): boolean;
  /** Requests reserved so far. */
  readonly sent: number;
  /** True once the wall-clock deadline has passed. */
  deadlineExceeded(): boolean;
}

/** A fresh ledger for one run. `now` is injectable for deterministic tests. */
export function createLedger(budget: Budget, now: () => number = Date.now): RequestLedger {
  let sent = 0;
  const startedAt = now();
  return {
    tryReserve(): boolean {
      if (sent >= budget.maxRequests) {
        return false;
      }
      sent += 1;
      return true;
    },
    get sent(): number {
      return sent;
    },
    deadlineExceeded(): boolean {
      return now() - startedAt >= budget.deadlineMs;
    },
  };
}
