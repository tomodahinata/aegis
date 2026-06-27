/**
 * The bounded request gate every probe request must pass before it reaches the network. It enforces,
 * centrally and unbypassably: the total-request ceiling (via the shared `RequestLedger`), the
 * concurrency cap (a semaphore), the self-rate-limit (a minimum gap between request starts), and the
 * global deadline. Probes never see this directly — the HTTP client acquires a slot per request.
 */

import type { Budget, RequestLedger } from '../safety/budget';

class Semaphore {
  private available: number;
  private readonly waiters: Array<() => void> = [];

  constructor(count: number) {
    this.available = count;
  }

  acquire(): Promise<void> {
    if (this.available > 0) {
      this.available -= 1;
      return Promise.resolve();
    }
    return new Promise<void>((resolve) => {
      this.waiters.push(resolve);
    });
  }

  release(): void {
    const next = this.waiters.shift();
    if (next) {
      next();
    } else {
      this.available += 1;
    }
  }
}

export type GateGrant =
  | { readonly ok: true; readonly release: () => void }
  | { readonly ok: false; readonly denied: 'budget' | 'deadline' };

export interface RequestGate {
  /** Wait for a free slot honoring concurrency + min-interval; or deny on budget/deadline exhaustion. */
  acquire(): Promise<GateGrant>;
}

export interface GateOptions {
  readonly budget: Budget;
  readonly ledger: RequestLedger;
  readonly signal?: AbortSignal;
  /** Injectable clock for deterministic tests. */
  readonly now?: () => number;
  /** Injectable sleep for deterministic tests. */
  readonly sleep?: (ms: number) => Promise<void>;
}

const realSleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

export function createRequestGate(opts: GateOptions): RequestGate {
  const { budget, ledger, signal } = opts;
  const now = opts.now ?? Date.now;
  const sleep = opts.sleep ?? realSleep;
  const semaphore = new Semaphore(budget.concurrency);
  let lastStart = Number.NEGATIVE_INFINITY;
  let intervalChain: Promise<void> = Promise.resolve();

  return {
    async acquire(): Promise<GateGrant> {
      if (signal?.aborted === true || ledger.deadlineExceeded()) {
        return { ok: false, denied: 'deadline' };
      }
      if (!ledger.tryReserve()) {
        return { ok: false, denied: 'budget' };
      }
      await semaphore.acquire();
      // Serialize the min-interval spacing across concurrent acquirers so starts stay ≥ minIntervalMs apart.
      const spaced = intervalChain.then(async () => {
        const gap = budget.minIntervalMs - (now() - lastStart);
        if (gap > 0) {
          await sleep(gap);
        }
        lastStart = now();
      });
      intervalChain = spaced.catch(() => undefined);
      await spaced;
      let released = false;
      return {
        ok: true,
        release: (): void => {
          if (!released) {
            released = true;
            semaphore.release();
          }
        },
      };
    },
  };
}
