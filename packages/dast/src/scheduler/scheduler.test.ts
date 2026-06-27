import { describe, expect, it } from 'vitest';
import { createLedger, DEFAULT_BUDGET } from '../safety/budget';
import { createRequestGate } from './scheduler';

const fast = { ...DEFAULT_BUDGET, minIntervalMs: 0 };

describe('createRequestGate', () => {
  it('denies acquisition once the request budget is exhausted', async () => {
    const budget = { ...fast, maxRequests: 2, concurrency: 10 };
    const ledger = createLedger(budget);
    const gate = createRequestGate({ budget, ledger });
    const a = await gate.acquire();
    const b = await gate.acquire();
    const c = await gate.acquire();
    expect(a.ok && b.ok).toBe(true);
    expect(c).toEqual({ ok: false, denied: 'budget' });
  });

  it('denies acquisition once the deadline has passed', async () => {
    let now = 0;
    const budget = { ...fast, deadlineMs: 100 };
    const ledger = createLedger(budget, () => now); // captures startedAt = 0
    now = 200; // clock advances past the deadline
    const gate = createRequestGate({ budget, ledger, now: () => now });
    expect(await gate.acquire()).toEqual({ ok: false, denied: 'deadline' });
  });

  it('never exceeds the concurrency cap', async () => {
    const budget = { ...fast, concurrency: 2, maxRequests: 100 };
    const ledger = createLedger(budget);
    const gate = createRequestGate({ budget, ledger });
    let active = 0;
    let peak = 0;
    await Promise.all(
      Array.from({ length: 6 }, async () => {
        const grant = await gate.acquire();
        if (!grant.ok) {
          return;
        }
        active += 1;
        peak = Math.max(peak, active);
        await new Promise((resolve) => setTimeout(resolve, 10));
        active -= 1;
        grant.release();
      }),
    );
    expect(peak).toBeLessThanOrEqual(2);
  });
});
