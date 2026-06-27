import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { createLedger, DEFAULT_BUDGET, resolveBudget } from './budget';

describe('createLedger', () => {
  it('caps reservations at maxRequests', () => {
    const ledger = createLedger({ ...DEFAULT_BUDGET, maxRequests: 3 });
    expect([
      ledger.tryReserve(),
      ledger.tryReserve(),
      ledger.tryReserve(),
      ledger.tryReserve(),
    ]).toEqual([true, true, true, false]);
    expect(ledger.sent).toBe(3);
  });

  it('reports the deadline once the clock passes it', () => {
    let now = 0;
    const ledger = createLedger({ ...DEFAULT_BUDGET, deadlineMs: 100 }, () => now);
    expect(ledger.deadlineExceeded()).toBe(false);
    now = 150;
    expect(ledger.deadlineExceeded()).toBe(true);
  });

  it('property: never reserves more than maxRequests for any number of attempts', () => {
    fc.assert(
      fc.property(fc.nat({ max: 80 }), fc.integer({ min: 1, max: 25 }), (attempts, cap) => {
        const ledger = createLedger({ ...DEFAULT_BUDGET, maxRequests: cap });
        let granted = 0;
        for (let i = 0; i < attempts; i += 1) {
          if (ledger.tryReserve()) {
            granted += 1;
          }
        }
        expect(ledger.sent).toBeLessThanOrEqual(cap);
        expect(granted).toBe(Math.min(attempts, cap));
      }),
      { numRuns: 50 },
    );
  });
});

describe('resolveBudget', () => {
  it('clamps out-of-range values into a safe band', () => {
    expect(resolveBudget({ maxRequests: -5, concurrency: 1000 })).toMatchObject({
      maxRequests: 1,
      concurrency: 32,
    });
  });

  it('falls back to defaults for omitted fields', () => {
    expect(resolveBudget()).toEqual(DEFAULT_BUDGET);
  });
});
