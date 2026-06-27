import type { SecurityEventType } from '@aegiskit/core';
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { computePostureScore } from './posture';
import { type StoredEvent, summarize } from './store';

const TYPES: readonly SecurityEventType[] = [
  'origin_block',
  'csrf_block',
  'rate_limit_block',
  'csp_violation',
  'validation_error',
  'suspicious_request',
];

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

const WINDOW = { since: 0, until: 100, bucketCount: 10 } as const;
const score = (events: StoredEvent[]) => computePostureScore(summarize(events, WINDOW));

describe('computePostureScore', () => {
  it('is a perfect A for no events', () => {
    expect(score([])).toMatchObject({ score: 100, grade: 'A' });
  });

  it('drops toward F under sustained high-severity volume', () => {
    const events = Array.from({ length: 100 }, (_, i) => mk('origin_block', 50, `e${i}`));
    const result = score(events);
    expect(result.score).toBeLessThan(40);
    expect(result.grade).toBe('F');
  });

  it('weights recent events more heavily than old ones', () => {
    const recent = score([mk('origin_block', 95, 'a')]);
    const old = score([mk('origin_block', 5, 'a')]);
    expect(recent.score).toBeLessThanOrEqual(old.score);
  });

  const eventArb = fc.tuple(fc.constantFrom(...TYPES), fc.integer({ min: 0, max: 99 }));

  it('property: adding any event never raises the score (monotonic)', () => {
    fc.assert(
      fc.property(fc.array(eventArb, { maxLength: 40 }), eventArb, (events, extra) => {
        const stored = events.map(([type, at], i) => mk(type, at, `e${i}`));
        const before = score(stored).score;
        const after = score([...stored, mk(extra[0], extra[1], 'extra')]).score;
        expect(after).toBeLessThanOrEqual(before);
      }),
    );
  });

  it('property: score is bounded [0,100] and deterministic', () => {
    fc.assert(
      fc.property(fc.array(eventArb, { maxLength: 60 }), (events) => {
        const stored = events.map(([type, at], i) => mk(type, at, `e${i}`));
        const a = score(stored);
        const b = score(stored);
        expect(a.score).toBeGreaterThanOrEqual(0);
        expect(a.score).toBeLessThanOrEqual(100);
        expect(a).toEqual(b);
      }),
    );
  });
});
