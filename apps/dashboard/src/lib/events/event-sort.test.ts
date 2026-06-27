import { describe, expect, it } from 'vitest';
// Relative imports only: this runs under the root Node vitest project, which has no `@` alias.
import { mkEvent } from '../../test-utils/events';
import { bySeverityThenRecent, resolveSort } from './event-sort';

describe('resolveSort', () => {
  it('accepts the known sort modes', () => {
    expect(resolveSort('severity')).toBe('severity');
    expect(resolveSort('recent')).toBe('recent');
  });

  it('fails closed to "recent" for undefined, empty, and unknown values', () => {
    expect(resolveSort(undefined)).toBe('recent');
    expect(resolveSort('')).toBe('recent');
    expect(resolveSort('../../etc/passwd')).toBe('recent');
    expect(resolveSort('newest')).toBe('recent');
  });

  it('is case-sensitive (only exact lowercase literals match)', () => {
    expect(resolveSort('Severity')).toBe('recent');
    expect(resolveSort('RECENT')).toBe('recent');
  });
});

describe('bySeverityThenRecent', () => {
  it('orders a higher-severity event type before a lower one', () => {
    // origin_block -> 'high' (rank 0); validation_error -> 'low' (rank 2).
    const high = mkEvent('origin_block', 1);
    const low = mkEvent('validation_error', 1);
    expect(bySeverityThenRecent(high, low)).toBeLessThan(0);
    expect(bySeverityThenRecent(low, high)).toBeGreaterThan(0);
  });

  it('breaks a severity tie by newest receivedAt first', () => {
    // Both high severity -> rank tie; the more recent receivedAt must come first.
    const newer = mkEvent('origin_block', 200);
    const older = mkEvent('csrf_block', 100);
    expect(bySeverityThenRecent(newer, older)).toBeLessThan(0);
    expect(bySeverityThenRecent(older, newer)).toBeGreaterThan(0);
  });

  it('sorts most-severe-then-newest without mutating the input array', () => {
    const events = [
      mkEvent('validation_error', 300, 'low-newest'),
      mkEvent('origin_block', 100, 'high-old'),
      mkEvent('origin_block', 200, 'high-new'),
    ];
    const snapshot = events.map((e) => e.id);

    const sorted = [...events].sort(bySeverityThenRecent);

    expect(sorted.map((e) => e.id)).toEqual(['high-new', 'high-old', 'low-newest']);
    expect(events.map((e) => e.id)).toEqual(snapshot);
  });
});
