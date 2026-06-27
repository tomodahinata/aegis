import { describe, expect, it } from 'vitest';
import { percent, relativeTime } from './format';

describe('relativeTime', () => {
  it('formats seconds/minutes/hours/days and clamps the future', () => {
    const now = 1_000_000_000;
    expect(relativeTime(now - 5_000, now)).toBe('5s ago');
    expect(relativeTime(now - 120_000, now)).toBe('2m ago');
    expect(relativeTime(now - 3 * 3_600_000, now)).toBe('3h ago');
    expect(relativeTime(now + 5_000, now)).toBe('0s ago');
  });
});

describe('percent', () => {
  it('rounds a fraction to a percentage', () => {
    expect(percent(0.5)).toBe('50%');
    expect(percent(0)).toBe('0%');
    expect(percent(2 / 3)).toBe('67%');
  });
});
