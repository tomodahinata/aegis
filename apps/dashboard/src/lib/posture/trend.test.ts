import type { PostureBucket } from '@aegiskit/observability';
import { describe, expect, it } from 'vitest';
import { summarizeTrend } from './trend';

const bucket = (start: number, weightedVolume: number): PostureBucket =>
  ({ start, weightedVolume }) as PostureBucket;

describe('summarizeTrend', () => {
  it('reports "improving" when the recent half has fewer weighted events', () => {
    const t = summarizeTrend([bucket(0, 10), bucket(1, 8), bucket(2, 2), bucket(3, 1)]);
    expect(t.direction).toBe('improving');
    expect(t.delta).toBeLessThan(0);
  });

  it('reports "worsening" when the recent half has more weighted events', () => {
    const t = summarizeTrend([bucket(0, 1), bucket(1, 2), bucket(2, 8), bucket(3, 10)]);
    expect(t.direction).toBe('worsening');
    expect(t.delta).toBeGreaterThan(0);
  });

  it('reports "steady" when both halves are equal', () => {
    expect(summarizeTrend([bucket(0, 5), bucket(1, 5)]).direction).toBe('steady');
  });

  it('reports "steady" for flat non-zero data with an odd bucket count (no sign bias)', () => {
    const t = summarizeTrend([bucket(0, 7), bucket(1, 7), bucket(2, 7)]);
    expect(t.direction).toBe('steady');
    expect(t.delta).toBe(0);
  });

  it('handles too-little data without throwing', () => {
    expect(summarizeTrend([]).direction).toBe('steady');
    expect(summarizeTrend([bucket(0, 3)]).direction).toBe('steady');
  });
});
