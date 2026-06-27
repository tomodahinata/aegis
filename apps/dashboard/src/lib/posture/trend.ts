import type { PostureBucket } from '@aegiskit/observability';

export type TrendDirection = 'improving' | 'worsening' | 'steady';

export interface TrendSummary {
  readonly direction: TrendDirection;
  /** A short human verdict, e.g. "improving — fewer weighted events than earlier". */
  readonly label: string;
  /** recent-half weighted volume minus earlier-half (negative ⇒ improving = fewer events). */
  readonly delta: number;
}

/**
 * Compare the recent half of the window to the earlier half by severity-weighted volume — fewer weighted
 * events recently means improving. Pure and deterministic, so the trend can be conveyed in WORDS (not by
 * the sparkline's shape/color alone, WCAG 1.4.1).
 */
export function summarizeTrend(buckets: readonly PostureBucket[]): TrendSummary {
  if (buckets.length < 2) {
    return { direction: 'steady', label: 'not enough data yet', delta: 0 };
  }
  const mid = Math.floor(buckets.length / 2);
  // Average each half rather than summing raw volume: for an odd bucket count the halves have
  // unequal sizes, and summing would bias sign(delta) toward "worsening" on flat non-zero data.
  const mean = (slice: readonly PostureBucket[]): number =>
    slice.reduce((acc, bucket) => acc + bucket.weightedVolume, 0) / slice.length;
  const delta = mean(buckets.slice(mid)) - mean(buckets.slice(0, mid));
  if (delta < 0) {
    return {
      direction: 'improving',
      label: 'improving — fewer weighted events than earlier',
      delta,
    };
  }
  if (delta > 0) {
    return {
      direction: 'worsening',
      label: 'worsening — more weighted events than earlier',
      delta,
    };
  }
  return { direction: 'steady', label: 'steady — about the same as earlier', delta };
}
