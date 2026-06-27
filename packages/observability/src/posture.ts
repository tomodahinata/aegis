import type { PostureSummary } from './store';

export type Grade = 'A' | 'B' | 'C' | 'D' | 'F';

export interface PostureScore {
  /** 0..100, higher = healthier. */
  readonly score: number;
  readonly grade: Grade;
  readonly factors: {
    /** Recency-decayed, severity-weighted event volume (the penalty input). */
    readonly weightedVolume: number;
    /** Echoed from the summary for display (not part of the score — see note below). */
    readonly blockRate: number;
    /** Points deducted (0..100). */
    readonly penalty: number;
  };
}

// Knee of the saturating penalty curve: where weightedVolume costs ~half the max penalty.
const KNEE = 50;
// Per-bucket recency decay: the most recent bucket counts fully, older buckets fade.
const DECAY = 0.9;

function gradeFor(score: number): Grade {
  if (score >= 90) return 'A';
  if (score >= 75) return 'B';
  if (score >= 60) return 'C';
  if (score >= 40) return 'D';
  return 'F';
}

/**
 * Deterministic posture score. Penalty is a *saturating* function of the recency-decayed,
 * severity-weighted event volume — so it is **monotonic** (adding any event never raises the
 * score), bounded to [0,100], and recovers over time as recent buckets empty.
 *
 * Note: `blockRate` is intentionally NOT a term in the score. A rate (blocks ÷ total) *falls*
 * when benign events are added, which would let an attacker *raise* a victim's score by
 * flooding low-severity `csp_violation`s — breaking monotonicity. Blocking severity is already
 * captured by the weights (origin/csrf = high). `blockRate` is surfaced for display only.
 */
export function computePostureScore(summary: PostureSummary): PostureScore {
  const n = summary.buckets.length;
  let weightedVolume = 0;
  for (let i = 0; i < n; i++) {
    const bucket = summary.buckets[i];
    if (bucket) {
      weightedVolume += bucket.weightedVolume * DECAY ** (n - 1 - i);
    }
  }
  const penalty = 100 * (weightedVolume / (weightedVolume + KNEE));
  const score = Math.round(100 - penalty);
  return {
    score,
    grade: gradeFor(score),
    factors: { weightedVolume, blockRate: summary.blockRate, penalty },
  };
}
