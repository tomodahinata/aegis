/**
 * Transition classification — given a role's before/after breadth (and whether the predicate text
 * changed), decide widening / narrowing / neutral / requires-review, and aggregate many transitions
 * into one policy-level verdict. Fail-safe: incomparable or unverifiable moves are always review.
 */

import { type Breadth, isAnonLike, isSubset } from './breadth';

export type DeltaKind = 'widening' | 'narrowing' | 'neutral' | 'requires-review';

/** `high`: anon-reachable or all-rows exposure or an RLS/parse blind spot. `notice`: everything else. */
export type DeltaSeverity = 'high' | 'notice';

export interface Verdict {
  readonly kind: DeltaKind;
  readonly severity: DeltaSeverity;
}

export function classifyTransition(
  role: string,
  before: Breadth,
  after: Breadth,
  exprChanged: boolean,
): Verdict {
  if (before === 'unverifiable' || after === 'unverifiable') {
    return { kind: 'requires-review', severity: isAnonLike(role) ? 'high' : 'notice' };
  }
  if (before === after) {
    // Same breadth but a different predicate (e.g. `is_admin()` → `is_member()`, or the ownership
    // column changed): the shape says "comparable", the text says "semantics moved" — review it.
    if (exprChanged && (before === 'own' || before === 'state' || before === 'delegated')) {
      return { kind: 'requires-review', severity: 'notice' };
    }
    return { kind: 'neutral', severity: 'notice' };
  }
  if (isSubset(before, after)) {
    const anonGain = isAnonLike(role) && after !== 'none';
    const high = after === 'all' || anonGain;
    return { kind: 'widening', severity: high ? 'high' : 'notice' };
  }
  if (isSubset(after, before)) {
    return { kind: 'narrowing', severity: 'notice' };
  }
  return { kind: 'requires-review', severity: 'notice' }; // incomparable (own↔state↔delegated)
}

/** Verdict dominance for aggregating transitions into one policy-level verdict. */
export const KIND_RANK: Record<DeltaKind, number> = {
  'requires-review': 3,
  widening: 2,
  narrowing: 1,
  neutral: 0,
};

export function worst(verdicts: readonly Verdict[]): Verdict {
  let kind: DeltaKind = 'neutral';
  let severity: DeltaSeverity = 'notice';
  for (const v of verdicts) {
    if (KIND_RANK[v.kind] > KIND_RANK[kind]) {
      kind = v.kind;
    }
    if (v.severity === 'high' && (v.kind === 'widening' || v.kind === 'requires-review')) {
      severity = 'high';
    }
  }
  return { kind, severity };
}
