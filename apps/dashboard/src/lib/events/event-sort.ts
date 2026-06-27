import type { StoredEvent } from '@aegiskit/observability';
import { EVENT_SEVERITY } from '@aegiskit/observability';
// Relative (not `@/…`): this pure module is unit-tested under the root Node vitest project,
// which does not define the `@` path alias.
import { severityToVisual } from '../posture/grade-ui';

/** The sort modes the events view accepts, in display order. Single source of truth. */
export const SORTS = ['recent', 'severity'] as const;
export type Sort = (typeof SORTS)[number];

/**
 * Validate a raw `?sort=` query value against the literal union, failing **closed** to the safe
 * default (`'recent'`, the store's native order) for anything unrecognized — undefined, empty, or
 * garbage. Matching is case-sensitive: the values come from our own server-rendered links.
 */
export function resolveSort(raw: string | undefined): Sort {
  return SORTS.find((s) => s === raw) ?? 'recent';
}

/**
 * Order two events most-severe-first, breaking ties by newest `receivedAt` first. Severity rank is
 * the single source of truth in `severityToVisual` (high = 0); a negative result sorts `a` before
 * `b`. Pure and total, so it is safe to pass to `Array.prototype.sort`.
 */
export function bySeverityThenRecent(a: StoredEvent, b: StoredEvent): number {
  return (
    severityToVisual(EVENT_SEVERITY[a.type]).rank - severityToVisual(EVENT_SEVERITY[b.type]).rank ||
    b.receivedAt - a.receivedAt
  );
}
