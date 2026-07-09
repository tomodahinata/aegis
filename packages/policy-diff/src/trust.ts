/**
 * Trusted-function resolution. A `function-delegated` predicate whose EVERY custom call is on the
 * team's allowlist participates in the lattice as a delegated check instead of forcing review;
 * anything unanalyzable (or off the list) stays untrusted — fail secure.
 */

import { customCallsIn } from '@aegiskit/scanner';

export interface DiffOptions {
  /**
   * Function names (normalized: lowercased, optionally schema-qualified as written in SQL) the team
   * vouches for as correct authorization checks — e.g. `['public.is_member', 'is_org_admin']`. A
   * `function-delegated` predicate whose EVERY custom call is trusted participates in the lattice as
   * a delegated check instead of forcing `requires-review`. Unknown or unanalyzable calls stay
   * untrusted (fail secure).
   */
  readonly trustedFunctions?: readonly string[];
}

/** Predicate-text → "every custom call in it is vouched for". Pure; safe to memoize per diff. */
export type Trust = (expr: string | undefined) => boolean;

export function makeTrust(options?: DiffOptions): Trust {
  const allow = new Set((options?.trustedFunctions ?? []).map((f) => f.toLowerCase()));
  if (allow.size === 0) {
    return () => false;
  }
  return (expr) => {
    const calls = customCallsIn(expr);
    if (calls === undefined) {
      return false; // unanalyzable ⇒ untrusted (fail secure)
    }
    return (
      calls.length > 0 &&
      calls.every((name) => allow.has(name) || allow.has(name.replace(/^public\./, '')))
    );
  };
}
