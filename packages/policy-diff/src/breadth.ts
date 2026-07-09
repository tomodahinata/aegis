/**
 * Row-breadth lattice — the algebra every access verdict rests on. `breadthOf` maps a predicate
 * class, as seen by ONE role, to the set of rows that role can touch; `isSubset` is the
 * strict-or-equal order over those sets. Pure and dependency-free (only the scanner's
 * `PredicateClass` vocabulary), so it is unit-testable in isolation.
 */

import type { PredicateClass } from '@aegiskit/scanner';

/**
 * Row-breadth of a predicate class as seen by one role. `unverifiable` poisons any comparison into
 * `requires-review`. The subset lattice used for verdicts: none ⊂ {own, state, delegated} ⊂ all —
 * own/state/delegated are pairwise INCOMPARABLE (an org-membership check is neither wider nor
 * narrower than an owner binding), which is exactly where fail-safe review lives.
 */
export type Breadth = 'none' | 'own' | 'state' | 'delegated' | 'all' | 'unverifiable';

/** `anon`/`public` callers hold no session — owner/role/session predicates evaluate to no rows. */
export const isAnonLike = (role: string): boolean => role === 'anon' || role === 'public';

export function breadthOf(cls: PredicateClass, role: string, trusted: boolean): Breadth {
  if (isAnonLike(role)) {
    // An anonymous caller has no session: owner bindings, session proofs, and role gates all
    // evaluate to no rows. Row-state predicates and `true` are the anon-satisfiable classes.
    switch (cls) {
      case 'unconditional':
        return 'all';
      case 'unknown':
        return 'state';
      case 'function-delegated':
        // Even a TRUSTED helper is only vouched as "a correct authorization check" — for anon we
        // assume it denies (like role-delegated); untrusted stays unverifiable.
        return trusted ? 'none' : 'unverifiable';
      case 'absent':
        return 'unverifiable';
      default:
        return 'none'; // deny / owner-bound / authenticated-only / role-delegated
    }
  }
  switch (cls) {
    case 'deny':
      return 'none';
    case 'owner-bound':
      return 'own';
    case 'unknown':
      return 'state';
    case 'role-delegated':
      return 'delegated';
    case 'function-delegated':
      return trusted ? 'delegated' : 'unverifiable';
    case 'authenticated-only':
      return 'all'; // every logged-in user: for an authenticated role this IS all rows
    case 'unconditional':
      return 'all';
    case 'absent':
      return 'unverifiable';
    default: {
      const exhaustive: never = cls;
      return exhaustive;
    }
  }
}

/** Strictly-below relation of the subset lattice (none ⊂ mid ⊂ all; mids incomparable). */
export function isSubset(a: Breadth, b: Breadth): boolean {
  if (a === b) {
    return true;
  }
  if (a === 'none') {
    return true;
  }
  if (b === 'all') {
    return a === 'own' || a === 'state' || a === 'delegated';
  }
  return false;
}

/** Human labels for each breadth, embedded verbatim in the summary sentences. */
export const BREADTH_LABEL: Record<Breadth, string> = {
  none: 'no rows',
  own: 'only rows they own',
  state: 'rows matching a row-state condition',
  delegated: 'rows allowed by a delegated check',
  all: 'ALL rows',
  unverifiable: 'rows decided by an unverifiable predicate',
};
