/**
 * Semantic access diff between two Supabase RLS models — the answer to the one question a migration
 * PR review actually asks: **did this change widen who can read or write what?**
 *
 * This module is the ORCHESTRATOR; the load-bearing logic lives in focused, independently-testable
 * neighbours: the row-breadth lattice (`./breadth`), transition classification (`./classify`),
 * trusted-function resolution (`./trust`), and per-policy transition extraction (`./policy`).
 *
 * Trust contract (the product's whole value rests on it):
 *
 *  - `widening` is claimed only when the after-rows are a SUPERSET-or-equal of the before-rows under
 *    the class lattice (`none ⊂ own/state/delegated ⊂ all`) — never for incomparable transitions.
 *  - `narrowing` is claimed only when the after-rows are a SUBSET-or-equal — a "safe" verdict must
 *    never paper over a possible widening.
 *  - Everything unverifiable (custom functions off the allowlist, over-long predicates, incomparable
 *    class moves, statements the model recorded as `uninterpreted`) is `requires-review`. The diff
 *    FAILS CLOSED: it may ask a human to look, it must never say "no change" when it cannot know.
 *
 * Honest scope: this reasons about the SHAPE of predicates over repo-managed SQL. It does not know
 * your data model or business rules, and it never claims a migration is "safe" — a clean diff means
 * "no access-relevant change detected in the modeled surface", nothing more.
 */

import type {
  GrantInfo,
  PolicyInfo,
  PolicySchema,
  RlsModel,
  SqlLocation,
  UninterpretedStatement,
} from '@aegiskit/scanner';
import { isAnonLike } from './breadth';
import { type DeltaKind, type DeltaSeverity, worst } from './classify';
import { fingerprint } from './fingerprint';
import {
  type AccessTransition,
  describeTransitions,
  type PolicySummary,
  policyIdentity,
  policyTransitions,
  qualifiedTable,
  samePolicy,
  toSummary,
} from './policy';
import { type DiffOptions, makeTrust } from './trust';

// Re-export the public vocabulary. The split into focused modules is an internal refactor; `./diff`
// stays the single entry point the package index and the tests import from.
export type { Breadth } from './breadth';
export type { DeltaKind, DeltaSeverity } from './classify';
export type { AccessTransition, PolicySummary } from './policy';
export type { DiffOptions } from './trust';

export type DeltaChange =
  | { readonly type: 'policy-added'; readonly policy: PolicySummary }
  | { readonly type: 'policy-removed'; readonly policy: PolicySummary }
  | {
      readonly type: 'policy-changed';
      readonly before: PolicySummary;
      readonly after: PolicySummary;
    }
  | { readonly type: 'rls-disabled' }
  | { readonly type: 'rls-enabled' }
  | { readonly type: 'table-added-without-rls' }
  | { readonly type: 'table-removed' }
  | { readonly type: 'grant-added'; readonly roles: readonly string[] }
  | { readonly type: 'grant-removed'; readonly roles: readonly string[] }
  | {
      readonly type: 'uninterpreted';
      readonly statementKind: UninterpretedStatement['kind'];
      readonly count: number;
    };

export interface AccessDelta {
  readonly kind: DeltaKind;
  readonly severity: DeltaSeverity;
  readonly schema: PolicySchema;
  readonly table: string;
  readonly change: DeltaChange;
  /** One human sentence stating exactly what access changed (renderers embed these verbatim). */
  readonly summary: string;
  /** The per-(role, command) transitions behind a policy verdict (empty for table/grant deltas). */
  readonly transitions: readonly AccessTransition[];
  /** Stable identity across re-pushes/re-runs (content-derived, line-independent). */
  readonly fingerprint: string;
  /** Head-side source location when known. */
  readonly loc?: SqlLocation;
}

export interface DeltaSummary {
  readonly widening: number;
  readonly narrowing: number;
  readonly requiresReview: number;
  readonly neutral: number;
  readonly high: number;
  /**
   * `action-required`: at least one high-severity widening/review — a human must look before merge.
   * `attention`: only notice-level widenings/reviews. `neutral`: narrowings/neutral only.
   * `no-change`: empty diff.
   */
  readonly conclusion: 'action-required' | 'attention' | 'neutral' | 'no-change';
}

export function diffAccess(base: RlsModel, head: RlsModel, options?: DiffOptions): AccessDelta[] {
  const trust = makeTrust(options);
  const deltas: AccessDelta[] = [];
  const push = (
    delta: Omit<AccessDelta, 'fingerprint'>,
    fingerprintParts: readonly (string | number)[],
  ): void => {
    deltas.push({ ...delta, fingerprint: fingerprint(fingerprintParts) });
  };

  // 1. Table-level RLS state.
  for (const [name, headTable] of head.tables) {
    const baseTable = base.tables.get(name);
    if (!baseTable) {
      if (!headTable.rlsEnabled) {
        push(
          {
            kind: 'widening',
            severity: 'high',
            schema: 'public',
            table: name,
            change: { type: 'table-added-without-rls' },
            summary: `new table "${name}" ships WITHOUT Row Level Security — with the anon/authenticated key, any caller can read and write every row`,
            transitions: [],
            loc: headTable.loc,
          },
          ['table-added-without-rls', name],
        );
      }
      continue;
    }
    if (baseTable.rlsEnabled && !headTable.rlsEnabled) {
      push(
        {
          kind: 'widening',
          severity: 'high',
          schema: 'public',
          table: name,
          change: { type: 'rls-disabled' },
          summary: `Row Level Security on "${name}" was DISABLED — every policy on it stops applying; all rows become reachable through the API`,
          transitions: [],
          loc: headTable.loc,
        },
        ['rls-disabled', name],
      );
    } else if (!baseTable.rlsEnabled && headTable.rlsEnabled) {
      push(
        {
          kind: 'narrowing',
          severity: 'notice',
          schema: 'public',
          table: name,
          change: { type: 'rls-enabled' },
          summary: `Row Level Security on "${name}" was enabled — access is now scoped by its policies`,
          transitions: [],
          loc: headTable.loc,
        },
        ['rls-enabled', name],
      );
    }
  }
  for (const [name] of base.tables) {
    if (!head.tables.has(name)) {
      push(
        {
          kind: 'narrowing',
          severity: 'notice',
          schema: 'public',
          table: name,
          change: { type: 'table-removed' },
          summary: `table "${name}" was dropped`,
          transitions: [],
        },
        ['table-removed', name],
      );
    }
  }

  // 2. Policies (added / removed / changed), keyed by schema+table+name identity.
  const basePolicies = new Map(base.policies.map((p) => [policyIdentity(p), p]));
  const headPolicies = new Map(head.policies.map((p) => [policyIdentity(p), p]));
  const keys = new Set([...basePolicies.keys(), ...headPolicies.keys()]);
  for (const key of keys) {
    const before = basePolicies.get(key);
    const after = headPolicies.get(key);
    const sample = (after ?? before) as PolicyInfo;
    const { schema, table } = sample;
    if (before && after && samePolicy(toSummary(before), toSummary(after))) {
      continue;
    }

    // RESTRICTIVE policies AND-narrow; their machinery is inverse. Kept deliberately coarse.
    if ((before?.restrictive ?? false) || (after?.restrictive ?? false)) {
      if (!before && after) {
        push(
          {
            kind: 'narrowing',
            severity: 'notice',
            schema,
            table,
            change: { type: 'policy-added', policy: toSummary(after) },
            summary: `RESTRICTIVE policy "${after.name}" added on "${table}" — access is further narrowed`,
            transitions: [],
            loc: after.loc,
          },
          ['restrictive-added', schema, table, after.name],
        );
      } else if (before && !after) {
        push(
          {
            kind: 'widening',
            severity: 'high',
            schema,
            table,
            change: { type: 'policy-removed', policy: toSummary(before) },
            summary: `RESTRICTIVE policy "${before.name}" on "${table}" was removed — a deny-refinement no longer applies, access widens to whatever the permissive policies grant`,
            transitions: [],
          },
          ['restrictive-removed', schema, table, before.name],
        );
      } else if (before && after) {
        push(
          {
            kind: 'requires-review',
            severity: 'notice',
            schema,
            table,
            change: { type: 'policy-changed', before: toSummary(before), after: toSummary(after) },
            summary: `RESTRICTIVE policy "${after.name}" on "${table}" changed — AND-narrowing semantics are not mechanically comparable, review required`,
            transitions: [],
            loc: after.loc,
          },
          ['restrictive-changed', schema, table, after.name],
        );
      }
      continue;
    }

    const transitions = policyTransitions(
      before ? toSummary(before) : undefined,
      after ? toSummary(after) : undefined,
      trust,
    );
    if (transitions.length === 0) {
      continue; // e.g. only formatting changed
    }
    const verdict = worst(transitions);
    const change: DeltaChange =
      before && after
        ? { type: 'policy-changed', before: toSummary(before), after: toSummary(after) }
        : after
          ? { type: 'policy-added', policy: toSummary(after) }
          : // before is defined here: the key came from one of the two maps
            { type: 'policy-removed', policy: toSummary(before as PolicyInfo) };
    const label = `policy "${(after ?? before)?.name}"`;
    push(
      {
        kind: verdict.kind,
        severity: verdict.severity,
        schema,
        table,
        change,
        summary: `${describeTransitions(qualifiedTable(schema, table), transitions, `${label} on "${table}" changed`)} (${label}${change.type === 'policy-added' ? ', added' : change.type === 'policy-removed' ? ', removed' : ''})`,
        transitions,
        ...(after ? { loc: after.loc } : {}),
      },
      ['policy', schema, table, (after ?? before)?.name ?? '', verdict.kind],
    );
  }

  // 3. Grants (public schema; presence-level, mirroring the model).
  const grantRoles = (grants: readonly GrantInfo[]): Map<string, Set<string>> => {
    const map = new Map<string, Set<string>>();
    for (const g of grants) {
      const set = map.get(g.table) ?? new Set<string>();
      for (const role of g.roles) {
        set.add(role);
      }
      map.set(g.table, set);
    }
    return map;
  };
  const baseGrants = grantRoles(base.grants);
  const headGrants = grantRoles(head.grants);
  for (const [table, roles] of headGrants) {
    const beforeRoles = new Set(baseGrants.get(table) ?? []);
    // A schema-wide ('*') grant already exposes every table, so a role it covers is NOT "new" when it
    // later appears on an individual table — without this, a redundant per-table GRANT (already implied
    // by GRANT … ON ALL TABLES) reads as a false widening.
    if (table !== '*') {
      for (const role of baseGrants.get('*') ?? []) {
        beforeRoles.add(role);
      }
    }
    const added = [...roles].filter((r) => !beforeRoles.has(r));
    if (added.length > 0) {
      const anonAdded = added.filter(isAnonLike);
      // A schema-wide grant exposes EVERY modeled table, so it is high-severity when ANY of them lacks
      // RLS — the broadest exposure ('*') must never rank below its single-table form.
      const rlsOff =
        table === '*'
          ? [...head.tables.values()].some((t) => t.rlsEnabled === false)
          : head.tables.get(table)?.rlsEnabled === false;
      const exposure =
        rlsOff && anonAdded.length > 0
          ? table === '*'
            ? ' — one or more tables have NO RLS, so this is direct data exposure'
            : ' — the table has NO RLS, so this is direct data exposure'
          : '';
      push(
        {
          kind: 'widening',
          severity: anonAdded.length > 0 && rlsOff ? 'high' : 'notice',
          schema: 'public',
          table,
          change: { type: 'grant-added', roles: added },
          summary: `table grant to ${added.join('/')} added on ${table === '*' ? 'ALL tables in schema public' : `"${table}"`}${exposure}`,
          transitions: [],
        },
        ['grant-added', table, ...added],
      );
    }
  }
  for (const [table, roles] of baseGrants) {
    const afterRoles = headGrants.get(table) ?? new Set<string>();
    const removed = [...roles].filter((r) => !afterRoles.has(r));
    if (removed.length > 0) {
      push(
        {
          kind: 'narrowing',
          severity: 'notice',
          schema: 'public',
          table,
          change: { type: 'grant-removed', roles: removed },
          summary: `table grant to ${removed.join('/')} removed from ${table === '*' ? 'ALL tables in schema public' : `"${table}"`}`,
          transitions: [],
        },
        ['grant-removed', table, ...removed],
      );
    }
  }

  // 4. Uninterpreted statements — the fail-closed net. Anything access-relevant the model could not
  // read that is NEW in head must surface as review; silence here would be a false "no change".
  const countByKey = (list: readonly UninterpretedStatement[]): Map<string, number> => {
    const map = new Map<string, number>();
    for (const u of list) {
      const key = `${u.kind}\x00${u.table ?? ''}`;
      map.set(key, (map.get(key) ?? 0) + 1);
    }
    return map;
  };
  const baseUn = countByKey(base.uninterpreted);
  for (const [key, headCount] of countByKey(head.uninterpreted)) {
    const excess = headCount - (baseUn.get(key) ?? 0);
    if (excess <= 0) {
      continue;
    }
    // The key is `${kind}\x00${table}` — split on the FIRST NUL so a table name can never leak into
    // the statement-kind slot, and neither field relies on a masking default.
    const nul = key.indexOf('\x00');
    const statementKind = key.slice(0, nul) as UninterpretedStatement['kind'];
    const table = key.slice(nul + 1);
    const severity: DeltaSeverity =
      statementKind === 'rls-statement' || statementKind === 'policy-statement' ? 'high' : 'notice';
    push(
      {
        kind: 'requires-review',
        severity,
        schema: 'public',
        table: table || '(unknown)',
        change: { type: 'uninterpreted', statementKind, count: excess },
        summary: `${excess} new access-relevant statement${excess === 1 ? '' : 's'} (${statementKind}${table ? ` on "${table}"` : ''}) could not be interpreted — the diff cannot rule out an access change here, review the SQL directly`,
        transitions: [],
      },
      ['uninterpreted', statementKind, table, excess],
    );
  }

  return deltas;
}

export function summarizeDeltas(deltas: readonly AccessDelta[]): DeltaSummary {
  let widening = 0;
  let narrowing = 0;
  let requiresReview = 0;
  let neutral = 0;
  let high = 0;
  for (const d of deltas) {
    if (d.kind === 'widening') {
      widening += 1;
    } else if (d.kind === 'narrowing') {
      narrowing += 1;
    } else if (d.kind === 'requires-review') {
      requiresReview += 1;
    } else {
      neutral += 1;
    }
    if (d.severity === 'high' && (d.kind === 'widening' || d.kind === 'requires-review')) {
      high += 1;
    }
  }
  const conclusion: DeltaSummary['conclusion'] =
    deltas.length === 0
      ? 'no-change'
      : high > 0
        ? 'action-required'
        : widening + requiresReview > 0
          ? 'attention'
          : 'neutral';
  return { widening, narrowing, requiresReview, neutral, high, conclusion };
}
