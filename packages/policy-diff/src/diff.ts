/**
 * Semantic access diff between two Supabase RLS models — the answer to the one question a migration
 * PR review actually asks: **did this change widen who can read or write what?**
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
  PolicyCommand,
  PolicyInfo,
  PolicySchema,
  PredicateClass,
  RlsModel,
  SqlLocation,
  UninterpretedStatement,
} from '@aegiskit/scanner';
import { customCallsIn } from '@aegiskit/scanner';

export type DeltaKind = 'widening' | 'narrowing' | 'neutral' | 'requires-review';

/** `high`: anon-reachable or all-rows exposure or an RLS/parse blind spot. `notice`: everything else. */
export type DeltaSeverity = 'high' | 'notice';

/** The concrete commands a policy's `all` expands to. */
const COMMANDS: readonly Exclude<PolicyCommand, 'all'>[] = ['select', 'insert', 'update', 'delete'];
type ConcreteCommand = (typeof COMMANDS)[number];

export interface PolicySummary {
  readonly name: string;
  readonly command: PolicyCommand;
  readonly roles: readonly string[];
  readonly restrictive: boolean;
  readonly usingClass: PredicateClass;
  readonly checkClass: PredicateClass;
  readonly usingExpr?: string;
  readonly checkExpr?: string;
}

/** One (role, command) access transition inside a policy change — the evidence behind the verdict. */
export interface AccessTransition {
  readonly role: string;
  readonly command: ConcreteCommand;
  readonly before: Breadth;
  readonly after: Breadth;
  readonly kind: DeltaKind;
  readonly severity: DeltaSeverity;
}

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

// ── Breadth: what rows a ROLE can touch under a predicate class ───────────────────────────────────

/**
 * Row-breadth of a predicate class as seen by one role. `unverifiable` poisons any comparison into
 * `requires-review`. The subset lattice used for verdicts: none ⊂ {own, state, delegated} ⊂ all —
 * own/state/delegated are pairwise INCOMPARABLE (an org-membership check is neither wider nor
 * narrower than an owner binding), which is exactly where fail-safe review lives.
 */
export type Breadth = 'none' | 'own' | 'state' | 'delegated' | 'all' | 'unverifiable';

const isAnonLike = (role: string): boolean => role === 'anon' || role === 'public';

function breadthOf(cls: PredicateClass, role: string, trusted: boolean): Breadth {
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
function isSubset(a: Breadth, b: Breadth): boolean {
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

// ── Policy → per-command governing classes ────────────────────────────────────────────────────────

/** Does `policy` cover concrete command `c`? */
function covers(policy: PolicySummary, c: ConcreteCommand): boolean {
  return policy.command === 'all' || policy.command === c;
}

/**
 * The predicate class governing command `c`. INSERT is governed by WITH CHECK (falling back to
 * USING inside a FOR ALL policy — PostgreSQL reuses USING as the check when WITH CHECK is omitted);
 * everything else by USING with WITH CHECK as the fallback. Mirrors the scanner's
 * `effectivePolicyClass`, extended to per-command evaluation of `FOR ALL` policies.
 */
function governingClass(policy: PolicySummary, c: ConcreteCommand): PredicateClass {
  if (c === 'insert') {
    return policy.checkClass !== 'absent' ? policy.checkClass : policy.usingClass;
  }
  return policy.usingClass !== 'absent' ? policy.usingClass : policy.checkClass;
}

/** The WRITE-side (post-image) class for a write command — the SEC-01 second gate. */
function writeCheckClass(policy: PolicySummary, c: ConcreteCommand): PredicateClass | undefined {
  if (c === 'select' || c === 'insert') {
    return undefined; // insert's check IS its governing class; select has no post-image
  }
  return policy.checkClass !== 'absent' ? policy.checkClass : policy.usingClass;
}

/** Roles a policy applies to; an empty `TO` list means PostgreSQL's `public` (everyone). */
function rolesOf(policy: PolicySummary): readonly string[] {
  return policy.roles.length === 0 ? ['public'] : policy.roles;
}

/**
 * The role PERSPECTIVES to evaluate a policy under. `public` means EVERYONE, so it must be judged
 * from both the anonymous and the authenticated viewpoint — evaluating it only as "anon-like" made
 * an owner-bound→authenticated-only widening invisible (both classes are `none` for anon).
 */
function evaluationRoles(policy: PolicySummary): readonly string[] {
  const out = new Set<string>();
  for (const role of rolesOf(policy)) {
    if (role === 'public') {
      out.add('anon');
      out.add('authenticated');
    } else {
      out.add(role);
    }
  }
  return [...out];
}

/** Does the policy apply to a caller holding `role`? A `public` policy applies to every role. */
function appliesTo(policy: PolicySummary, role: string): boolean {
  const roles = rolesOf(policy);
  return roles.includes(role) || roles.includes('public');
}

const normalizeExpr = (expr: string | undefined): string =>
  (expr ?? '').replace(/\s+/g, ' ').trim().toLowerCase();

// ── Trust ─────────────────────────────────────────────────────────────────────────────────────────

function makeTrust(options?: DiffOptions): (expr: string | undefined) => boolean {
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

// ── Transition classification ─────────────────────────────────────────────────────────────────────

interface Verdict {
  readonly kind: DeltaKind;
  readonly severity: DeltaSeverity;
}

function classifyTransition(
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
const KIND_RANK: Record<DeltaKind, number> = {
  'requires-review': 3,
  widening: 2,
  narrowing: 1,
  neutral: 0,
};

function worst(verdicts: readonly Verdict[]): Verdict {
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

// ── Fingerprint (identity, not security) ──────────────────────────────────────────────────────────

/** FNV-1a 64-bit over the delta's stable identity — dedup/stickiness only, not a security primitive. */
function fingerprint(parts: readonly (string | number)[]): string {
  let h = 0xcbf29ce484222325n;
  const prime = 0x100000001b3n;
  const s = parts.join('\x00');
  for (let i = 0; i < s.length; i += 1) {
    h ^= BigInt(s.charCodeAt(i));
    h = (h * prime) & 0xffffffffffffffffn;
  }
  return h.toString(16).padStart(16, '0');
}

// ── Policy comparison ─────────────────────────────────────────────────────────────────────────────

function toSummary(p: PolicyInfo): PolicySummary {
  return {
    name: p.name,
    command: p.command,
    roles: p.roles,
    restrictive: p.restrictive,
    usingClass: p.usingClass,
    checkClass: p.checkClass,
    ...(p.usingExpr !== undefined ? { usingExpr: p.usingExpr } : {}),
    ...(p.checkExpr !== undefined ? { checkExpr: p.checkExpr } : {}),
  };
}

const policyIdentity = (p: PolicyInfo): string => `${p.schema}\x00${p.table}\x00${p.name}`;

function samePolicy(a: PolicySummary, b: PolicySummary): boolean {
  return (
    a.command === b.command &&
    a.restrictive === b.restrictive &&
    [...rolesOf(a)].sort().join(',') === [...rolesOf(b)].sort().join(',') &&
    a.usingClass === b.usingClass &&
    a.checkClass === b.checkClass &&
    normalizeExpr(a.usingExpr) === normalizeExpr(b.usingExpr) &&
    normalizeExpr(a.checkExpr) === normalizeExpr(b.checkExpr)
  );
}

/**
 * All (role, command) transitions between two states of one policy. `undefined` on either side
 * means the policy does not exist there — which uniformly folds adds, removes, role changes, and
 * command changes into breadth transitions from/to `none`.
 */
function policyTransitions(
  before: PolicySummary | undefined,
  after: PolicySummary | undefined,
  trust: (expr: string | undefined) => boolean,
): AccessTransition[] {
  const roles = new Set<string>([
    ...(before ? evaluationRoles(before) : []),
    ...(after ? evaluationRoles(after) : []),
  ]);
  const transitions: AccessTransition[] = [];
  for (const role of roles) {
    for (const command of COMMANDS) {
      const evaluate = (p: PolicySummary | undefined): { breadth: Breadth; expr: string } => {
        if (!p || !covers(p, command) || !appliesTo(p, role)) {
          return { breadth: 'none', expr: '' };
        }
        const gate = governingClass(p, command);
        const gateExpr = command === 'insert' ? (p.checkExpr ?? p.usingExpr) : p.usingExpr;
        const gateBreadth = breadthOf(gate, role, trust(gateExpr));
        // SEC-01: a write command is as wide as the WIDER of its row gate and its post-image check —
        // `USING (owner) WITH CHECK (authenticated-only)` still lets any user write foreign rows.
        const check = writeCheckClass(p, command);
        if (check !== undefined) {
          const checkBreadth = breadthOf(check, role, trust(p.checkExpr ?? p.usingExpr));
          const wider =
            isSubset(gateBreadth, checkBreadth) || checkBreadth === 'unverifiable'
              ? checkBreadth
              : gateBreadth;
          return {
            breadth: wider,
            expr: `${normalizeExpr(gateExpr)}|${normalizeExpr(p.checkExpr ?? p.usingExpr)}`,
          };
        }
        return { breadth: gateBreadth, expr: normalizeExpr(gateExpr) };
      };
      const b = evaluate(before);
      const a = evaluate(after);
      if (b.breadth === 'none' && a.breadth === 'none') {
        continue;
      }
      const verdict = classifyTransition(role, b.breadth, a.breadth, b.expr !== a.expr);
      if (verdict.kind === 'neutral') {
        continue;
      }
      transitions.push({
        role,
        command,
        before: b.breadth,
        after: a.breadth,
        kind: verdict.kind,
        severity: verdict.severity,
      });
    }
  }
  return transitions;
}

// ── Summaries (the human sentences) ───────────────────────────────────────────────────────────────

const BREADTH_LABEL: Record<Breadth, string> = {
  none: 'no rows',
  own: 'only rows they own',
  state: 'rows matching a row-state condition',
  delegated: 'rows allowed by a delegated check',
  all: 'ALL rows',
  unverifiable: 'rows decided by an unverifiable predicate',
};

function describeTransitions(
  table: string,
  transitions: readonly AccessTransition[],
  fallback: string,
): string {
  const dominant = [...transitions].sort(
    (a, b) =>
      KIND_RANK[b.kind] - KIND_RANK[a.kind] ||
      (b.severity === 'high' ? 1 : 0) - (a.severity === 'high' ? 1 : 0) ||
      // Total-order tie-break so the human summary is reproducible regardless of the role-set
      // construction order (the leading role/command must not vary across equivalent inputs).
      a.command.localeCompare(b.command) ||
      a.role.localeCompare(b.role),
  )[0];
  if (!dominant) {
    return fallback;
  }
  const peers = transitions.filter(
    (t) => t.kind === dominant.kind && t.before === dominant.before && t.after === dominant.after,
  );
  const commands = [...new Set(peers.map((t) => t.command.toUpperCase()))].join('/');
  const roles = [...new Set(peers.map((t) => t.role))].join(', ');
  const rest = transitions.length - peers.length;
  const tail = rest > 0 ? ` (+${rest} more transition${rest === 1 ? '' : 's'})` : '';
  if (dominant.kind === 'requires-review') {
    return `${commands} for role ${roles} on "${table}" moved from ${BREADTH_LABEL[dominant.before]} to ${BREADTH_LABEL[dominant.after]} — not mechanically comparable, review required${tail}`;
  }
  return `role ${roles} could previously ${commands} ${BREADTH_LABEL[dominant.before]} on "${table}"; after this change: ${BREADTH_LABEL[dominant.after]}${tail}`;
}

// ── The diff ──────────────────────────────────────────────────────────────────────────────────────

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
    const [kind = '', table = ''] = key.split('\x00');
    const statementKind = kind as UninterpretedStatement['kind'];
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

function qualifiedTable(schema: string, table: string): string {
  return schema === 'public' ? table : `${schema}.${table}`;
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
