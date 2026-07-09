/**
 * Policy modeling and per-(role, command) transition extraction — turns two states of one policy
 * into the breadth transitions that drive its verdict, plus the human sentence describing them.
 */

import type { PolicyCommand, PolicyInfo, PredicateClass } from '@aegiskit/scanner';
import { BREADTH_LABEL, type Breadth, breadthOf, isSubset } from './breadth';
import { classifyTransition, type DeltaKind, type DeltaSeverity, KIND_RANK } from './classify';
import type { Trust } from './trust';

/** The concrete commands a policy's `all` expands to. */
export const COMMANDS: readonly Exclude<PolicyCommand, 'all'>[] = [
  'select',
  'insert',
  'update',
  'delete',
];
export type ConcreteCommand = (typeof COMMANDS)[number];

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

export function toSummary(p: PolicyInfo): PolicySummary {
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

export const policyIdentity = (p: PolicyInfo): string => `${p.schema}\x00${p.table}\x00${p.name}`;

export function samePolicy(a: PolicySummary, b: PolicySummary): boolean {
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
export function policyTransitions(
  before: PolicySummary | undefined,
  after: PolicySummary | undefined,
  trust: Trust,
): AccessTransition[] {
  // `trust()` re-masks and regex-scans its argument; its result depends only on the predicate text,
  // not on the role/command it is evaluated for. Memoize per call so each distinct predicate is
  // analyzed once instead of O(roles × commands) times.
  const trustCache = new Map<string, boolean>();
  const trustMemo = (expr: string | undefined): boolean => {
    const key = expr ?? '';
    const cached = trustCache.get(key);
    if (cached !== undefined) {
      return cached;
    }
    const value = trust(expr);
    trustCache.set(key, value);
    return value;
  };

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
        const gateBreadth = breadthOf(gate, role, trustMemo(gateExpr));
        // SEC-01: a write command is as wide as the WIDER of its row gate and its post-image check —
        // `USING (owner) WITH CHECK (authenticated-only)` still lets any user write foreign rows.
        const check = writeCheckClass(p, command);
        if (check !== undefined) {
          const checkBreadth = breadthOf(check, role, trustMemo(p.checkExpr ?? p.usingExpr));
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

export function describeTransitions(
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

/** `public` tables render bare; other schemas keep their qualifier (e.g. `storage.objects`). */
export function qualifiedTable(schema: string, table: string): string {
  return schema === 'public' ? table : `${schema}.${table}`;
}
