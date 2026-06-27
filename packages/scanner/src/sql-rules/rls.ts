/**
 * Supabase RLS verification rules. Each is designed to produce ZERO findings on an exemplary, correct
 * RLS design (RLS enabled everywhere, pinned search_path, WITH CHECK on writes, no anon table grants,
 * `USING (true)` only on read-only reference data) — and to flag exactly its inverse. We deliberately
 * do NOT flag RLS-enabled-but-no-policy (deny-all is the *safe* state) nor read-only `USING (true)`
 * (reference data) — conservative toward zero false positives, with the recall trade-off documented.
 */

import { effectivePolicyClass, isAuthenticatedOnlyGap } from '../internal/sql/predicate';
import { docsUrlFor } from '../rule';
import type { SqlRule } from '../sql-rule';

const OWASP = 'A01:2021 Broken Access Control';
const isWrite = (command: string): boolean =>
  command === 'insert' || command === 'update' || command === 'delete' || command === 'all';
// `anon` and `public` are the two roles an unauthenticated visitor holds (PostgreSQL's `public` grants to
// everyone, including `anon`). A policy with no `TO` clause applies to `public` — the model represents that
// as an empty `roles` array, which callers must treat as implicit-public, not "no role".
const isAnonRole = (role: string): boolean => role === 'anon' || role === 'public';

export const tableWithoutRls: SqlRule = {
  meta: {
    id: 'rls/table-without-rls',
    title: 'Public table without Row Level Security',
    severity: 'HIGH',
    owasp: OWASP,
    docsUrl: docsUrlFor('rls/table-without-rls'),
  },
  check(ctx) {
    for (const table of ctx.model.tables.values()) {
      if (!table.rlsEnabled) {
        ctx.report({
          loc: table.loc,
          confidence: 'high',
          message: `Table "${table.name}" has no Row Level Security enabled — with the anon/authenticated Supabase key, any user can read and write every row.`,
          remediation: `Run \`ALTER TABLE public.${table.name} ENABLE ROW LEVEL SECURITY;\` and add policies scoped to the caller (e.g. auth.uid() = user_id).`,
          evidence: `table ${table.name}`,
        });
      }
    }
  },
};

export const securityDefinerSearchPath: SqlRule = {
  meta: {
    id: 'rls/security-definer-search-path',
    title: 'SECURITY DEFINER function without a pinned search_path',
    severity: 'HIGH',
    owasp: OWASP,
    docsUrl: docsUrlFor('rls/security-definer-search-path'),
  },
  check(ctx) {
    for (const fn of ctx.model.securityDefinerFunctions) {
      if (!fn.searchPathPinned) {
        ctx.report({
          loc: fn.loc,
          confidence: 'high',
          message: `SECURITY DEFINER function "${fn.name}" does not pin search_path — a caller can shadow built-in objects in their own schema and run code as the function owner (privilege escalation).`,
          remediation: `Add \`SET search_path = ''\` (or \`= public, pg_temp\`) to the function definition so name resolution can't be hijacked.`,
          evidence: `function ${fn.name}`,
        });
      }
    }
  },
};

export const writePolicyWithoutCheck: SqlRule = {
  meta: {
    id: 'rls/write-policy-without-check',
    title: 'Write policy without WITH CHECK',
    severity: 'HIGH',
    owasp: OWASP,
    docsUrl: docsUrlFor('rls/write-policy-without-check'),
  },
  check(ctx) {
    for (const policy of ctx.model.policies) {
      if (policy.restrictive) {
        continue; // RESTRICTIVE narrows access; absence of WITH CHECK is not a grant
      }
      // Only INSERT genuinely needs WITH CHECK: it has no USING clause to fall back on. For UPDATE and
      // ALL, PostgreSQL reuses the USING expression as the WITH CHECK when it is omitted, so those are
      // safe — flagging them is a false positive (this was a real bug found validating against SpoLove).
      if (policy.command === 'insert' && !policy.hasCheck) {
        ctx.report({
          loc: policy.loc,
          confidence: 'medium',
          message: `INSERT policy on "${policy.table}" has no WITH CHECK — an INSERT policy has no USING clause to fall back on, so any authenticated caller can insert rows that violate the intended ownership.`,
          remediation:
            'Add `WITH CHECK (auth.uid() = user_id)` (or the appropriate ownership predicate).',
          evidence: `${policy.table} insert without WITH CHECK`,
        });
      }
    }
  },
};

export const permissiveWritePolicy: SqlRule = {
  meta: {
    id: 'rls/permissive-write-policy',
    title: 'Write policy with an unconditional predicate',
    severity: 'MEDIUM',
    owasp: OWASP,
    docsUrl: docsUrlFor('rls/permissive-write-policy'),
  },
  check(ctx) {
    for (const policy of ctx.model.policies) {
      if (policy.restrictive) {
        continue;
      }
      if (isWrite(policy.command) && (policy.usingTrue || policy.checkTrue)) {
        ctx.report({
          loc: policy.loc,
          confidence: 'medium',
          message: `Write policy on "${policy.table}" (${policy.command.toUpperCase()}) uses an unconditional \`true\` predicate — any authenticated caller may modify any row.`,
          remediation:
            'Replace the `true` predicate with an ownership check, e.g. `USING (auth.uid() = user_id)` / `WITH CHECK (...)`.',
          evidence: `${policy.table} ${policy.command} permissive`,
        });
      }
    }
  },
};

/**
 * The moat rule: RLS that *exists* but does not *scope rows to the caller*. A PERMISSIVE policy whose
 * predicate only proves the caller is authenticated — `auth.role() = 'authenticated'`, `auth.uid() IS
 * NOT NULL` — on a table that carries an ownership column lets every logged-in user read/modify EVERY
 * row, not just their own. This is the gap Supabase's "is RLS enabled?" check and the existing rules
 * here all miss. Aegis cannot read your intent (a table may be deliberately shared), so it reports at
 * `medium` confidence — surfaced for review, never failing CI. The escape hatches (membership subquery,
 * delegated function, owner-bound predicate, no ownership column) are all handled by `classifyPredicate`
 * returning a non-`authenticated-only` class, so they never reach here.
 */
export const policyNotOwnerScoped: SqlRule = {
  meta: {
    id: 'rls/policy-not-owner-scoped',
    title: 'RLS policy authenticates the caller but does not scope rows to them',
    severity: 'HIGH',
    owasp: OWASP,
    docsUrl: docsUrlFor('rls/policy-not-owner-scoped'),
  },
  check(ctx) {
    for (const policy of ctx.model.policies) {
      if (policy.restrictive) {
        continue; // RESTRICTIVE narrows access; it never grants it, so it is never the gap
      }
      if (!policy.tableHasOwnershipColumn) {
        continue; // no ownership column ⇒ likely intentionally shared/reference data (fail secure)
      }
      if (!isAuthenticatedOnlyGap(policy)) {
        continue; // owner-bound / role-delegated / function-delegated / unconditional / unknown → safe or out of scope
      }
      // A write-only gap is one where USING scopes correctly but WITH CHECK only checks "is logged in" —
      // the read side is fine, but writes are unrestricted. Attribute the message to that write path so
      // the remediation points at the right clause (SEC-01).
      const writeCheckGap =
        policy.command !== 'select' &&
        policy.checkClass === 'authenticated-only' &&
        effectivePolicyClass(policy) !== 'authenticated-only';
      const message = writeCheckGap
        ? `Policy on "${policy.table}" (${policy.command.toUpperCase()}) scopes reads to the caller but its WITH CHECK only verifies the caller is authenticated (e.g. auth.uid() IS NOT NULL) — any authenticated user can write rows they don't own or set the ownership column to someone else's id (IDOR write). Aegis flags this for review; the USING clause alone looked correct.`
        : `Policy on "${policy.table}" (${policy.command.toUpperCase()}) only checks that the caller is authenticated (e.g. auth.role()/auth.uid() IS NOT NULL), but the table has an ownership column — every authenticated user can ${policy.command === 'select' ? 'read' : 'read or modify'} EVERY row, not just their own. Aegis flags this for review; it cannot confirm whether the table is meant to be shared.`;
      ctx.report({
        loc: policy.loc,
        confidence: 'medium',
        message,
        remediation:
          'Scope the policy to the caller, e.g. `USING (auth.uid() = user_id)` (with a matching `WITH CHECK (auth.uid() = user_id)` for writes). If this table is intentionally readable by all authenticated users (reference/lookup data), this is expected — no change needed.',
        evidence: writeCheckGap
          ? (policy.checkExpr ?? `${policy.table} ${policy.command} with check`)
          : (policy.usingExpr ?? policy.checkExpr ?? `${policy.table} ${policy.command}`),
      });
    }
  },
};

/**
 * A PERMISSIVE UPDATE/DELETE/ALL policy reachable by `anon`/`public` whose predicate does NOT bind rows
 * to the caller — so an *unauthenticated* visitor can modify or delete EXISTING rows. A policy with no
 * `TO` clause counts: PostgreSQL applies it to `public` (which includes `anon`), so it is exposed even
 * though no role is named. INSERT is excluded (a public submission form is a legitimate anon-write
 * pattern); only mutation of existing rows is the gap. The danger is a predicate an anonymous caller can
 * satisfy: an unconditional `true` *in the USING predicate* is already owned by `permissiveWritePolicy`,
 * so this rule targets the case that one misses — a row-STATE-only predicate (`unknown`: no auth
 * primitive, no ownership binding, no membership subquery), e.g. `is_public = true AND share_slug is not
 * null`. (A `true` in WITH CHECK is a *separate* post-image defect that `permissiveWritePolicy` reports;
 * when the USING side is still row-state-only this rule also fires, and the two findings are complementary
 * — one says anon can target existing rows, the other says the resulting row state is unconstrained.) An
 * owner-bound or membership-delegated predicate matches no anon row (anon has no `auth.uid()`), so it
 * never reaches here. Found validating against a real public view-counter table whose `GRANT UPDATE (col)`
 * + permissive policy let anon UPDATE published rows — column-level GRANTs are not a robust row-ownership
 * boundary on Supabase's default table grants.
 */
export const anonWritablePolicy: SqlRule = {
  meta: {
    id: 'rls/anon-writable',
    title: 'Anonymous role can modify or delete existing rows',
    severity: 'HIGH',
    owasp: OWASP,
    docsUrl: docsUrlFor('rls/anon-writable'),
  },
  check(ctx) {
    for (const policy of ctx.model.policies) {
      if (policy.restrictive) {
        continue; // RESTRICTIVE only narrows access; it never grants the write
      }
      // Only mutation of EXISTING rows is the gap — INSERT (public submission forms) is intentional.
      if (policy.command !== 'update' && policy.command !== 'delete' && policy.command !== 'all') {
        continue;
      }
      // An empty `roles` array means no `TO` clause → PostgreSQL applies the policy to `public` (incl.
      // `anon`), so it is exposed. A non-empty list must actually name `anon`/`public` to qualify.
      const exposedRoles = policy.roles.length === 0 ? ['public'] : policy.roles.filter(isAnonRole);
      if (exposedRoles.length === 0) {
        continue;
      }
      // An unconditional `true` in the USING predicate is already reported by `permissiveWritePolicy`;
      // flag the gap it misses — a row-state-only predicate an anonymous caller can satisfy.
      if (effectivePolicyClass(policy) !== 'unknown') {
        continue;
      }
      const roleLabel =
        policy.roles.length === 0 ? 'public (no TO clause, includes anon)' : exposedRoles.join('/');
      ctx.report({
        loc: policy.loc,
        confidence: 'medium',
        message: `Policy on "${policy.table}" (${policy.command.toUpperCase()}) is reachable by ${roleLabel} and its predicate only checks row state, not the caller — an unauthenticated visitor can ${policy.command === 'delete' ? 'DELETE' : 'modify'} any row that satisfies it. A column-level GRANT does not stop this: on Supabase's default table grants, anon may already hold the table privilege.`,
        remediation:
          'Do not grant UPDATE/DELETE on existing rows to anon/public. Move the mutation behind a SECURITY DEFINER function (e.g. an `increment_view_count(slug)` RPC) that performs the scoped change, or restrict the policy to the authenticated owner with `USING (auth.uid() = user_id)`.',
        evidence:
          policy.usingExpr ?? policy.checkExpr ?? `${policy.table} ${policy.command} to anon`,
      });
    }
  },
};

export const anonTableGrant: SqlRule = {
  meta: {
    id: 'rls/anon-table-grant',
    title: 'Table granted to anon/public',
    severity: 'MEDIUM',
    owasp: OWASP,
    docsUrl: docsUrlFor('rls/anon-table-grant'),
  },
  check(ctx) {
    for (const grant of ctx.model.grants) {
      const exposed = grant.roles.filter((role) => role === 'anon' || role === 'public');
      if (exposed.length === 0) {
        continue;
      }
      // Granting to anon WITH RLS enabled is the standard Supabase pattern (rows are scoped by policy),
      // so flag only a schema-wide grant, or a grant on a table that is NOT RLS-protected (a real leak).
      if (grant.table !== '*') {
        const table = ctx.model.tables.get(grant.table);
        if (!table || table.rlsEnabled) {
          continue;
        }
      }
      const target = grant.table === '*' ? 'all tables in schema public' : `"${grant.table}"`;
      ctx.report({
        loc: grant.loc,
        confidence: 'medium',
        message: `Table-level GRANT to ${exposed.join('/')} on ${target} exposes data to unauthenticated/all roles without RLS to scope it — public data access.`,
        remediation:
          'Grant table privileges only to the `authenticated` role and rely on RLS policies for per-row scoping; never grant table DML to `anon`/`public` on an unprotected table.',
        evidence: `grant to ${exposed.join('/')}`,
      });
    }
  },
};
