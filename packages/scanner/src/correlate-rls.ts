/**
 * RLS↔code correlation — turn a config-level RLS gap into a CONFIRMED application exposure. When a
 * table has weak RLS (none enabled, or an unconditional write policy) AND the application queries it
 * through a non-admin (anon/authenticated) Supabase client, that is a concrete "any user can reach
 * this data" finding, located at the exact query site. The SAST↔SAST analog of runtime confirmation.
 *
 * Cost-aware: if the migrations have no weak table (a correct RLS design), this returns immediately
 * WITHOUT parsing any TypeScript — zero overhead on well-configured projects.
 */

import { readFileSync } from 'node:fs';
import { forEachDescendant, parseSource, rangeOf, ts } from './internal/ast';
import { buildRlsModel, type RlsModel } from './internal/sql/model';
import { isAuthenticatedOnlyGap } from './internal/sql/predicate';
import { docsUrlFor } from './rule';
import type { Confidence, Finding } from './types';

export interface CorrelateRlsOptions {
  readonly sqlFiles: readonly string[];
  readonly tsFiles: readonly string[];
  readonly readFile?: (path: string) => string;
}

/** Why a table's RLS is weak, plus how confident we are the query site is a real exposure. */
interface WeakReason {
  readonly reason: string;
  readonly confidence: Confidence;
}

/**
 * Tables whose RLS is weak enough that a non-admin query exposes data. Confidence is carried per table:
 * no-RLS and unconditional-write are unambiguous exposures (`high`, CI-blocking); an authenticated-only
 * policy is a "RLS exists but doesn't scope to the caller" read exposure that depends on intent (the
 * table may be deliberately shared), so it is `medium` — non-blocking, mirroring `rls/policy-not-owner-
 * scoped`. The `!weak.has` guards ensure a high reason is never downgraded to medium.
 */
function weakTables(model: RlsModel): Map<string, WeakReason> {
  const weak = new Map<string, WeakReason>();
  for (const table of model.tables.values()) {
    if (!table.rlsEnabled) {
      weak.set(table.name, { reason: 'has no Row Level Security', confidence: 'high' });
    }
  }
  for (const policy of model.policies) {
    if (policy.restrictive) {
      continue;
    }
    if (
      (policy.usingTrue || policy.checkTrue) &&
      policy.command !== 'select' &&
      !weak.has(policy.table)
    ) {
      weak.set(policy.table, { reason: 'has an unconditional write policy', confidence: 'high' });
      continue;
    }
    if (
      policy.tableHasOwnershipColumn &&
      isAuthenticatedOnlyGap(policy) &&
      !weak.has(policy.table)
    ) {
      weak.set(policy.table, {
        reason: 'has an RLS policy that only checks authentication, not row ownership',
        confidence: 'medium',
      });
    }
  }
  return weak;
}

/** A `supabase.from('<literal>')` table name, or undefined. */
function fromTableName(node: ts.Node): string | undefined {
  if (
    ts.isCallExpression(node) &&
    ts.isPropertyAccessExpression(node.expression) &&
    node.expression.name.text === 'from'
  ) {
    const arg = node.arguments[0];
    if (arg && ts.isStringLiteralLike(arg)) {
      return arg.text;
    }
  }
  return undefined;
}

// The admin/service-role client bypasses RLS by design, so a `.from()` there is not an RLS exposure.
const SERVICE_ROLE_HINT = /createAdminClient|service_role|SERVICE_ROLE/;

export function correlateRls(options: CorrelateRlsOptions): Finding[] {
  const read = options.readFile ?? ((path: string) => readFileSync(path, 'utf8'));
  // Skip any SQL file that can't be read (the authoritative scanSql pass already surfaces it as a
  // finding); build the RLS model from the rest rather than letting one bad file abort correlation.
  const sqlSources: { path: string; text: string }[] = [];
  for (const path of options.sqlFiles) {
    try {
      sqlSources.push({ path, text: read(path) });
    } catch {
      // already surfaced by scanSql; nothing to correlate from an unreadable migration
    }
  }
  const model = buildRlsModel(sqlSources);
  const weak = weakTables(model);
  if (weak.size === 0) {
    return []; // correct RLS design → nothing to correlate, no TS parsed
  }

  const findings: Finding[] = [];
  for (const file of options.tsFiles) {
    let text: string;
    try {
      text = read(file);
    } catch {
      continue;
    }
    if (SERVICE_ROLE_HINT.test(text)) {
      continue; // admin client bypasses RLS — not an exposure
    }
    const sourceFile = parseSource(file, text);
    forEachDescendant(sourceFile, (node) => {
      const table = fromTableName(node);
      const entry = table ? weak.get(table) : undefined;
      if (table && entry) {
        // High-confidence reasons (no RLS, unconditional write) are confirmed exposures. The medium
        // authenticated-only path is intent-dependent — the table MAY be deliberately shared — so it gets
        // softer, accurate copy and never the absolute "confirmed exposure" phrasing (SEC-02 + the repo
        // framing rule: Aegis never claims it can confirm a table is meant to be private).
        const exposure =
          entry.confidence === 'high'
            ? 'any authenticated/anonymous user can read or modify this data (confirmed exposure)'
            : 'every authenticated user can read every row, not just their own — flagged for review; Aegis cannot confirm the table is meant to be private';
        findings.push({
          ruleId: 'rls/exposed-table-access',
          severity: 'HIGH',
          confidence: entry.confidence,
          message: `Table "${table}" ${entry.reason} and is queried here via a non-admin Supabase client — ${exposure}.`,
          file,
          range: rangeOf(sourceFile, node),
          docsUrl: docsUrlFor('rls/exposed-table-access'),
          remediation: `Enable/repair RLS on "${table}" (ALTER TABLE … ENABLE ROW LEVEL SECURITY + caller-scoped policies), or move this access behind the service-role admin client guarded by an authorization check.`,
          owasp: 'A01:2021 Broken Access Control',
          evidence: `.from('${table}')`,
        });
      }
    });
  }
  return findings;
}
