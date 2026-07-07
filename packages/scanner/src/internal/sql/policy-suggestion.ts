/**
 * Generate a corrected, owner-scoped RLS policy for a table whose current policy authenticates the caller
 * but binds no row to them (the `rls/policy-not-owner-scoped` gap). Pure and deterministic — the ADVISORY
 * companion to the finding: Aegis cannot know your intended ownership semantics, so the output scopes rows
 * to `auth.uid() = <ownershipColumn>` (the canonical Supabase single-owner pattern) for the reader to adapt.
 *
 * Provably consistent with the classifier: every statement this emits, fed back through `classifyPredicate`,
 * classifies `owner-bound` — never the `authenticated-only` gap. That invariant is asserted in the test, so
 * the generator and the checker can never drift (mirrors the portfolio `rls-policy-generator` ⇄ checker test;
 * keep the two in sync — see the portfolio cross-repo coupling note).
 */

import type { PolicyCommand } from './model';

export interface OwnerScopedPolicyInput {
  /** Unqualified table name in the `public` schema. */
  readonly table: string;
  /** The ownership column to scope rows by (e.g. `user_id`). */
  readonly ownershipColumn: string;
  /** The command the original (gap) policy governed. */
  readonly command: PolicyCommand;
}

/**
 * Which clauses a command needs to scope both reads and writes to the owner. USING governs which existing
 * rows are visible/affected; WITH CHECK governs the post-image of a write. INSERT has no USING (there is no
 * prior row); DELETE ignores WITH CHECK (it produces no row) — so each gets exactly the clause that binds it.
 */
function clausesFor(command: PolicyCommand): { readonly using: boolean; readonly check: boolean } {
  switch (command) {
    case 'select':
      return { using: true, check: false };
    case 'insert':
      return { using: false, check: true };
    case 'delete':
      return { using: true, check: false };
    default:
      // update / all — govern both the affected rows and their post-image.
      return { using: true, check: true };
  }
}

/**
 * Build a scoped `CREATE POLICY` that replaces the gap policy. The predicate is `auth.uid() = <column>`,
 * which `classifyPredicate` recognizes as `owner-bound`. Restricted to the `authenticated` role: an
 * owner-scoped policy is meaningless for `anon`, which has no `auth.uid()`.
 */
export function suggestOwnerScopedPolicy(input: OwnerScopedPolicyInput): string {
  const { using, check } = clausesFor(input.command);
  const predicate = `auth.uid() = ${input.ownershipColumn}`;
  const lines = [
    `create policy "${input.table}_${input.command}_owner" on public.${input.table}`,
    `  for ${input.command} to authenticated`,
  ];
  if (using) {
    lines.push(`  using (${predicate})${check ? '' : ';'}`);
  }
  if (check) {
    lines.push(`  with check (${predicate});`);
  }
  return lines.join('\n');
}
