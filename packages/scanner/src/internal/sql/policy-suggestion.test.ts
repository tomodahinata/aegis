import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { OWNERSHIP_COLUMNS } from '../ownership-columns';
import type { PolicyCommand } from './model';
import { suggestOwnerScopedPolicy } from './policy-suggestion';
import { classifyPredicate, extractClauseBody } from './predicate';

const COMMANDS: readonly PolicyCommand[] = ['all', 'select', 'insert', 'update', 'delete'];

describe('suggestOwnerScopedPolicy', () => {
  it('emits USING for reads, WITH CHECK for the post-image, matching each command', () => {
    expect(
      suggestOwnerScopedPolicy({ table: 'notes', ownershipColumn: 'user_id', command: 'select' }),
    ).toBe(
      'create policy "notes_select_owner" on public.notes\n' +
        '  for select to authenticated\n' +
        '  using (auth.uid() = user_id);',
    );
    expect(
      suggestOwnerScopedPolicy({ table: 'notes', ownershipColumn: 'user_id', command: 'insert' }),
    ).toBe(
      'create policy "notes_insert_owner" on public.notes\n' +
        '  for insert to authenticated\n' +
        '  with check (auth.uid() = user_id);',
    );
    expect(
      suggestOwnerScopedPolicy({ table: 'notes', ownershipColumn: 'user_id', command: 'all' }),
    ).toBe(
      'create policy "notes_all_owner" on public.notes\n' +
        '  for all to authenticated\n' +
        '  using (auth.uid() = user_id)\n' +
        '  with check (auth.uid() = user_id);',
    );
  });

  it('scopes DELETE by USING only (WITH CHECK is ignored for DELETE)', () => {
    const sql = suggestOwnerScopedPolicy({
      table: 't',
      ownershipColumn: 'owner_id',
      command: 'delete',
    });
    expect(sql).toContain('using (auth.uid() = owner_id);');
    expect(sql).not.toContain('with check');
  });

  // The load-bearing invariant: whatever the generator emits, feeding its clause(s) back through the
  // classifier yields `owner-bound` — never the `authenticated-only` gap. Generator ⇄ checker can never
  // drift, so a suggested fix is provably not itself flaggable by `rls/policy-not-owner-scoped`.
  it('every generated clause classifies as owner-bound (generator ⇄ checker consistency)', () => {
    fc.assert(
      fc.property(
        fc.constantFrom(...OWNERSHIP_COLUMNS),
        fc.constantFrom(...COMMANDS),
        // A realistic unquoted public-schema table identifier.
        fc.stringMatching(/^[a-z][a-z0-9_]{0,30}$/),
        (ownershipColumn, command, table) => {
          const sql = suggestOwnerScopedPolicy({ table, ownershipColumn, command });
          const using = extractClauseBody(sql, 'using');
          const check = extractClauseBody(sql, 'with check');
          // At least one clause is always present.
          expect(using !== undefined || check !== undefined).toBe(true);
          for (const clause of [using, check]) {
            if (clause !== undefined) {
              expect(classifyPredicate(clause)).toBe('owner-bound');
            }
          }
        },
      ),
    );
  });
});
