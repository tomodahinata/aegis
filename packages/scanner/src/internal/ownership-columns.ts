/**
 * Columns whose PURPOSE is to scope rows to a principal (a user / tenant / account). Filtering or
 * gating on one of these is how ownership is enforced — so their PRESENCE on a table is also what makes
 * an "authenticated-only" RLS policy suspicious: the column exists to scope rows, yet the policy ignores
 * it. One authoritative list shared by the IDOR taint rule (`rules/authz.ts`), the SQL model
 * (`internal/sql/model.ts`), and the owner-scoping RLS rule (`sql-rules/rls.ts`) — DRY.
 *
 * The bare primary key `id` is deliberately EXCLUDED: `.eq('id', x)` is the ubiquitous "fetch one by
 * id" that is safe under RLS or a later ownership check; flagging it would flood the zero-false-positive
 * gate. Only columns that exist to enforce ownership belong here.
 */
export const OWNERSHIP_COLUMNS: ReadonlySet<string> = new Set([
  'user_id',
  'owner_id',
  'tenant_id',
  'organization_id',
  'org_id',
  'account_id',
  'profile_id',
  'team_id',
  'workspace_id',
  'customer_id',
  'member_id',
]);

/**
 * Matches any ownership column as a whole word — a cheap presence pre-filter. Used to skip the taint
 * pass on files with no ownership column, and to detect (from migration text) whether a table carries
 * an ownership column. The regex is flag-free, so `.test()` is stateless and the instance is safely
 * shared across call sites.
 */
export const OWNERSHIP_COLUMN_PATTERN = new RegExp(`\\b(?:${[...OWNERSHIP_COLUMNS].join('|')})\\b`);
