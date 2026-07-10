/**
 * Roles an untrusted caller can never assume, so a policy scoped ONLY to them is not an attack surface —
 * `service_role` even bypasses RLS entirely (BYPASSRLS), making `FOR ALL TO service_role USING (true)`
 * idiomatic backend access rather than a gap. A policy that ALSO names authenticated/anon/public stays in
 * scope (empty `roles` = implicit public ⇒ not privileged-only). Field-validated: `service_role`-scoped
 * permissive writes were a false-positive class on the public corpus.
 *
 * Shared by the `rls/*` rules AND the RLS↔code correlator so the two verdict surfaces cannot drift —
 * they did once: `correlate-rls` kept emitting HIGH "confirmed exposure" findings on the exact
 * privileged-only policies the rules had just learned to skip.
 */
export const PRIVILEGED_ROLES: ReadonlySet<string> = new Set([
  'service_role',
  'supabase_admin',
  'supabase_auth_admin',
  'supabase_storage_admin',
  'postgres',
  'dashboard_user',
]);

/** True when the role list is non-empty and every entry is a privileged (untrusted-unreachable) role. */
export const appliesOnlyToPrivilegedRoles = (roles: readonly string[]): boolean =>
  roles.length > 0 && roles.every((role) => PRIVILEGED_ROLES.has(role));
