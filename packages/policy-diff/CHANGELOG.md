# @aegiskit/policy-diff

## 0.1.0

### Minor Changes

- ea67c99: Aegis Policy Gate: a semantic RLS access diff that answers the one question a migration PR review asks — "did this change widen who can read or write what?" — and fails closed on anything it cannot verify.

  - **New `@aegiskit/policy-diff` package:** `diffAccess` compares the Supabase RLS surface (policies, RLS state, table grants) of two migration states over a role-aware breadth lattice (`none ⊂ own/state/delegated ⊂ all`). `widening` is claimed only for superset-or-equal moves, `narrowing` only for subset-or-equal, and everything unverifiable (untrusted custom functions, over-long/incomparable predicates, uninterpreted statements) is `requires-review` — never a false "no change". `renderDeltaMarkdown` produces the sticky PR-comment body, hardened against markdown/HTML injection from attacker-authored SQL.
  - **`@aegiskit/scanner`:** fail-open closure of the RLS model — final-state `DISABLE RLS`, `REVOKE` (full vs. partial), `ALTER POLICY RENAME`, storage-schema policies, and an `uninterpreted` record for anything access-relevant the model could not read. `customCallsIn` / `PredicateClass` are now part of the public contract (consumed by `policy-diff`).
  - **`@aegiskit/cli`:** new `aegis diff --base <ref> [--head <ref>] [--trust <fn>] [--format pretty|markdown|json]` — reads authoritative SQL at a git ref via `ls-tree`/`show` (no checkout), exits `1` on high-severity widenings (`--strict` also fails on notice-level attention).
  - **GitHub Action + `@aegiskit/mcp`:** `policy-diff: true` posts the access delta as a sticky PR comment and exposes a `policy-diff-conclusion` output; the MCP server gains `explain_policy_diff` so Claude Code / Cursor can cite a reproducible delta.

- 330c373: scanner: close the false-positive/false-negative classes surfaced by the independent 12,727-repo field study (RLS precision hardening, round 2).

  - `ALTER TABLE IF EXISTS [ONLY] <table>` is now parsed identically to the bare form for ENABLE/DISABLE ROW LEVEL SECURITY and ADD COLUMN (shared `ALTER_TABLE_HEAD` fragment). Previously ENABLE via `IF EXISTS` produced a CI-breaking false `rls/table-without-rls`, DISABLE was silently missed (fail-open), and ADD COLUMN dropped the ownership-column record. A comment interleaved inside a static `ALTER … ENABLE/DISABLE` is now also attributed to its table instead of being misread.
  - Procedural RLS enablement (a DO-block loop over `pg_tables`, a dynamic `EXECUTE format('alter table %I enable row level security', …)`, a plpgsql function body, the psql `\gexec` idiom) sets a new `proceduralRlsEnable` field on `RlsModel`. `rls/table-without-rls` and `rls/anon-table-grant` (non-wildcard) suppress when it is set — the model cannot prove any table unprotected, so flagging would be a CI-blocking false positive. Detection requires BOTH a procedural construct (`DO`, `CREATE FUNCTION/PROCEDURE`, `EXECUTE`, `format()`/`concat()`, `||`) AND the full executable `alter table … enable` phrase: a string literal or comment merely _mentioning_ the phrase — even inside an unrelated `ALTER TABLE` or split across INSERT values — does not suppress anything.
  - The Supabase CLI's `(select auth.uid() as uid)` performance-wrapper alias is now recognized by every classifier gate (`selectWrap` unified); these forms previously fell through to `unknown`, misfiring `rls/anon-writable` on authenticated-only and `service_role` policies.
  - Hardcoded-identity pins (`auth.uid() = '<uuid>'`, `auth.jwt() ->> 'sub' = '<id>'`) classify as `role-delegated` — a single-admin gate an anonymous caller can never satisfy (~4% of `rls/anon-writable` field false positives).
  - Policies scoped exclusively to privileged roles (`service_role`, `supabase_admin`, `supabase_auth_admin`, `supabase_storage_admin`, `postgres`, `dashboard_user`) are skipped by `rls/write-policy-without-check`, `rls/permissive-write-policy`, and `rls/policy-not-owner-scoped` — `service_role` bypasses RLS entirely (BYPASSRLS), so `FOR ALL TO service_role USING (true)` is idiomatic backend access. A policy that also names `authenticated`/`anon`/`public` stays fully in scope.
  - The RLS↔code correlator (`rls/exposed-table-access`) applies the same two suppressions (procedural enable, privileged-only policies) so it can no longer re-emit, at HIGH confidence, findings the rules suppress.

  policy-diff: `table-added-without-rls` and the grant-added "NO RLS — direct data exposure" escalation are suppressed when the head model declares a procedural bulk-enable — neither is a provable exposure there (the grant widening itself still emits, at notice). Known deferred FP: a base static enable refactored into a head procedural loop still reads as `rls-disabled`; gating that branch would fail open on real disables, so it needs per-table attribution first.

### Patch Changes

- Updated dependencies [ea67c99]
- Updated dependencies [97ecfbc]
- Updated dependencies [330c373]
  - @aegiskit/scanner@0.3.0
