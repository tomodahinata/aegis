# @aegiskit/scanner

## 0.3.0

### Minor Changes

- ea67c99: Aegis Policy Gate: a semantic RLS access diff that answers the one question a migration PR review asks — "did this change widen who can read or write what?" — and fails closed on anything it cannot verify.

  - **New `@aegiskit/policy-diff` package:** `diffAccess` compares the Supabase RLS surface (policies, RLS state, table grants) of two migration states over a role-aware breadth lattice (`none ⊂ own/state/delegated ⊂ all`). `widening` is claimed only for superset-or-equal moves, `narrowing` only for subset-or-equal, and everything unverifiable (untrusted custom functions, over-long/incomparable predicates, uninterpreted statements) is `requires-review` — never a false "no change". `renderDeltaMarkdown` produces the sticky PR-comment body, hardened against markdown/HTML injection from attacker-authored SQL.
  - **`@aegiskit/scanner`:** fail-open closure of the RLS model — final-state `DISABLE RLS`, `REVOKE` (full vs. partial), `ALTER POLICY RENAME`, storage-schema policies, and an `uninterpreted` record for anything access-relevant the model could not read. `customCallsIn` / `PredicateClass` are now part of the public contract (consumed by `policy-diff`).
  - **`@aegiskit/cli`:** new `aegis diff --base <ref> [--head <ref>] [--trust <fn>] [--format pretty|markdown|json]` — reads authoritative SQL at a git ref via `ls-tree`/`show` (no checkout), exits `1` on high-severity widenings (`--strict` also fails on notice-level attention).
  - **GitHub Action + `@aegiskit/mcp`:** `policy-diff: true` posts the access delta as a sticky PR comment and exposes a `policy-diff-conclusion` output; the MCP server gains `explain_policy_diff` so Claude Code / Cursor can cite a reproducible delta.

- 97ecfbc: Explain and deliver the RLS/authz moat: suggested fixes, compliance evidence v2, and an MCP server.

  - **RLS explainability (scanner/cli):** `rls/policy-not-owner-scoped` findings now carry a structured `explanation` (why the policy fails, its predicate class) and a concrete, owner-scoped `CREATE POLICY` suggestion bound to the table's real ownership column — rendered in the pretty (incl. `--plain`), JSON, and SARIF reporters. Directly answers the top community ask: "tell me why my RLS fails, and how to fix it."
  - **Compliance evidence v2 (scanner/cli):** `aegis report --format html` renders a self-contained, print-ready, WCAG-AA control-evidence document. New `--record`/`--history` flags maintain an append-only scan-history ledger, and the HTML report gains a remediation-tracking section (first-seen / resolved / mean-time-to-remediate) — the remediation-over-time evidence SOC 2 CC7.1 auditors require.
  - **New `@aegiskit/mcp` package:** Aegis as a Model Context Protocol server (`scan_project`, `explain_finding`) so Claude Code / Cursor users find and fix Supabase RLS/authz gaps in-editor, with secret evidence redacted before it reaches the model.

- 330c373: scanner: close the false-positive/false-negative classes surfaced by the independent 12,727-repo field study (RLS precision hardening, round 2).

  - `ALTER TABLE IF EXISTS [ONLY] <table>` is now parsed identically to the bare form for ENABLE/DISABLE ROW LEVEL SECURITY and ADD COLUMN (shared `ALTER_TABLE_HEAD` fragment). Previously ENABLE via `IF EXISTS` produced a CI-breaking false `rls/table-without-rls`, DISABLE was silently missed (fail-open), and ADD COLUMN dropped the ownership-column record. A comment interleaved inside a static `ALTER … ENABLE/DISABLE` is now also attributed to its table instead of being misread.
  - Procedural RLS enablement (a DO-block loop over `pg_tables`, a dynamic `EXECUTE format('alter table %I enable row level security', …)`, a plpgsql function body, the psql `\gexec` idiom) sets a new `proceduralRlsEnable` field on `RlsModel`. `rls/table-without-rls` and `rls/anon-table-grant` (non-wildcard) suppress when it is set — the model cannot prove any table unprotected, so flagging would be a CI-blocking false positive. Detection requires BOTH a procedural construct (`DO`, `CREATE FUNCTION/PROCEDURE`, `EXECUTE`, `format()`/`concat()`, `||`) AND the full executable `alter table … enable` phrase: a string literal or comment merely _mentioning_ the phrase — even inside an unrelated `ALTER TABLE` or split across INSERT values — does not suppress anything.
  - The Supabase CLI's `(select auth.uid() as uid)` performance-wrapper alias is now recognized by every classifier gate (`selectWrap` unified); these forms previously fell through to `unknown`, misfiring `rls/anon-writable` on authenticated-only and `service_role` policies.
  - Hardcoded-identity pins (`auth.uid() = '<uuid>'`, `auth.jwt() ->> 'sub' = '<id>'`) classify as `role-delegated` — a single-admin gate an anonymous caller can never satisfy (~4% of `rls/anon-writable` field false positives).
  - Policies scoped exclusively to privileged roles (`service_role`, `supabase_admin`, `supabase_auth_admin`, `supabase_storage_admin`, `postgres`, `dashboard_user`) are skipped by `rls/write-policy-without-check`, `rls/permissive-write-policy`, and `rls/policy-not-owner-scoped` — `service_role` bypasses RLS entirely (BYPASSRLS), so `FOR ALL TO service_role USING (true)` is idiomatic backend access. A policy that also names `authenticated`/`anon`/`public` stays fully in scope.
  - The RLS↔code correlator (`rls/exposed-table-access`) applies the same two suppressions (procedural enable, privileged-only policies) so it can no longer re-emit, at HIGH confidence, findings the rules suppress.

  policy-diff: `table-added-without-rls` and the grant-added "NO RLS — direct data exposure" escalation are suppressed when the head model declares a procedural bulk-enable — neither is a provable exposure there (the grant widening itself still emits, at notice). Known deferred FP: a base static enable refactored into a head procedural loop still reads as `rls-disabled`; gating that branch would fail open on real disables, so it needs per-table attribution first.

## 0.2.0

### Minor Changes

- 430bb72: scanner: detect RLS policies that gate on authentication but not row ownership.

  - `rls/policy-not-owner-scoped` now also flags write-capable policies whose `WITH CHECK` predicate is authenticated-only even when `USING` is owner-bound (`FOR ALL … USING (auth.uid() = user_id) WITH CHECK (auth.uid() IS NOT NULL)`), where any logged-in user can insert or give away rows they do not own (CWE-639).
  - `rls/exposed-table-access` correlates this authenticated-only case to the query site at **medium** confidence — it informs, it does not assert confirmed exposure, because the table may be intentionally shared.
  - Predicate classification now ignores `auth.*` tokens that appear inside SQL comments or string literals (JWT-claim literals are preserved), removing a class of false positives, and is hardened against a quadratic-time blowup on adversarially long policy predicates.
  - `crypto/weak-hash` no longer suppresses weak hashes used for auth-relevant identifiers (e.g. `cacheSessionToken`, `deviceFingerprint`), while keeping benign UUID/cache-key/asset-fingerprint uses suppressed.

  cli: the pretty reporter prints a prioritized "Fix first" headline with a severity breakdown and sorts findings by severity → confidence → location. Engine, JSON, and SARIF output order are unchanged.

### Patch Changes

- 06a14c8: scanner: point rule docs links and the SARIF `informationUri` at the live coverage matrix instead of the unregistered `aegis.dev` domain, which did not resolve. Every finding's `Docs:` link and the SARIF report now reach a real page. The canonical project URL is centralized as `PROJECT_URL` so it can never drift across reporters again.

## 0.1.0

### Minor Changes

- c456706: Add `authz/idor-tainted-scope` — taint-based IDOR detection. It flags a Supabase query that scopes rows by an ownership column (`user_id`, `tenant_id`, `owner_id`, …) when that filter is bound to request-controlled input (e.g. `.eq('user_id', body.userId)`): a proven request-source → ownership-filter dataflow, not a heuristic. Reported at high confidence (can fail CI), and — sharing the `authz/` prefix — it slots into the static↔dynamic correlation, so a runtime `dast/idor` probe upgrades it to "confirmed exploitable". The primary key `id` is excluded and a numeric cast does not clear it (authorization is not a sanitization problem), preserving the zero-false-positive gate. The complementary heuristic rule now defers to this finding instead of emitting a contradictory pass.

  Also hardens the engine to be fail-secure per rule: a rule that throws on a pathological AST is now surfaced as a LOW analysis-error finding (naming the rule and file) instead of aborting the whole scan and silently dropping every other rule's and file's findings. This mirrors the existing per-file parse isolation.

- 20e9e2a: Initial release of Aegis — a drop-in, defense-in-depth security toolkit for Next.js / Supabase SaaS.

  - `@aegiskit/core` — edge-safe primitives: nonce-based CSP, hardened headers, serverless-correct rate limiting, fail-closed origin/CSRF checks, a typed env boundary, and a pluggable security-event sink.
  - `@aegiskit/next` — App Router adapters: `secure()` (the single CSP emitter), `secureRoute()`, `getNonce()`, and a `server-only` env boundary.
  - `@aegiskit/store-upstash` — an atomic, serverless-correct rate-limit store backed by Upstash Redis.
  - `@aegiskit/scanner` + `@aegiskit/cli` — static analysis for the gaps a library can't auto-fix, with confidence-gated CI, SARIF output, and an accessible report.

- 7724da1: Phase 2 — observability, the dashboard, scanner usability, and adoption.

  - **Observability loop**: `@aegiskit/core` `createHttpSink` (edge-safe, batched, HMAC-signed, bounded, fire-and-forget); a new `@aegiskit/observability` package (`EventStore` + `createMemoryEventStore`, `computePostureScore`, `EVENT_SEVERITY`, `verifyBatchSignature`); `@aegiskit/next` `createCspReportHandler` + a `secure({ cspReportEndpoint })` option; and `@aegiskit/store-supabase` (a persistent EventStore + a migration with RLS on by default).
  - **Scanner usability**: inline `// aegis-disable-next-line <rule> -- <reason>` suppression (reason mandatory), a line-stable `aegis-baseline.json` for incremental adoption (`--baseline` / `--update-baseline` / `--show-suppressed`), and two new rules — `xss/dangerous-html-unsanitized` and `secrets/committed-literal`.
  - **Adoption**: a new `@aegiskit/eslint-config` security preset and a reusable GitHub Action (`action.yml`).
  - **CLI fix**: `aegis scan|ci|doctor <path>` now honors a positional path argument. Previously only `--cwd` was read, so `aegis scan apps/dashboard` silently scanned the current directory instead of the target — a dangerous failure mode for a security scanner.
  - **Dashboard**: a self-hostable, WCAG 2.2 AA `apps/dashboard` that dogfoods Aegis (posture score, events, CSP violations, signed ingestion, admin session).

- 42a3b97: Phase 3 — remediation (`aegis fix`): turn detect-and-warn into detect-and-fix.

  - **`@aegiskit/scanner`**: findings can now carry a safe, machine-applicable `Fix` (`TextEdit[]`), resolved only under the new `scan({ computeFixes: true })` option (zero hot-path cost otherwise). Ships a pure, overlap-safe edit applier (`applyTextEdits`, `planFileFixes`) and the first codemod — wrapping a route handler with `secureRoute({ origin: true })` — which is **strictly shape-gated and fails closed to guided** (dynamic routes, arrow handlers, re-exports, multi-param handlers are never auto-rewritten).
  - **`@aegiskit/cli`**: new `aegis fix [path]` command — **preview-first** (no writes by default), `--write` to apply, `--rule <id>` to scope. `--format json` emits a machine-readable remediation plan (auto + guided) designed as a **coding-agent handoff**. The headers finding reuses `aegis init` to scaffold a `secure()` middleware. Output is accessible (mode shown as icon **and** text, `--plain` / `--no-color` honored).

  The honest-scope line is enforced in the type system: only provably-safe transforms are `auto`; everything requiring human judgement is `guided`, with precise steps. Aegis never claims to fix authorization/IDOR or business-logic flaws.
