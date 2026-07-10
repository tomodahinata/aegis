# @aegiskit/cli

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

### Patch Changes

- Updated dependencies [ea67c99]
- Updated dependencies [97ecfbc]
- Updated dependencies [330c373]
  - @aegiskit/policy-diff@0.1.0
  - @aegiskit/scanner@0.3.0
  - @aegiskit/dast@0.0.3

## 0.2.0

### Minor Changes

- 430bb72: scanner: detect RLS policies that gate on authentication but not row ownership.

  - `rls/policy-not-owner-scoped` now also flags write-capable policies whose `WITH CHECK` predicate is authenticated-only even when `USING` is owner-bound (`FOR ALL … USING (auth.uid() = user_id) WITH CHECK (auth.uid() IS NOT NULL)`), where any logged-in user can insert or give away rows they do not own (CWE-639).
  - `rls/exposed-table-access` correlates this authenticated-only case to the query site at **medium** confidence — it informs, it does not assert confirmed exposure, because the table may be intentionally shared.
  - Predicate classification now ignores `auth.*` tokens that appear inside SQL comments or string literals (JWT-claim literals are preserved), removing a class of false positives, and is hardened against a quadratic-time blowup on adversarially long policy predicates.
  - `crypto/weak-hash` no longer suppresses weak hashes used for auth-relevant identifiers (e.g. `cacheSessionToken`, `deviceFingerprint`), while keeping benign UUID/cache-key/asset-fingerprint uses suppressed.

  cli: the pretty reporter prints a prioritized "Fix first" headline with a severity breakdown and sorts findings by severity → confidence → location. Engine, JSON, and SARIF output order are unchanged.

### Patch Changes

- Updated dependencies [06a14c8]
- Updated dependencies [430bb72]
  - @aegiskit/scanner@0.2.0
  - @aegiskit/dast@0.0.2

## 0.1.0

### Minor Changes

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

### Patch Changes

- Updated dependencies [c456706]
- Updated dependencies [20e9e2a]
- Updated dependencies [7724da1]
- Updated dependencies [42a3b97]
  - @aegiskit/scanner@0.1.0
  - @aegiskit/dast@0.0.1
