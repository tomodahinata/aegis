# @aegiskit/scanner

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
