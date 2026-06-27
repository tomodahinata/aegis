# @aegiskit/next

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

### Patch Changes

- Updated dependencies [20e9e2a]
- Updated dependencies [7724da1]
  - @aegiskit/core@0.1.0
