# @aegiskit/mcp

## 0.1.0

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
  - @aegiskit/cli@0.3.0
