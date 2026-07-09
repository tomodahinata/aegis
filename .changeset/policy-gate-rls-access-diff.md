---
"@aegiskit/policy-diff": minor
"@aegiskit/scanner": minor
"@aegiskit/cli": minor
"@aegiskit/mcp": minor
---

Aegis Policy Gate: a semantic RLS access diff that answers the one question a migration PR review asks — "did this change widen who can read or write what?" — and fails closed on anything it cannot verify.

- **New `@aegiskit/policy-diff` package:** `diffAccess` compares the Supabase RLS surface (policies, RLS state, table grants) of two migration states over a role-aware breadth lattice (`none ⊂ own/state/delegated ⊂ all`). `widening` is claimed only for superset-or-equal moves, `narrowing` only for subset-or-equal, and everything unverifiable (untrusted custom functions, over-long/incomparable predicates, uninterpreted statements) is `requires-review` — never a false "no change". `renderDeltaMarkdown` produces the sticky PR-comment body, hardened against markdown/HTML injection from attacker-authored SQL.
- **`@aegiskit/scanner`:** fail-open closure of the RLS model — final-state `DISABLE RLS`, `REVOKE` (full vs. partial), `ALTER POLICY RENAME`, storage-schema policies, and an `uninterpreted` record for anything access-relevant the model could not read. `customCallsIn` / `PredicateClass` are now part of the public contract (consumed by `policy-diff`).
- **`@aegiskit/cli`:** new `aegis diff --base <ref> [--head <ref>] [--trust <fn>] [--format pretty|markdown|json]` — reads authoritative SQL at a git ref via `ls-tree`/`show` (no checkout), exits `1` on high-severity widenings (`--strict` also fails on notice-level attention).
- **GitHub Action + `@aegiskit/mcp`:** `policy-diff: true` posts the access delta as a sticky PR comment and exposes a `policy-diff-conclusion` output; the MCP server gains `explain_policy_diff` so Claude Code / Cursor can cite a reproducible delta.
