---
"@aegiskit/scanner": minor
"@aegiskit/cli": minor
"@aegiskit/mcp": minor
---

Explain and deliver the RLS/authz moat: suggested fixes, compliance evidence v2, and an MCP server.

- **RLS explainability (scanner/cli):** `rls/policy-not-owner-scoped` findings now carry a structured `explanation` (why the policy fails, its predicate class) and a concrete, owner-scoped `CREATE POLICY` suggestion bound to the table's real ownership column — rendered in the pretty (incl. `--plain`), JSON, and SARIF reporters. Directly answers the top community ask: "tell me why my RLS fails, and how to fix it."
- **Compliance evidence v2 (scanner/cli):** `aegis report --format html` renders a self-contained, print-ready, WCAG-AA control-evidence document. New `--record`/`--history` flags maintain an append-only scan-history ledger, and the HTML report gains a remediation-tracking section (first-seen / resolved / mean-time-to-remediate) — the remediation-over-time evidence SOC 2 CC7.1 auditors require.
- **New `@aegiskit/mcp` package:** Aegis as a Model Context Protocol server (`scan_project`, `explain_finding`) so Claude Code / Cursor users find and fix Supabase RLS/authz gaps in-editor, with secret evidence redacted before it reaches the model.
