# @aegiskit/mcp

Aegis as a [Model Context Protocol](https://modelcontextprotocol.io) server. Add it to Claude Code, Cursor, or any MCP-capable agent and it gains two tools:

- **`scan_project`** — run the Aegis static scanner over a Next.js/Supabase project and return a prioritized summary of findings (RLS/authz correctness, secrets, CSP, injection…), each with a stable fingerprint.
- **`explain_finding`** — given a fingerprint, return the full explanation of *why* it is a gap and, for Supabase RLS owner-scoping gaps, a concrete corrected `CREATE POLICY` you can adapt and apply.

This lets a coding agent find and fix the exact class of bug that dominates real vibe-coded incidents — "RLS exists but doesn't scope rows to the owner" — without leaving the editor. Evidence for secret-bearing findings is redacted before it reaches the model.

> **Honest scope.** Aegis reports and explains; it does not "protect" your app, and a suggested policy is advisory — your agent or you apply it, so Aegis never silently rewrites your SQL. It complements secure design, code review, and testing; it does not replace them.

## Use with Claude Code

Add to your project's `.mcp.json`:

```json
{
  "mcpServers": {
    "aegis": { "command": "npx", "args": ["-y", "@aegiskit/mcp"] }
  }
}
```

## Use with Cursor

Add to `~/.cursor/mcp.json` (or the project `.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "aegis": { "command": "npx", "args": ["-y", "@aegiskit/mcp"] }
  }
}
```

The server scans the working directory by default; pass `path` to a tool to scan elsewhere.

## Related

- [`@aegiskit/cli`](../cli) — the same scanner on the command line and in CI (SARIF, baselines, compliance evidence).
- [`@aegiskit/scanner`](../scanner) — the analysis engine.
