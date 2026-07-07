#!/usr/bin/env node
/**
 * `aegis-mcp` — the stdio entrypoint. Register Aegis as an MCP server in Claude Code / Cursor and the
 * agent gains `scan_project` + `explain_finding`. Stdout is reserved for the JSON-RPC transport, so any
 * diagnostics go to stderr; a failed startup exits non-zero so the host surfaces it.
 */

import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { createAegisMcpServer } from './server';

async function main(): Promise<void> {
  const server = createAegisMcpServer();
  await server.connect(new StdioServerTransport());
}

main().catch((error: unknown) => {
  process.stderr.write(`aegis-mcp: ${error instanceof Error ? error.message : String(error)}\n`);
  process.exit(1);
});
