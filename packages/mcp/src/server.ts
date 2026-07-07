/**
 * The Aegis MCP server: exposes the scanner to coding agents (Claude Code, Cursor, Windsurf) so a
 * developer can find and understand Supabase RLS/authz gaps without leaving the editor — and get an
 * LLM-ready corrected policy the agent can apply. Thin glue over `scan-service.ts` (which holds the
 * testable logic); this file only declares the tools, their schemas, and how results render to text.
 *
 * Honest scope (CLAUDE.md): the tools report and explain; they never claim to "protect" anything, and a
 * suggested policy is advisory (the agent/human applies it, so Aegis never silently rewrites your SQL).
 */

import { resolve } from 'node:path';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import {
  DEFAULT_SCAN_LIMIT,
  explainFinding,
  type FindingDetail,
  MAX_SCAN_LIMIT,
  type ScanSummary,
  scanAndSummarize,
} from './scan-service';

/**
 * Package identity reported to the MCP client. NOTE: `version` is a hand-maintained literal — nothing in
 * the build syncs it to package.json, so bump it here whenever package.json's version changes.
 */
export const SERVER_INFO = { name: 'aegis', version: '0.0.0' } as const;

function textResult(
  text: string,
  isError = false,
): {
  content: { type: 'text'; text: string }[];
  isError?: boolean;
} {
  return { content: [{ type: 'text', text }], ...(isError ? { isError: true } : {}) };
}

/**
 * Fail-secure tool error: the scan touches the filesystem and can throw (bad path, EACCES). We own the
 * error surface here rather than leaning on the SDK's wrapper — detail goes to stderr (stdout is the
 * JSON-RPC channel), and the agent gets a short message flagged as an error.
 */
function toolFailure(tool: string, cwd: string, error: unknown): ReturnType<typeof textResult> {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`aegis-mcp: ${tool} failed for ${cwd}: ${message}\n`);
  return textResult(`Aegis ${tool} failed: ${message}`, true);
}

function formatSummary(summary: ScanSummary): string {
  const { counts } = summary;
  const header =
    `Aegis scanned ${summary.scannedFiles} files — ${summary.total} finding${summary.total === 1 ? '' : 's'} ` +
    `(BLOCKER ${counts.BLOCKER}, HIGH ${counts.HIGH}, MEDIUM ${counts.MEDIUM}, LOW ${counts.LOW}, INFO ${counts.INFO}).`;
  if (summary.total === 0) {
    return `${header}\nNo findings. (Absence of Aegis-detectable gaps — not proof the app is secure.)`;
  }
  const rows = summary.findings.map(
    (f, i) =>
      `${i + 1}. [${f.severity}/${f.confidence}] ${f.ruleId} — ${f.location}\n` +
      `   ${f.message}\n   fingerprint: ${f.fingerprint}`,
  );
  const note = summary.truncated
    ? `\n(Showing the top ${summary.findings.length} of ${summary.total}. Raise \`limit\` to see more.)`
    : '';
  return `${header}\n\n${rows.join('\n')}\n${note}\nCall explain_finding with a fingerprint for the full explanation and a suggested fix.`;
}

function formatDetail(detail: FindingDetail): string {
  const lines = [
    `${detail.ruleId} [${detail.severity}/${detail.confidence}] — ${detail.location}`,
    '',
    detail.message,
  ];
  if (detail.explanation) {
    lines.push('', `Why: ${detail.explanation.detail}`);
    if (detail.explanation.suggestedFix) {
      lines.push(
        '',
        'Suggested fix (advisory — review before applying):',
        '',
        detail.explanation.suggestedFix,
      );
    }
  }
  lines.push('', `Remediation: ${detail.remediation}`);
  if (detail.owasp) {
    lines.push(`OWASP: ${detail.owasp}`);
  }
  lines.push(`Docs: ${detail.docsUrl}`);
  return lines.join('\n');
}

/**
 * Build the Aegis MCP server with its tools registered. Exported (not just run) so tests can connect an
 * in-memory client and exercise the tool handlers without a real stdio transport.
 */
export function createAegisMcpServer(): McpServer {
  const server = new McpServer(SERVER_INFO);

  server.registerTool(
    'scan_project',
    {
      title: 'Scan a project for security gaps',
      description:
        'Run the Aegis static scanner over a Next.js/Supabase project and return a prioritized summary ' +
        'of findings (RLS/authz correctness, secrets, CSP, injection…). Each finding carries a fingerprint ' +
        'to pass to explain_finding.',
      inputSchema: {
        path: z
          .string()
          .optional()
          .describe('Project root to scan. Defaults to the server working directory.'),
        limit: z
          .number()
          .int()
          .min(1)
          .max(MAX_SCAN_LIMIT)
          .optional()
          .describe(
            `Max findings to return, highest severity first (default ${DEFAULT_SCAN_LIMIT}).`,
          ),
      },
    },
    (args) => {
      const cwd = resolve(args.path ?? process.cwd());
      try {
        return textResult(formatSummary(scanAndSummarize(cwd, args.limit)));
      } catch (error) {
        return toolFailure('scan_project', cwd, error);
      }
    },
  );

  server.registerTool(
    'explain_finding',
    {
      title: 'Explain a finding and suggest a fix',
      description:
        'Return the full explanation for one finding (by fingerprint from scan_project): why it is a gap ' +
        'and, for RLS owner-scoping gaps, a concrete corrected CREATE POLICY you can adapt and apply.',
      inputSchema: {
        fingerprint: z.string().describe('The finding fingerprint from scan_project.'),
        path: z
          .string()
          .optional()
          .describe('Project root that was scanned. Defaults to the server working directory.'),
      },
    },
    (args) => {
      const cwd = resolve(args.path ?? process.cwd());
      try {
        const detail = explainFinding(cwd, args.fingerprint);
        if (detail === undefined) {
          return textResult(
            `No finding with fingerprint ${args.fingerprint} in ${cwd}. Re-run scan_project — the code may have changed.`,
            true,
          );
        }
        return textResult(formatDetail(detail));
      } catch (error) {
        return toolFailure('explain_finding', cwd, error);
      }
    },
  );

  return server;
}
