/**
 * `@aegiskit/mcp` — Aegis as a Model Context Protocol server. The binary is `./main.ts`; this entry
 * re-exports the server factory and the SDK-agnostic scan service for programmatic use and testing.
 */

export {
  explainFinding,
  type FindingDetail,
  type FindingRow,
  type ScanSummary,
  scanAndSummarize,
} from './scan-service';
export { createAegisMcpServer, SERVER_INFO } from './server';
