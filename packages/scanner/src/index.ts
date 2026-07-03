/**
 * `@aegiskit/scanner` — static analysis that finds the security gaps a runtime library can't fix.
 *
 * It parses TypeScript/JSX, classifies each file's runtime context (server/client/edge) and
 * client-reachability, then runs a set of evidence-grounded rules. Confidence levels gate CI
 * so uncertain findings inform without breaking the build — the antidote to false-positive
 * fatigue.
 */

export {
  applyBaseline,
  type Baseline,
  type BaselineApplication,
  type BaselineEntry,
  buildBaseline,
  fingerprintFinding,
  parseBaseline,
  serializeBaseline,
} from './baseline';
export { classifyFile, type FileClassification, type RuntimeContext } from './classify';
export {
  type ComplianceFramework,
  SUPPORTED_FRAMEWORKS,
} from './compliance/controls';
export {
  buildComplianceReport,
  type ComplianceReport,
  type ControlEvidence,
  type ControlStatus,
} from './compliance/report';
export { type CorrelateRlsOptions, correlateRls } from './correlate-rls';
export { type ScanOptions, scan } from './engine';
export { applyTextEdits, type FilePlan, planFileFixes } from './fix';
export { parseSource } from './internal/ast';
export { findTaintFlows, traceOf } from './internal/dataflow';
export type { GrantInfo, PolicyInfo, RlsModel, SqlLocation, TableInfo } from './internal/sql/model';
export { buildRlsModel } from './internal/sql/model';
export type {
  SinkCategory,
  TaintFlow,
  TaintSanitizer,
  TaintSink,
  TaintSource,
  TaintSpec,
  TaintStep,
} from './internal/taint-descriptors';
export { toComplianceJson } from './reporters/compliance-json';
export { toComplianceMd } from './reporters/compliance-md';
export { toJson } from './reporters/json';
export { toSarif } from './reporters/sarif';
export { docsUrlFor, type FileInfo, type Rule, type RuleContext, type RuleMeta } from './rule';
export { ALL_RULES } from './rules';
export { type ScanSqlOptions, scanSql } from './scan-sql';
export type { SqlRule, SqlRuleContext, SqlRuleMeta } from './sql-rule';
export { ALL_SQL_RULES } from './sql-rules';
export {
  type AutoFix,
  type Confidence,
  emptySummary,
  type Finding,
  type Fix,
  type HttpExchange,
  meetsThreshold,
  type PassCheck,
  type ScanResult,
  SEVERITY_ORDER,
  type Severity,
  type SourceRange,
  type Summary,
  type TextEdit,
  type TraceStep,
} from './types';
