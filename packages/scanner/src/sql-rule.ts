/**
 * The SQL-analysis rule contract — the parallel of `Rule` for the cross-file RLS model. Separate from
 * `Rule` (SRP): a `Rule` reasons over a parsed TypeScript `FileInfo`; a `SqlRule` reasons over the
 * whole-project `RlsModel`. Both ultimately emit the same `Finding`, so all reporters/baseline reuse.
 */

import type { RlsModel, SqlLocation } from './internal/sql/model';
import type { Confidence, FindingExplanation, Severity } from './types';

export interface SqlRuleMeta {
  readonly id: string;
  readonly title: string;
  readonly severity: Severity;
  readonly owasp?: string;
  readonly docsUrl: string;
}

export interface SqlReportInput {
  readonly loc: SqlLocation;
  /** What is wrong and why, in one sentence. */
  readonly message: string;
  /** Imperative, copy-pasteable remediation. */
  readonly remediation: string;
  readonly confidence: Confidence;
  /** Override `meta.severity` for this finding (rare). */
  readonly severity?: Severity;
  readonly evidence?: string;
  /** Structured "why" + advisory corrected statement (see `FindingExplanation`). Omit when not derivable. */
  readonly explanation?: FindingExplanation;
}

export interface SqlRuleContext {
  readonly model: RlsModel;
  report(input: SqlReportInput): void;
}

/** A SQL rule evaluates the whole-project RLS model once and reports findings. */
export interface SqlRule {
  readonly meta: SqlRuleMeta;
  check(ctx: SqlRuleContext): void;
}
