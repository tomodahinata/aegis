/**
 * The single shape every taint-powered rule shares: declare sinks (a `TaintSpec`) and the copy, and
 * this factory turns each unsanitized source→sink flow into a finding (carrying its dataflow trace)
 * and each sanitized flow into a green pass. Keeping it in one place means a new injection rule is
 * just sinks + words — no detection logic to re-derive (DRY/ETC).
 */

import { traceOf } from '../internal/dataflow';
import type { TaintSpec } from '../internal/taint-descriptors';
import { weaker } from '../internal/taint-descriptors';
import type { FileInfo, Rule, RuleMeta } from '../rule';
import type { Confidence } from '../types';

export interface TaintRuleConfig {
  readonly meta: RuleMeta;
  readonly spec: TaintSpec;
  /** Cheap pre-filter — typically a `file.text.includes('<sink token>')` gate. */
  readonly appliesTo: (file: FileInfo) => boolean;
  /** One sentence: what is wrong and the consequence. */
  readonly message: string;
  /** Imperative, copy-pasteable remediation. */
  readonly remediation: string;
  /** Green-check text for a flow proven sanitized. */
  readonly passDetail: string;
  /**
   * Ceiling on per-finding confidence. Use for rules whose safe pattern is genuinely hard to prove
   * syntactically (e.g. open redirect, where a relative target is fine) so they inform without
   * blocking CI. Omit for rules whose sinks are unambiguous.
   */
  readonly maxConfidence?: Confidence;
}

export function defineTaintRule(config: TaintRuleConfig): Rule {
  return {
    meta: config.meta,
    appliesTo: config.appliesTo,
    check(ctx) {
      for (const flow of ctx.taint(config.spec)) {
        if (flow.sanitized) {
          ctx.pass(config.passDetail);
          continue;
        }
        const confidence = config.maxConfidence
          ? weaker(flow.confidence, config.maxConfidence)
          : flow.confidence;
        ctx.report({
          node: flow.sink,
          confidence,
          message: config.message,
          remediation: config.remediation,
          evidence: flow.source.getText(ctx.file.sourceFile),
          trace: traceOf(ctx.file, flow),
        });
      }
    },
  };
}
