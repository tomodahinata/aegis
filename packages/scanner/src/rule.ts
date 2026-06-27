import type ts from 'typescript';
import type { FileClassification } from './classify';
import type { ImportBinding } from './internal/ast';
import type { TaintFlow, TaintSpec } from './internal/taint-descriptors';
import type { Confidence, Fix, Severity, TraceStep } from './types';

export interface FileInfo {
  readonly path: string;
  readonly text: string;
  readonly sourceFile: ts.SourceFile;
  readonly classification: FileClassification;
  readonly imports: readonly ImportBinding[];
  /** True if some Client Component imports this module (transitively). */
  readonly reachableFromClient: boolean;
}

export interface RuleMeta {
  readonly id: string;
  readonly title: string;
  readonly severity: Severity;
  readonly owasp?: string;
  readonly docsUrl: string;
}

export interface ReportInput {
  readonly node: ts.Node;
  readonly message: string;
  readonly remediation: string;
  readonly confidence: Confidence;
  /**
   * Override `meta.severity` for this one finding. Use when a single rule spans a range of impact
   * decided per match — e.g. CSP `'unsafe-inline'` is HIGH in `script-src` but MEDIUM in `style-src`.
   * Omit to inherit `meta.severity` (the common case).
   */
  readonly severity?: Severity;
  readonly evidence?: string;
  /**
   * Lazily compute a safe auto-fix. The engine invokes this **only** under `computeFixes`, so a
   * normal scan/CI run pays nothing. Return `undefined` when no provably-safe transform applies —
   * the finding then falls back to guided remediation. Keeping the fix here co-locates it with the
   * detection that understands the offending shape.
   */
  readonly fix?: () => Fix | undefined;
  /** Source→sink dataflow path for a taint finding (build via `ctx.taint` + `traceOf`). */
  readonly trace?: readonly TraceStep[];
}

export interface RuleContext {
  readonly file: FileInfo;
  readonly files: ReadonlyMap<string, FileInfo>;
  /** Resolve a local identifier to its import binding (its origin module + exported name). */
  resolveBinding(localName: string): ImportBinding | undefined;
  /**
   * Resolve an import specifier (e.g. `@/lib/auth`) to the scanned `FileInfo` it points at, or
   * undefined for an external/unresolvable module. Reuses the engine's alias-aware module graph, so a
   * rule can follow a call one hop into a same-project helper (depth-1, fail-secure interprocedural).
   */
  resolveModule(specifier: string): FileInfo | undefined;
  /**
   * Intraprocedural taint flows for `spec` in this file. Memoized per scan (the scope index is built
   * once per file and shared across taint rules), so calling it from several rules is cheap.
   */
  taint(spec: TaintSpec): readonly TaintFlow[];
  report(input: ReportInput): void;
  /** Record a confirmed good practice (rendered green; never a failure). */
  pass(detail: string): void;
}

/**
 * A rule is one file. `appliesTo` is a cheap pre-filter so most files skip the rule entirely;
 * `check` is pure (reads `ctx`, calls `report`/`pass`) and runs independently per file.
 */
export interface Rule {
  readonly meta: RuleMeta;
  appliesTo(file: FileInfo): boolean;
  check(ctx: RuleContext): void;
}

/** Build a canonical docs URL for a rule id. */
export function docsUrlFor(ruleId: string): string {
  return `https://aegis.dev/rules/${ruleId.replace(/\//g, '-')}`;
}
