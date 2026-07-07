/** Severity ordered from most to least urgent. */
export type Severity = 'BLOCKER' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

/**
 * Confidence gates CI: only `high`-confidence findings fail a build by default. This is the
 * primary lever against the #1 scanner failure mode — false positives eroding trust.
 */
export type Confidence = 'high' | 'medium' | 'low';

export const SEVERITY_ORDER: readonly Severity[] = ['BLOCKER', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

/** A single replacement of `[start, end)` (UTF-16 offsets into the ORIGINAL file text). */
export interface TextEdit {
  readonly start: number;
  readonly end: number;
  readonly newText: string;
}

/**
 * A provably-safe, machine-applicable fix. Only emitted when the code shape is unambiguous;
 * anything requiring human judgement carries no `Fix` and is remediated via `Finding.remediation`
 * ("guided"). This is the toolkit's honest-scope line drawn in the type system.
 */
export interface AutoFix {
  readonly kind: 'auto';
  /** Human-readable summary, e.g. "Wrap POST with secureRoute (origin check on)". */
  readonly title: string;
  readonly edits: readonly TextEdit[];
}

export type Fix = AutoFix;

export interface SourceRange {
  /** 1-based. */
  readonly startLine: number;
  /** 1-based. */
  readonly startColumn: number;
  readonly endLine: number;
  readonly endColumn: number;
}

/**
 * One hop in a dataflow (taint) trace: where untrusted input entered, how it travelled, and the
 * dangerous sink it reached. Serializable by construction (a resolved `range`, never an AST node) so
 * it survives JSON/SARIF output. Rendered as a numbered source→sink path in the terminal and as a
 * SARIF `threadFlow`, giving a security finding its single most useful property — the actual path.
 */
export interface TraceStep {
  readonly kind: 'source' | 'propagation' | 'sink';
  /** Human-readable description, e.g. "tainted by req.json()" or "reaches supabase.rpc(...)". */
  readonly label: string;
  readonly range: SourceRange;
}

/**
 * The HTTP exchange that a dynamic (DAST) probe used to confirm a finding at runtime. Present only on
 * findings produced by `@aegiskit/dast`; absent on every static finding, so the two serialize and render
 * through the same reporters. Bodies are truncated and secret-redacted before they reach here.
 */
export interface HttpExchange {
  readonly kind: 'http-request';
  readonly method: string;
  /** Request path + query, e.g. `/api/search?q=…`. The origin lives in the finding's `file`. */
  readonly path: string;
  readonly request?: {
    readonly headers?: Readonly<Record<string, string>>;
    readonly body?: string;
  };
  readonly response?: {
    readonly status: number;
    readonly headers?: Readonly<Record<string, string>>;
    readonly body?: string;
  };
}

/**
 * A structured, plain-language explanation of WHY a finding is a gap, plus — when Aegis can derive one — a
 * concrete corrected statement to adapt. Present only on findings whose rule can prove the "why" (currently
 * the RLS owner-scoping rule), so every other finding serializes and renders byte-identically (mirrors
 * `trace?`/`target?`). The `suggestedFix` is ADVISORY: a starting point for the reader, never an automatic
 * edit — Aegis cannot know your intended ownership semantics, so it does not ship as a machine-applied `fix`.
 */
export interface FindingExplanation {
  /** Stable machine token for the kind of gap, e.g. the RLS predicate class `authenticated-only`. */
  readonly kind: string;
  /** One or two sentences: the proof the code DOES carry vs the binding it is MISSING. */
  readonly detail: string;
  /** A copy-pasteable corrected statement (e.g. an owner-scoped CREATE POLICY), when derivable. */
  readonly suggestedFix?: string;
}

export interface Finding {
  readonly ruleId: string;
  readonly severity: Severity;
  readonly confidence: Confidence;
  /** What is wrong and why, in one sentence. */
  readonly message: string;
  /** Absolute path of the offending file. */
  readonly file: string;
  readonly range: SourceRange;
  readonly docsUrl: string;
  /** Imperative, copy-pasteable guidance. */
  readonly remediation: string;
  readonly owasp?: string;
  /** The matched source slice, for trust/debugging. */
  readonly evidence?: string;
  /** Present only when included via `showSuppressed`: this finding was muted by a directive. */
  readonly suppressed?: boolean;
  /** A safe auto-fix, resolved only when scanning with `computeFixes`. Absent ⇒ remediate manually. */
  readonly fix?: Fix;
  /**
   * Source→sink dataflow path, present only on findings produced by a taint rule. Absent on every
   * syntactic rule, so existing findings serialize and render byte-identically.
   */
  readonly trace?: readonly TraceStep[];
  /**
   * The HTTP exchange that confirmed this finding at runtime, present only on dynamic (DAST) findings.
   * When set, `file` is the target URL (not a source path) and `range` is synthetic. Absent on every
   * static finding, so existing findings render byte-identically.
   */
  readonly target?: HttpExchange;
  /**
   * A structured "why this is a gap" plus an advisory corrected statement. Present only on findings whose
   * rule can prove the explanation (the RLS owner-scoping rule); absent elsewhere, so findings without it
   * serialize and render byte-identically.
   */
  readonly explanation?: FindingExplanation;
}

/** A check that confirmed a *good* practice — rendered green, never a failure. Builds trust. */
export interface PassCheck {
  readonly ruleId: string;
  readonly title: string;
  readonly detail: string;
  readonly file?: string;
}

export type Summary = Record<Severity, number>;

export interface ScanResult {
  readonly findings: readonly Finding[];
  readonly passes: readonly PassCheck[];
  readonly summary: Summary;
  readonly scannedFiles: number;
  readonly durationMs: number;
  /** Number of findings muted by inline `// aegis-disable-*` directives. */
  readonly suppressedCount: number;
}

export function emptySummary(): Summary {
  return { BLOCKER: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
}

const SEVERITY_RANK: Record<Severity, number> = {
  BLOCKER: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3,
  INFO: 4,
};

/** True when `severity` is at least as severe as `threshold`. */
export function meetsThreshold(severity: Severity, threshold: Severity): boolean {
  return SEVERITY_RANK[severity] <= SEVERITY_RANK[threshold];
}
