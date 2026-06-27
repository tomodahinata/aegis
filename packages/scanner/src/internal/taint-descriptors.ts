/**
 * Vocabulary of the taint engine: what a *source* (untrusted input), a *sanitizer* (a transform that
 * renders input safe), and a *sink* (a dangerous operation) are. Pure types plus two generic AST
 * helpers — no traversal, no registry data (that lives in `taint-registry.ts`), no algorithm (that
 * lives in `dataflow.ts`). Splitting the vocabulary from the algorithm keeps "is `req.json()` a
 * source?" a one-line data edit that never touches the fixpoint.
 */

import type { Confidence } from '../types';
import { ts } from './ast';

/**
 * The injection class a sink is vulnerable to. A sanitizer neutralizes a sink *only* if it covers the
 * sink's category — this is how the engine models the fact that `encodeURIComponent` makes a value
 * safe for a URL but not for SQL, while `Number()` makes it safe everywhere. Set membership, not a
 * sanitizer×sink matrix (KISS).
 */
export type SinkCategory = 'sql' | 'html' | 'url' | 'fs-path' | 'shell' | 'code';

export const ALL_SINK_CATEGORIES: ReadonlySet<SinkCategory> = new Set<SinkCategory>([
  'sql',
  'html',
  'url',
  'fs-path',
  'shell',
  'code',
]);

/** A source of untrusted input — an expression node that introduces taint. */
export interface TaintSource {
  readonly id: string;
  /** Human label for the trace, e.g. "URL query parameter". */
  readonly label: string;
  readonly match: (node: ts.Node) => boolean;
  /** How sure we are this is attacker-controlled. Caps the final flow confidence (fail-secure). */
  readonly confidence: Confidence;
}

/**
 * A sanitizer call/construction that renders its `argIndex`-th argument safe for the categories it
 * `neutralizes`, returning the sanitized value. An empty `neutralizes` set models an *identity cast*
 * that sanitizes nothing (e.g. `String(x)`) — encoded as data so the engine never mistakes a cast for
 * safety.
 */
export interface TaintSanitizer {
  readonly id: string;
  readonly label: string;
  /** Matches a `CallExpression` or `NewExpression` (e.g. `new URL(x, BASE)`). */
  readonly match: (node: ts.CallExpression | ts.NewExpression) => boolean;
  readonly argIndex: number;
  readonly neutralizes: ReadonlySet<SinkCategory>;
}

/**
 * A dangerous operation. `match` returns the argument expression(s) that must be untainted (empty ⇒
 * this node is not the sink). Returning the dangerous sub-expressions unifies call sinks
 * (`fetch(url)`) and assignment sinks (`el.innerHTML = x`) under one shape.
 */
export interface TaintSink {
  readonly id: string;
  readonly category: SinkCategory;
  /** Human label for the trace, e.g. "reaches fetch()". */
  readonly label: string;
  readonly match: (node: ts.Node) => readonly ts.Expression[];
}

/** A rule's declaration of what it hunts: its sinks, plus any sources beyond the shared registry. */
export interface TaintSpec {
  readonly sinks: readonly TaintSink[];
  readonly extraSources?: readonly TaintSource[];
}

/** One hop in a flow, carrying the live AST node (resolved to a `SourceRange` only at the boundary). */
export interface TaintStep {
  readonly node: ts.Node;
  readonly kind: 'source' | 'propagation' | 'sink';
  readonly label: string;
}

/** A detected path from a source to a sink. `sanitized` ⇒ an adequate sanitizer intervened. */
export interface TaintFlow {
  readonly source: ts.Node;
  readonly sink: ts.Node;
  /** Ordered source → … → sink; `steps[0].kind === 'source'`, last is `'sink'`. */
  readonly steps: readonly TaintStep[];
  readonly sanitized: boolean;
  readonly confidence: Confidence;
}

/** Arguments of a call or `new` expression, or `undefined` if `node` is neither. */
export function callLikeArguments(node: ts.Node): readonly ts.Expression[] | undefined {
  if (ts.isCallExpression(node) || ts.isNewExpression(node)) {
    return node.arguments ?? [];
  }
  return undefined;
}

const CONFIDENCE_RANK: Record<Confidence, number> = { high: 0, medium: 1, low: 2 };

/** The weaker of two confidences (fail-secure: ambiguity only ever lowers certainty). */
export function weaker(a: Confidence, b: Confidence): Confidence {
  return CONFIDENCE_RANK[a] >= CONFIDENCE_RANK[b] ? a : b;
}
