/**
 * Intraprocedural taint engine. Within each function scope it tracks untrusted input from a SOURCE,
 * through assignments / destructuring / template+concat / property access / known pass-through
 * transforms, to a dangerous SINK — clearing taint when an adequate SANITIZER intervenes. No
 * type-checker, no CFG/SSA: a single source-ordered pass over each scope with name-based identity.
 * Every precision hazard (reassignment, shadowing, unknown call) degrades to a lower confidence or to
 * "not tainted", so an uncertain flow is surfaced without a build break and a flow it cannot prove is
 * simply not emitted — preserving the zero-false-positive gate.
 *
 * The honest scope: it reasons *within* a function. Flows that cross function or module boundaries are
 * out of range by design (the interprocedural extension is a separate, additive pass).
 */

import type { FileInfo } from '../rule';
import type { Confidence, TraceStep } from '../types';
import { rangeOf, ts } from './ast';
import {
  callLikeArguments,
  type SinkCategory,
  type TaintFlow,
  type TaintSanitizer,
  type TaintSource,
  type TaintSpec,
  type TaintStep,
  weaker,
} from './taint-descriptors';
import { PARAM_SOURCE_NAMES, passThroughSource, SANITIZERS, SOURCES } from './taint-registry';
import { buildScopeIndex, type FunctionScope, type ScopeIndex, walkScope } from './taint-scope';

export { buildScopeIndex, type ScopeIndex };

/** Guards against pathological generated code; a scope beyond this is skipped (emits nothing for it). */
const MAX_SCOPE_NODES = 5_000;
/** Bounds expression recursion (deeply nested concat/property chains). */
const MAX_EXPR_DEPTH = 40;

const NO_CATEGORIES: ReadonlySet<SinkCategory> = new Set();

/** Binary operators that carry an operand's taint to their result. */
const PROPAGATING_BINARY_OPS: ReadonlySet<ts.SyntaxKind> = new Set([
  ts.SyntaxKind.PlusToken,
  ts.SyntaxKind.QuestionQuestionToken,
  ts.SyntaxKind.BarBarToken,
  ts.SyntaxKind.AmpersandAmpersandToken,
]);

function union(
  a: ReadonlySet<SinkCategory>,
  b: ReadonlySet<SinkCategory>,
): ReadonlySet<SinkCategory> {
  if (a.size === 0) return b;
  if (b.size === 0) return a;
  return new Set([...a, ...b]);
}

/** A tainted value as it travels: where it came from, how confident we are, what it is now safe for. */
interface TaintInfo {
  readonly origin: ts.Node;
  readonly confidence: Confidence;
  readonly neutralized: ReadonlySet<SinkCategory>;
  readonly steps: readonly TaintStep[];
}

interface ScopeEnv {
  readonly sources: readonly TaintSource[];
  readonly sanitizers: readonly TaintSanitizer[];
  readonly scope: FunctionScope;
}

function step(node: ts.Node, kind: TaintStep['kind'], label: string): TaintStep {
  return { node, kind, label };
}

/** Compute the taint of an expression against the current name→taint state. `undefined` ⇒ clean. */
function taintOfExpr(
  expr: ts.Expression,
  state: ReadonlyMap<string, TaintInfo>,
  env: ScopeEnv,
  depth: number,
): TaintInfo | undefined {
  if (depth > MAX_EXPR_DEPTH) {
    return undefined;
  }
  // Transparent wrappers — see straight through them.
  if (
    ts.isParenthesizedExpression(expr) ||
    ts.isAwaitExpression(expr) ||
    ts.isNonNullExpression(expr) ||
    ts.isAsExpression(expr) ||
    ts.isSatisfiesExpression(expr)
  ) {
    return taintOfExpr(expr.expression, state, env, depth + 1);
  }

  for (const source of env.sources) {
    if (source.match(expr)) {
      return {
        origin: expr,
        confidence: source.confidence,
        neutralized: NO_CATEGORIES,
        steps: [step(expr, 'source', `tainted by ${source.label}`)],
      };
    }
  }

  if (ts.isIdentifier(expr)) {
    const info = state.get(expr.text);
    if (!info) {
      return undefined;
    }
    if (env.scope.symbols.ambiguous.has(expr.text) || env.scope.symbols.reassigned.has(expr.text)) {
      return { ...info, confidence: weaker(info.confidence, 'medium') };
    }
    return info;
  }

  if (ts.isCallExpression(expr) || ts.isNewExpression(expr)) {
    for (const sanitizer of env.sanitizers) {
      if (sanitizer.match(expr)) {
        const arg = (callLikeArguments(expr) ?? [])[sanitizer.argIndex];
        const inner = arg ? taintOfExpr(arg, state, env, depth + 1) : undefined;
        if (!inner) {
          return undefined; // sanitizing a clean value (or no arg) stays clean
        }
        return {
          ...inner,
          neutralized: union(inner.neutralized, sanitizer.neutralizes),
          steps: [...inner.steps, step(expr, 'propagation', `sanitized via ${sanitizer.label}`)],
        };
      }
    }
    if (ts.isCallExpression(expr)) {
      const through = passThroughSource(expr);
      if (through) {
        const inner = taintOfExpr(through.from, state, env, depth + 1);
        if (!inner) {
          return undefined;
        }
        return {
          ...inner,
          neutralized: through.clearsNeutralization ? NO_CATEGORIES : inner.neutralized,
          steps: [...inner.steps, step(expr, 'propagation', 'passed through a string transform')],
        };
      }
    }
    return undefined; // unknown call/new → treated as clean (fail-secure against guessing)
  }

  if (ts.isTemplateExpression(expr)) {
    for (const span of expr.templateSpans) {
      const inner = taintOfExpr(span.expression, state, env, depth + 1);
      if (inner) {
        // Neutralization is preserved: `\`id=${Number(x)}\`` stays safe; a raw value stays unsafe.
        return {
          ...inner,
          steps: [...inner.steps, step(expr, 'propagation', 'interpolated into a string')],
        };
      }
    }
    return undefined;
  }

  // `a + b` (concatenation) and the short-circuit operators `a ?? b` / `a || b` / `a && b` (the
  // ubiquitous `searchParams.get('x') ?? ''` fallback) all carry an operand's taint to the result.
  if (ts.isBinaryExpression(expr) && PROPAGATING_BINARY_OPS.has(expr.operatorToken.kind)) {
    const inner =
      taintOfExpr(expr.left, state, env, depth + 1) ??
      taintOfExpr(expr.right, state, env, depth + 1);
    if (inner) {
      const label =
        expr.operatorToken.kind === ts.SyntaxKind.PlusToken
          ? 'concatenated into a string'
          : 'carried through a fallback';
      return { ...inner, steps: [...inner.steps, step(expr, 'propagation', label)] };
    }
    return undefined;
  }

  // A projection of tainted data is tainted; a lookup into trusted data by a tainted *key* is not.
  if (ts.isPropertyAccessExpression(expr)) {
    const inner = taintOfExpr(expr.expression, state, env, depth + 1);
    return inner
      ? {
          ...inner,
          steps: [...inner.steps, step(expr, 'propagation', `property .${expr.name.text}`)],
        }
      : undefined;
  }
  if (ts.isElementAccessExpression(expr)) {
    const inner = taintOfExpr(expr.expression, state, env, depth + 1);
    return inner
      ? { ...inner, steps: [...inner.steps, step(expr, 'propagation', 'element access')] }
      : undefined;
  }

  return undefined;
}

function paramInfo(node: ts.Node): TaintInfo {
  return {
    origin: node,
    confidence: 'high',
    neutralized: NO_CATEGORIES,
    steps: [step(node, 'source', 'tainted by route parameter')],
  };
}

/** Seed taint for parameters whose bound name is a Next route input (`params`/`searchParams`). */
function seedParameter(name: ts.BindingName, state: Map<string, TaintInfo>): void {
  if (ts.isIdentifier(name)) {
    if (PARAM_SOURCE_NAMES.has(name.text)) {
      state.set(name.text, paramInfo(name));
    }
    return;
  }
  for (const element of name.elements) {
    if (ts.isBindingElement(element)) {
      seedParameter(element.name, state);
    }
  }
}

/** Bind every name introduced by a (possibly destructuring) declaration to a tainted value. */
function bindPattern(name: ts.BindingName, info: TaintInfo, state: Map<string, TaintInfo>): void {
  if (ts.isIdentifier(name)) {
    state.set(name.text, info);
    return;
  }
  for (const element of name.elements) {
    if (ts.isBindingElement(element)) {
      bindPattern(
        element.name,
        { ...info, steps: [...info.steps, step(element, 'propagation', 'destructured')] },
        state,
      );
    }
  }
}

function detectSinkFlows(
  node: ts.Node,
  state: ReadonlyMap<string, TaintInfo>,
  env: ScopeEnv,
  spec: TaintSpec,
  emit: (flow: TaintFlow) => void,
): void {
  for (const sink of spec.sinks) {
    for (const danger of sink.match(node)) {
      const info = taintOfExpr(danger, state, env, 0);
      if (!info) {
        continue;
      }
      emit({
        source: info.origin,
        sink: node,
        steps: [...info.steps, step(node, 'sink', sink.label)],
        sanitized: info.neutralized.has(sink.category),
        confidence: info.confidence,
      });
    }
  }
}

function analyzeScope(
  scope: FunctionScope,
  spec: TaintSpec,
  sources: ScopeEnv['sources'],
  emit: (flow: TaintFlow) => void,
): void {
  const env: ScopeEnv = {
    sources,
    sanitizers: SANITIZERS,
    scope,
  };
  const state = new Map<string, TaintInfo>();
  for (const param of scope.parameters) {
    seedParameter(param.name, state);
  }

  let visited = 0;
  let overBudget = false;
  walkScope(scope.body, (node) => {
    if (overBudget) {
      return;
    }
    visited += 1;
    if (visited > MAX_SCOPE_NODES) {
      overBudget = true;
      return;
    }
    // 1. Update state in source order, BEFORE any later sink reads it.
    if (ts.isVariableDeclaration(node) && node.initializer) {
      const info = taintOfExpr(node.initializer, state, env, 0);
      if (ts.isIdentifier(node.name)) {
        if (info) state.set(node.name.text, info);
        else state.delete(node.name.text);
      } else if (info) {
        bindPattern(node.name, info, state);
      }
    } else if (
      ts.isBinaryExpression(node) &&
      node.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
      ts.isIdentifier(node.left)
    ) {
      const info = taintOfExpr(node.right, state, env, 0);
      if (info) state.set(node.left.text, info);
      else state.delete(node.left.text);
    }
    // 2. A sink anywhere (including inside an initializer like `const r = fetch(x)`).
    detectSinkFlows(node, state, env, spec, emit);
  });
}

/** Stable key so the same source→sink pair (re-derivable along several node paths) emits once. */
function flowKey(flow: TaintFlow): string {
  return `${flow.source.getStart()}:${flow.source.getEnd()}->${flow.sink.getStart()}:${flow.sink.getEnd()}`;
}

/**
 * All taint flows for `spec` in `file`. Sanitized flows are returned too (so a rule can record a green
 * pass); a rule reports only `!sanitized` ones. Deterministically ordered by sink position.
 */
export function findTaintFlows(
  file: FileInfo,
  spec: TaintSpec,
  index?: ScopeIndex,
): readonly TaintFlow[] {
  const idx = index ?? buildScopeIndex(file.sourceFile);
  // Merge the spec's extra sources once per spec, not once per scope (it is constant for the spec).
  const sources: ScopeEnv['sources'] = spec.extraSources
    ? [...SOURCES, ...spec.extraSources]
    : SOURCES;
  const byKey = new Map<string, TaintFlow>();
  for (const scope of idx.scopes) {
    analyzeScope(scope, spec, sources, (flow) => {
      const key = flowKey(flow);
      if (!byKey.has(key)) {
        byKey.set(key, flow);
      }
    });
  }
  return [...byKey.values()].sort((a, b) => a.sink.getStart() - b.sink.getStart());
}

/** Resolve a flow's live AST steps into serializable trace steps for a `Finding`. */
export function traceOf(file: FileInfo, flow: TaintFlow): readonly TraceStep[] {
  return flow.steps.map((s) => ({
    kind: s.kind,
    label: s.label,
    range: rangeOf(file.sourceFile, s.node),
  }));
}
