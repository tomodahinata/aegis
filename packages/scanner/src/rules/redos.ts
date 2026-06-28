import { forEachDescendant, ts } from '../internal/ast';
import { classifyRegex, type RegexComplexity } from '../internal/redos';
import type { TaintSink } from '../internal/taint-descriptors';
import { docsUrlFor } from '../rule';
import { defineTaintRule } from './taint-rule';

/** Methods whose RECEIVER is the matched string and whose first argument is the regex. */
const SUBJECT_METHODS: ReadonlySet<string> = new Set([
  'match',
  'matchAll',
  'search',
  'split',
  'replace',
  'replaceAll',
]);
/** Methods whose RECEIVER is the regex and whose first argument is the matched string. */
const REGEX_RECEIVER_METHODS: ReadonlySet<string> = new Set(['test', 'exec']);

/** The pattern body of a regex literal `/…/flags`, without delimiters or flags. */
function literalPattern(text: string): string | undefined {
  const lastSlash = text.lastIndexOf('/');
  return lastSlash > 0 ? text.slice(1, lastSlash) : undefined;
}

/** `new RegExp('…')` / `RegExp('…')` with a *string-literal* pattern (the only statically known form). */
function regExpCtorPattern(node: ts.Expression): string | undefined {
  if (!ts.isNewExpression(node) && !ts.isCallExpression(node)) {
    return undefined;
  }
  const callee = node.expression;
  if (!(ts.isIdentifier(callee) && callee.text === 'RegExp')) {
    return undefined;
  }
  const first = node.arguments?.[0];
  return first && ts.isStringLiteralLike(first) ? first.text : undefined;
}

/** A regex pattern from an inline literal or `new RegExp('literal')`; otherwise undefined. */
function inlinePattern(node: ts.Expression): string | undefined {
  if (ts.isRegularExpressionLiteral(node)) {
    return literalPattern(node.text);
  }
  return regExpCtorPattern(node);
}

// Per-file map of `const NAME = /…/` (or `= new RegExp('…')`) → its pattern. A name declared more than
// once maps to `null` (ambiguous ⇒ unresolved, fail-secure). Built once per source file, then memoized.
const FILE_REGEX_BINDINGS = new WeakMap<ts.SourceFile, Map<string, string | null>>();

function regexBindings(sourceFile: ts.SourceFile): Map<string, string | null> {
  const cached = FILE_REGEX_BINDINGS.get(sourceFile);
  if (cached) {
    return cached;
  }
  const map = new Map<string, string | null>();
  forEachDescendant(sourceFile, (node) => {
    if (!ts.isVariableDeclaration(node) || !ts.isIdentifier(node.name) || !node.initializer) {
      return;
    }
    // Only `const`: a `let`/`var` regex can be reassigned to a safe pattern later, so resolving its
    // declaration-time value would risk a false positive. Const is immutable ⇒ the value is the value.
    if (!(node.parent.flags & ts.NodeFlags.Const)) {
      return;
    }
    const pattern = inlinePattern(node.initializer);
    if (pattern === undefined) {
      return;
    }
    const name = node.name.text;
    map.set(name, map.has(name) ? null : pattern);
  });
  FILE_REGEX_BINDINGS.set(sourceFile, map);
  return map;
}

/** Resolve a regex operand to its static pattern: inline literal, `new RegExp('…')`, or a const binding. */
function patternOf(node: ts.Expression, sourceFile: ts.SourceFile): string | undefined {
  const inline = inlinePattern(node);
  if (inline !== undefined) {
    return inline;
  }
  if (ts.isIdentifier(node)) {
    return regexBindings(sourceFile).get(node.text) ?? undefined;
  }
  return undefined;
}

/**
 * A taint sink: the matched-string operand of a regex op, returned ONLY when the regex's worst-case
 * complexity equals `target`. One factory keeps the exponential and quadratic rules byte-identical except
 * for the class they hunt (DRY) — both reuse the same operand resolution and method handling.
 */
function regexSink(target: RegexComplexity): TaintSink {
  return {
    id: `redos.${target}`,
    category: 'redos',
    label: `matched against a ${target} regex`,
    match: (node) => {
      if (!ts.isCallExpression(node) || !ts.isPropertyAccessExpression(node.expression)) {
        return [];
      }
      const method = node.expression.name.text;
      const onSubject = SUBJECT_METHODS.has(method);
      if (!onSubject && !REGEX_RECEIVER_METHODS.has(method)) {
        return [];
      }
      const subject = onSubject ? node.expression.expression : node.arguments[0];
      const regex = onSubject ? node.arguments[0] : node.expression.expression;
      if (!subject || !regex) {
        return [];
      }
      const pattern = patternOf(regex, node.getSourceFile());
      return pattern !== undefined && classifyRegex(pattern) === target ? [subject] : [];
    },
  };
}

const REGEX_OP = /\.(?:test|exec|match|matchAll|search|split|replace|replaceAll)\s*\(/;

export const redos = defineTaintRule({
  meta: {
    id: 'redos/super-linear-regex',
    title: 'Untrusted input matched against a catastrophic regex (ReDoS)',
    severity: 'HIGH',
    owasp: 'A06:2021 Vulnerable and Outdated Components',
    docsUrl: docsUrlFor('redos/super-linear-regex'),
  },
  appliesTo: (file) => REGEX_OP.test(file.text),
  spec: { sinks: [regexSink('exponential')] },
  message:
    'Untrusted input is matched against a regex with catastrophic (exponential) backtracking — a short crafted string forces the engine into exponential work, pinning the request thread at 100% CPU (ReDoS, a denial of service).',
  remediation:
    'Remove the nested unbounded quantifier (e.g. `(a+)+` → `a+`) or the overlapping alternation (e.g. `(\\w|\\d)` → `\\w`), make the inner quantifier possessive/atomic, or match with a linear engine (RE2). Bounding input length alone does NOT stop exponential backtracking.',
  passDetail:
    'Input reaching this regex is constrained by a validator or numeric cast before matching.',
});

export const redosQuadratic = defineTaintRule({
  meta: {
    id: 'redos/quadratic-regex',
    title: 'Untrusted input matched against a quadratic regex (ReDoS)',
    // MEDIUM: O(n²) needs a large input to hurt, and the taint layer already suppresses length-bounded /
    // validated input — so a finding here is unbounded attacker input reaching a quadratic matcher.
    severity: 'MEDIUM',
    owasp: 'A06:2021 Vulnerable and Outdated Components',
    docsUrl: docsUrlFor('redos/quadratic-regex'),
  },
  appliesTo: (file) => REGEX_OP.test(file.text),
  spec: { sinks: [regexSink('quadratic')] },
  message:
    'Untrusted input is matched against a regex with quadratic (O(n²)) backtracking — two adjacent unbounded quantifiers over overlapping characters, pinned by an end anchor, re-partition on a failing match. A large input (no length limit) degrades to seconds of CPU per request (ReDoS).',
  remediation:
    'Collapse the adjacent quantifiers (e.g. `\\d+\\d+$` → `\\d+$`), anchor more tightly, or validate/cap the input length before matching. Prefer a linear engine (RE2) for untrusted input.',
  passDetail:
    'Input reaching this regex is constrained by a validator or numeric cast before matching.',
});
