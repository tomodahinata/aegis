import { forEachDescendant, ts } from '../internal/ast';
import { docsUrlFor, type Rule } from '../rule';

/**
 * Incomplete escaping in a hand-rolled `.replace()` sanitizer (CWE-116). When code backslash-escapes a
 * quote/backtick (`x.replace(/'/g, "\\'")`) to build a string/JS/shell fragment but does NOT escape the
 * backslash FIRST, the escaping is bypassable: an input `\` becomes `\'`, which closes the very quote the
 * escape was meant to protect. The order is load-bearing — `\` must be escaped before everything else.
 *
 * Detection is purely structural over the literal arguments of a fluent replace chain, so it is certain
 * (not heuristic): we flag only a chain that escapes a quote with a backslash while the backslash-escape
 * is missing or comes too late. Chains that escape the backslash first, that use HTML entities, or whose
 * arguments are not statically known are left silent (fail-secure — zero false positives over recall).
 */

const QUOTES: ReadonlySet<string> = new Set(["'", '"', '`']);
const BACKSLASH = '\\';
// Regex metacharacters: a single one of these in a regex body is NOT a literal character.
const REGEX_META: ReadonlySet<string> = new Set([
  '.',
  '^',
  '$',
  '*',
  '+',
  '?',
  '(',
  ')',
  '[',
  ']',
  '{',
  '}',
  '|',
  '\\',
]);

function isReplaceCall(node: ts.Node): node is ts.CallExpression {
  return (
    ts.isCallExpression(node) &&
    ts.isPropertyAccessExpression(node.expression) &&
    (node.expression.name.text === 'replace' || node.expression.name.text === 'replaceAll')
  );
}

/** The single character a replace `target` matches — from `/x/`, `/\x/`, or `'x'` — else undefined. */
function targetChar(target: ts.Expression | undefined): string | undefined {
  if (!target) {
    return undefined;
  }
  if (ts.isStringLiteralLike(target)) {
    return target.text.length === 1 ? target.text : undefined;
  }
  if (ts.isRegularExpressionLiteral(target)) {
    const slash = target.text.lastIndexOf('/');
    const body = slash > 0 ? target.text.slice(1, slash) : '';
    if (body.length === 1) {
      return REGEX_META.has(body) ? undefined : body; // a bare metachar is not a literal char
    }
    if (body.length === 2 && body[0] === BACKSLASH) {
      return body[1]; // an escaped metachar/quote, e.g. `\\` → `\`, `\.` → `.`
    }
  }
  return undefined;
}

/** The character that `node` backslash-escapes (replacement is exactly `\` + char), else undefined. */
function backslashEscapedChar(node: ts.CallExpression): string | undefined {
  const char = targetChar(node.arguments[0]);
  const replacement = node.arguments[1];
  if (char === undefined || !replacement || !ts.isStringLiteralLike(replacement)) {
    return undefined;
  }
  return replacement.text === BACKSLASH + char ? char : undefined;
}

/** Only the outermost link of a fluent `a.replace(…).replace(…)` chain (the rest are walked from it). */
function isOutermostReplace(node: ts.CallExpression): boolean {
  const parent = node.parent;
  return !(
    ts.isPropertyAccessExpression(parent) &&
    (parent.name.text === 'replace' || parent.name.text === 'replaceAll') &&
    ts.isCallExpression(parent.parent) &&
    parent.parent.expression === parent
  );
}

/** Strip redundant parentheses so a grouped receiver `(s.replace(…)).replace(…)` is still walked. */
function unwrapParens(node: ts.Expression): ts.Expression {
  let cur = node;
  while (ts.isParenthesizedExpression(cur)) {
    cur = cur.expression;
  }
  return cur;
}

/**
 * The escaped chars of the chain in EXECUTION order (inner call runs first). Walks DOWN the fluent
 * receiver chain, recording each `.replace` link, and STEPS THROUGH any interposed non-replace call
 * (`.trim()`, `.toLowerCase()`) or parentheses — otherwise an earlier backslash-escape would be dropped
 * and a correct backslash-first sanitizer (`s.replace(/\\/…).trim().replace(/'/…)`) falsely flagged.
 */
function chainEscapesInOrder(outermost: ts.CallExpression): (string | undefined)[] {
  const reverse: (string | undefined)[] = [];
  let cur: ts.Expression = outermost;
  for (;;) {
    cur = unwrapParens(cur);
    if (!ts.isCallExpression(cur) || !ts.isPropertyAccessExpression(cur.expression)) {
      break;
    }
    if (isReplaceCall(cur)) {
      reverse.push(backslashEscapedChar(cur));
    }
    cur = cur.expression.expression;
  }
  return reverse.reverse();
}

export const incompleteEscape: Rule = {
  meta: {
    id: 'sanitize/incomplete-escape',
    title: 'Backslash-escaping sanitizer that does not escape the backslash first',
    severity: 'HIGH',
    owasp: 'A03:2021 Injection',
    docsUrl: docsUrlFor('sanitize/incomplete-escape'),
  },
  appliesTo: (file) => file.text.includes('.replace'),
  check(ctx) {
    forEachDescendant(ctx.file.sourceFile, (node) => {
      if (!isReplaceCall(node) || !isOutermostReplace(node)) {
        return;
      }
      const escapes = chainEscapesInOrder(node);
      const firstQuote = escapes.findIndex((c) => c !== undefined && QUOTES.has(c));
      if (firstQuote === -1) {
        return; // not a backslash-escaping-quote sanitizer ⇒ out of scope
      }
      const backslashAt = escapes.indexOf(BACKSLASH);
      // Correct iff the backslash is escaped strictly before the first quote.
      if (backslashAt !== -1 && backslashAt < firstQuote) {
        return;
      }
      ctx.report({
        node,
        confidence: 'medium',
        message:
          "This sanitizer backslash-escapes a quote but does not escape the backslash first — an input `\\` becomes `\\'`, which escapes the escape and closes the quote, defeating the sanitizer (incomplete escaping, CWE-116).",
        remediation:
          'Escape the backslash before any other character: `s.replace(/\\\\/g, "\\\\\\\\").replace(/\'/g, "\\\\\'")`. Better, use a vetted encoder for the target context (JSON.stringify, a SQL driver\'s parameter binding, a shell-arg escaper) instead of hand-rolling.',
        evidence: '.replace() escape chain',
      });
    });
  },
};
