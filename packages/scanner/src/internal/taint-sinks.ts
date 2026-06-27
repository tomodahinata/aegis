/**
 * Reusable builders for the common sink shapes, so each taint rule declares its dangerous operations
 * as data rather than re-implementing AST matching. A sink's `match` returns the argument
 * expression(s) that must be untainted — the engine then asks the dataflow whether any is reached by
 * an unsanitized source.
 */

import { ts } from './ast';
import type { SinkCategory, TaintSink } from './taint-descriptors';

type ArgSelector = 'all' | readonly number[];

function pickArgs(args: readonly ts.Expression[], which: ArgSelector): readonly ts.Expression[] {
  if (which === 'all') {
    return args;
  }
  return which.map((i) => args[i]).filter((e): e is ts.Expression => e !== undefined);
}

/** `name(...)` — a bare function call (e.g. `fetch(url)`, `eval(code)`). */
export function identCallSink(
  id: string,
  category: SinkCategory,
  label: string,
  names: ReadonlySet<string>,
  which: ArgSelector,
): TaintSink {
  return {
    id,
    category,
    label,
    match: (node) =>
      ts.isCallExpression(node) &&
      ts.isIdentifier(node.expression) &&
      names.has(node.expression.text)
        ? pickArgs(node.arguments, which)
        : [],
  };
}

/**
 * `receiver.method(...)` — a method call by name (e.g. `axios.get(url)`, `fs.readFile(path)`).
 *
 * `receiverMatches` (optional) further constrains the call to a specific receiver shape. It is what
 * separates a genuinely dangerous `document.write(...)` from the many innocuous `.write()` methods that
 * share the name (`process.stdout.write`, a Node stream/socket, `res.write`, a file handle) — without it
 * a bare method-name match flags those as DOM sinks (a real false positive). Omitted ⇒ any receiver.
 */
export function methodCallSink(
  id: string,
  category: SinkCategory,
  label: string,
  methods: ReadonlySet<string>,
  which: ArgSelector,
  receiverMatches?: (receiver: ts.Expression) => boolean,
): TaintSink {
  return {
    id,
    category,
    label,
    match: (node) =>
      ts.isCallExpression(node) &&
      ts.isPropertyAccessExpression(node.expression) &&
      methods.has(node.expression.name.text) &&
      (receiverMatches === undefined || receiverMatches(node.expression.expression))
        ? pickArgs(node.arguments, which)
        : [],
  };
}

/** `new Name(...)` — a construction (e.g. `new Function(code)`). */
export function newExprSink(
  id: string,
  category: SinkCategory,
  label: string,
  names: ReadonlySet<string>,
  which: ArgSelector,
): TaintSink {
  return {
    id,
    category,
    label,
    match: (node) =>
      ts.isNewExpression(node) &&
      ts.isIdentifier(node.expression) &&
      names.has(node.expression.text)
        ? pickArgs(node.arguments ?? [], which)
        : [],
  };
}

/** `receiver.prop = rhs` — an assignment to a dangerous property (e.g. `el.innerHTML = html`). */
export function assignmentSink(
  id: string,
  category: SinkCategory,
  label: string,
  props: ReadonlySet<string>,
): TaintSink {
  return {
    id,
    category,
    label,
    match: (node) =>
      ts.isBinaryExpression(node) &&
      node.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
      ts.isPropertyAccessExpression(node.left) &&
      props.has(node.left.name.text)
        ? [node.right]
        : [],
  };
}

/**
 * A URL-shaped argument is "relative" — and therefore not a server-side-request / open-redirect
 * target — when it begins with a path separator (`/foo`, `` `/api/${id}` ``) but not a
 * protocol-relative `//host`. Used to suppress the common safe pattern `fetch(\`/api/${id}\`)`.
 */
export function looksRelativeUrl(expr: ts.Expression): boolean {
  const headStartsWithSlash = (text: string): boolean =>
    text.startsWith('/') && !text.startsWith('//');
  if (ts.isStringLiteralLike(expr)) {
    return headStartsWithSlash(expr.text);
  }
  if (ts.isTemplateExpression(expr)) {
    return headStartsWithSlash(expr.head.text);
  }
  if (ts.isBinaryExpression(expr) && expr.operatorToken.kind === ts.SyntaxKind.PlusToken) {
    return looksRelativeUrl(expr.left);
  }
  return false;
}
