import { forEachDescendant, ts } from '../internal/ast';
import { docsUrlFor, type Rule } from '../rule';

/**
 * A cross-window `message` handler that trusts `event.data` without verifying `event.origin` (CWE-345 /
 * CWE-940). Any page that can `postMessage` to this window — a malicious iframe it embeds, a popup, or an
 * opener — can drive the handler; without an origin check that is a DOM-XSS / state-tampering vector.
 *
 * Zero-false-positive scoping (deliberate, with a documented recall trade-off):
 *  • Only `window.addEventListener('message', …)` / `window.onmessage = …` — an explicit `window` receiver
 *    is unambiguously the page (cross-origin) surface. Worker `self.onmessage` is a different threat model
 *    (messages come from the same-origin controlling page; `event.origin` is empty) and is NOT flagged.
 *  • Only an INLINE handler (arrow/function) whose body we can read; a named/external handler is skipped.
 *  • Flag only when the handler actually CONSUMES the message (`data`) yet never mentions `origin` — a
 *    relay/no-op handler, or one that already consults `origin` anywhere, is left silent.
 */

const isWindow = (node: ts.Expression): boolean => ts.isIdentifier(node) && node.text === 'window';

/** `window.<prop>` property access. */
function windowProp(expr: ts.Expression, prop: string): boolean {
  return (
    ts.isPropertyAccessExpression(expr) && isWindow(expr.expression) && expr.name.text === prop
  );
}

function inlineHandler(
  node: ts.Expression | undefined,
): ts.ArrowFunction | ts.FunctionExpression | undefined {
  return node && (ts.isArrowFunction(node) || ts.isFunctionExpression(node)) ? node : undefined;
}

/** The handler reads the message payload (`data`) but never consults the sender's `origin`. */
function consumesDataWithoutOriginCheck(fn: ts.ArrowFunction | ts.FunctionExpression): boolean {
  const body = fn.body.getText(fn.getSourceFile());
  return /\bdata\b/.test(body) && !/\borigin\b/.test(body);
}

export const postMessageOriginMissing: Rule = {
  meta: {
    id: 'dom/postmessage-origin-missing',
    title: 'window "message" handler trusts data without checking origin',
    severity: 'MEDIUM',
    owasp: 'A08:2021 Software and Data Integrity Failures',
    docsUrl: docsUrlFor('dom/postmessage-origin-missing'),
  },
  appliesTo: (file) => file.text.includes('message') && file.text.includes('window'),
  check(ctx) {
    const flag = (fn: ts.ArrowFunction | ts.FunctionExpression, node: ts.Node): void => {
      if (!consumesDataWithoutOriginCheck(fn)) {
        return;
      }
      ctx.report({
        node,
        confidence: 'high',
        message:
          "This window 'message' handler reads event.data but never checks event.origin — any page that can postMessage to this window (a malicious iframe, popup, or opener) can drive it, a DOM-XSS / state-tampering vector.",
        remediation:
          "Verify the sender first: `if (event.origin !== 'https://trusted.example') return;` (or test against an allowlist), then trust event.data. Never act on the payload before checking event.origin.",
        evidence: "addEventListener('message')",
      });
    };

    forEachDescendant(ctx.file.sourceFile, (node) => {
      // window.addEventListener('message', handler)
      if (ts.isCallExpression(node) && windowProp(node.expression, 'addEventListener')) {
        const event = node.arguments[0];
        const handler = inlineHandler(node.arguments[1]);
        if (event && ts.isStringLiteralLike(event) && event.text === 'message' && handler) {
          flag(handler, node);
        }
        return;
      }
      // window.onmessage = handler
      if (
        ts.isBinaryExpression(node) &&
        node.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
        windowProp(node.left, 'onmessage')
      ) {
        const handler = inlineHandler(node.right);
        if (handler) {
          flag(handler, node);
        }
      }
    });
  },
};
