import { forEachDescendant, ts } from '../internal/ast';
import { docsUrlFor, type Rule } from '../rule';

// A call whose name looks like a sanitizer is treated as safe (DOMPurify.sanitize, sanitizeHtml…).
const SANITIZER = /^(?:sanitize|purify|clean|escapeHtml|dompurify)/i;

function propertyName(name: ts.PropertyName): string | undefined {
  if (ts.isIdentifier(name) || ts.isStringLiteral(name)) {
    return name.text;
  }
  return undefined;
}

/** Find the `__html: <expr>` value inside a `{ __html: … }` object literal. */
function findHtmlValue(node: ts.Expression): ts.Expression | undefined {
  if (!ts.isObjectLiteralExpression(node)) {
    return undefined;
  }
  for (const property of node.properties) {
    if (ts.isPropertyAssignment(property) && propertyName(property.name) === '__html') {
      return property.initializer;
    }
  }
  return undefined;
}

/** The body of the function enclosing `node`, if any (for one-hop local variable resolution). */
function enclosingFunctionBody(node: ts.Node): ts.Node | undefined {
  for (let cur = node.parent; cur; cur = cur.parent) {
    if (
      ts.isFunctionDeclaration(cur) ||
      ts.isFunctionExpression(cur) ||
      ts.isArrowFunction(cur) ||
      ts.isMethodDeclaration(cur)
    ) {
      return cur.body;
    }
  }
  return undefined;
}

/**
 * The initializer of a local `const name = …`, but only when the name is declared exactly once in the
 * enclosing function — an unambiguous single definition. This lets the rule see that `const html =
 * DOMPurify.sanitize(x)` is safe (no false positive) and that `const html = bio` is not.
 */
function resolveLocalInitializer(ident: ts.Identifier): ts.Expression | undefined {
  const body = enclosingFunctionBody(ident);
  if (!body) {
    return undefined;
  }
  let found: ts.Expression | undefined;
  let count = 0;
  const visit = (node: ts.Node): void => {
    if (
      ts.isVariableDeclaration(node) &&
      ts.isIdentifier(node.name) &&
      node.name.text === ident.text &&
      node.initializer
    ) {
      found = node.initializer;
      count += 1;
    }
    node.forEachChild(visit);
  };
  body.forEachChild(visit);
  return count === 1 ? found : undefined;
}

/** A `__html` source is safe iff it is a static literal, `JSON.stringify(...)`, or a sanitizer call. */
function isSafeHtmlSource(expr: ts.Expression): boolean {
  if (ts.isStringLiteral(expr) || ts.isNoSubstitutionTemplateLiteral(expr)) {
    return true;
  }
  if (ts.isCallExpression(expr)) {
    const callee = expr.expression;
    if (ts.isPropertyAccessExpression(callee)) {
      if (
        ts.isIdentifier(callee.expression) &&
        callee.expression.text === 'JSON' &&
        callee.name.text === 'stringify'
      ) {
        return true;
      }
      return SANITIZER.test(callee.name.text);
    }
    if (ts.isIdentifier(callee)) {
      return SANITIZER.test(callee.text);
    }
  }
  return false;
}

export const dangerousHtmlUnsanitized: Rule = {
  meta: {
    id: 'xss/dangerous-html-unsanitized',
    title: 'dangerouslySetInnerHTML from an unsanitized source',
    severity: 'HIGH',
    owasp: 'A03:2021 Injection',
    docsUrl: docsUrlFor('xss/dangerous-html-unsanitized'),
  },
  appliesTo: (file) => file.text.includes('dangerouslySetInnerHTML'),
  check(ctx) {
    forEachDescendant(ctx.file.sourceFile, (node) => {
      if (!ts.isJsxAttribute(node)) {
        return;
      }
      if (!ts.isIdentifier(node.name) || node.name.text !== 'dangerouslySetInnerHTML') {
        return;
      }
      const initializer = node.initializer;
      if (!initializer || !ts.isJsxExpression(initializer) || !initializer.expression) {
        return;
      }
      const htmlValue = findHtmlValue(initializer.expression);
      if (!htmlValue) {
        return; // value isn't an inline { __html: … } we can reason about
      }
      // Follow a variable one hop to its local definition so a value sanitized into a variable is
      // recognized as safe (and an unsanitized one is still caught).
      const resolved = ts.isIdentifier(htmlValue)
        ? (resolveLocalInitializer(htmlValue) ?? htmlValue)
        : htmlValue;
      if (isSafeHtmlSource(resolved)) {
        ctx.pass(
          'dangerouslySetInnerHTML uses a safe source (static literal / JSON.stringify / sanitizer).',
        );
        return;
      }
      ctx.report({
        node,
        // A call to an unrecognized function might be a custom sanitizer → medium; a bare value is clearly unsafe.
        confidence: ts.isCallExpression(resolved) ? 'medium' : 'high',
        message:
          'dangerouslySetInnerHTML is set from an unsanitized expression — injected HTML/scripts execute in the user’s session (XSS).',
        remediation:
          'Sanitize with DOMPurify (or, for JSON-LD, JSON.stringify a typed object). Never inject raw user/dynamic HTML.',
        evidence: 'dangerouslySetInnerHTML',
      });
    });
  },
};
