import type { FileInfo } from '../rule';
import { forEachDescendant, ts } from './ast';

export function collectCalls(sourceFile: ts.SourceFile): ts.CallExpression[] {
  const calls: ts.CallExpression[] = [];
  forEachDescendant(sourceFile, (node) => {
    if (ts.isCallExpression(node)) {
      calls.push(node);
    }
  });
  return calls;
}

/** The simple name being called (`foo` in `foo()` or `x.foo()`), if any. */
export function calleeName(call: ts.CallExpression): string | undefined {
  const expression = call.expression;
  if (ts.isIdentifier(expression)) {
    return expression.text;
  }
  if (ts.isPropertyAccessExpression(expression)) {
    return expression.name.text;
  }
  return undefined;
}

export interface StringLike {
  readonly node: ts.Node;
  readonly text: string;
}

/** Every string literal / template, with its raw source text (templates included verbatim). */
export function collectStringLikes(sourceFile: ts.SourceFile): StringLike[] {
  const out: StringLike[] = [];
  forEachDescendant(sourceFile, (node) => {
    if (
      ts.isStringLiteral(node) ||
      ts.isNoSubstitutionTemplateLiteral(node) ||
      ts.isTemplateExpression(node)
    ) {
      out.push({ node, text: node.getText(sourceFile) });
    }
  });
  return out;
}

function isProcessEnv(node: ts.Expression): boolean {
  return (
    ts.isPropertyAccessExpression(node) &&
    ts.isIdentifier(node.expression) &&
    node.expression.text === 'process' &&
    node.name.text === 'env'
  );
}

export interface EnvAccess {
  readonly key: string;
  readonly node: ts.Node;
}

/** Every `process.env.X` / `process.env['X']` / `const { X } = process.env` access with its key. */
export function collectProcessEnvKeys(sourceFile: ts.SourceFile): EnvAccess[] {
  const out: EnvAccess[] = [];
  forEachDescendant(sourceFile, (node) => {
    if (ts.isPropertyAccessExpression(node) && isProcessEnv(node.expression)) {
      out.push({ key: node.name.text, node });
    } else if (
      ts.isElementAccessExpression(node) &&
      isProcessEnv(node.expression) &&
      ts.isStringLiteralLike(node.argumentExpression)
    ) {
      out.push({ key: node.argumentExpression.text, node });
    } else if (
      ts.isVariableDeclaration(node) &&
      node.initializer !== undefined &&
      isProcessEnv(node.initializer) &&
      ts.isObjectBindingPattern(node.name)
    ) {
      // `const { STRIPE_SECRET_KEY } = process.env` — key is the source name (propertyName) if renamed.
      for (const element of node.name.elements) {
        out.push({ key: element.propertyName?.getText() ?? element.name.getText(), node: element });
      }
    }
  });
  return out;
}

// Names that mark a secret. Suffix anchors avoid matching e.g. `KEYBOARD`.
const SECRET_WORDS =
  /SECRET|SERVICE_ROLE|PRIVATE_KEY|PASSWORD|WEBHOOK|API_KEY|ACCESS_KEY|_KEY$|_TOKEN$/;
// Values that are *designed* to be public — never flagged.
const PUBLISHABLE =
  /ANON_KEY|PUBLISHABLE_KEY|PUBLIC_KEY|CLIENT_ID|MEASUREMENT_ID|POSTHOG_KEY|SENTRY_DSN/;

/** Does an env var name denote a secret (and not a known-publishable value)? */
export function looksSecret(name: string): boolean {
  if (PUBLISHABLE.test(name)) {
    return false;
  }
  return SECRET_WORDS.test(name);
}

export function hasAnyToken(text: string, tokens: readonly string[]): boolean {
  const lower = text.toLowerCase();
  return tokens.some((token) => lower.includes(token.toLowerCase()));
}

/** Does this file import from any module matching one of the patterns? */
export function importsFrom(file: FileInfo, matchers: readonly RegExp[]): boolean {
  return file.imports.some((binding) => matchers.some((m) => m.test(binding.module)));
}

/** Local names imported from modules matching `matchers` (e.g. the LLM SDK call names). */
export function importedNamesFrom(file: FileInfo, matchers: readonly RegExp[]): Set<string> {
  const names = new Set<string>();
  for (const binding of file.imports) {
    if (matchers.some((m) => m.test(binding.module))) {
      names.add(binding.localName);
    }
  }
  return names;
}
