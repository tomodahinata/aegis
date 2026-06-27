import type { Fix, TextEdit } from '../types';
import { ts } from './ast';

/**
 * Codemod: wrap App Router route handlers with `@aegiskit/next` `secureRoute({ origin: true })`.
 *
 * This is the riskiest transform Aegis ships — it rewrites the handler's signature — so it is
 * deliberately conservative and **fails closed**: it returns a `Fix` only when *every* requested
 * handler matches a shape we can transform provably-correctly, and `undefined` otherwise (the
 * finding then falls back to guided remediation). Better no codemod than a broken build.
 *
 * Semantics are safe by construction (see secure-route.ts): with no body schema `secureRoute`
 * does not consume the request, so a body that calls `await req.json()` keeps working; the wrapper
 * runs the origin check and returns 403 on cross-origin — exactly the fix the rule prescribes.
 */
export function wrapRouteHandlersWithSecureRoute(
  sourceFile: ts.SourceFile,
  methodNames: readonly string[],
): Fix | undefined {
  if (methodNames.length === 0) {
    return undefined;
  }

  const edits: TextEdit[] = [];
  const wrapped: string[] = [];

  for (const method of methodNames) {
    const fn = findExportedFunction(sourceFile, method);
    // Only a plain `export [async] function METHOD(...)` with a body is safe to rewrite.
    if (!fn || fn.asteriskToken) {
      return undefined;
    }
    if (!fn.body) {
      return undefined; // overload signature without a body
    }

    const paramText = paramBinding(fn);
    if (paramText === undefined) {
      return undefined; // >1 param (dynamic route), rest/destructured param — needs human judgement.
    }

    const isAsync =
      ts.getModifiers(fn)?.some((m) => m.kind === ts.SyntaxKind.AsyncKeyword) ?? false;
    const headerEnd = fn.body.getStart(sourceFile) + 1; // through the opening `{`
    edits.push({
      start: fn.getStart(sourceFile),
      end: headerEnd,
      newText: `export const ${method} = secureRoute({ origin: true }, ${isAsync ? 'async ' : ''}${paramText} => {`,
    });

    const bodyEnd = fn.body.getEnd(); // position just past the closing `}`
    edits.push({ start: bodyEnd - 1, end: bodyEnd, newText: '});' });
    wrapped.push(method);
  }

  const importEdit = planSecureRouteImport(sourceFile);
  if (importEdit) {
    edits.unshift(importEdit);
  }

  return {
    kind: 'auto',
    title: `Wrap ${wrapped.join('/')} with secureRoute (origin check on)`,
    edits,
  };
}

/** A non-default `export [async] function NAME` declaration, or undefined. */
function findExportedFunction(
  sourceFile: ts.SourceFile,
  name: string,
): ts.FunctionDeclaration | undefined {
  for (const stmt of sourceFile.statements) {
    if (!ts.isFunctionDeclaration(stmt) || stmt.name?.text !== name) {
      continue;
    }
    const mods = ts.getModifiers(stmt);
    const exported = mods?.some((m) => m.kind === ts.SyntaxKind.ExportKeyword) ?? false;
    const isDefault = mods?.some((m) => m.kind === ts.SyntaxKind.DefaultKeyword) ?? false;
    if (exported && !isDefault) {
      return stmt;
    }
  }
  return undefined;
}

/**
 * The destructured input binding for the wrapped arrow, preserving the original parameter name so
 * the body is untouched: `req` → `({ req })`, `request` → `({ req: request })`, none → `()`.
 * Returns undefined for any shape we won't transform (multiple params, rest, already-destructured).
 */
function paramBinding(fn: ts.FunctionDeclaration): string | undefined {
  if (fn.parameters.length === 0) {
    return '()';
  }
  if (fn.parameters.length > 1) {
    return undefined;
  }
  const p = fn.parameters[0];
  if (!p || p.dotDotDotToken || !ts.isIdentifier(p.name)) {
    return undefined;
  }
  const name = p.name.text;
  return name === 'req' ? '({ req })' : `({ req: ${name} })`;
}

/** A one-time import insertion for `secureRoute`, or undefined if already imported. */
function planSecureRouteImport(sourceFile: ts.SourceFile): TextEdit | undefined {
  if (hasNamedImport(sourceFile, '@aegiskit/next', 'secureRoute')) {
    return undefined;
  }
  const decl = "import { secureRoute } from '@aegiskit/next';";

  // Never insert above the directive prologue ('use client'/'use server' must stay first).
  let prologueEnd = 0;
  for (const stmt of sourceFile.statements) {
    if (ts.isExpressionStatement(stmt) && ts.isStringLiteralLike(stmt.expression)) {
      prologueEnd = stmt.getEnd();
    } else {
      break;
    }
  }

  const firstImport = sourceFile.statements.find(
    (s): s is ts.ImportDeclaration =>
      ts.isImportDeclaration(s) && s.getStart(sourceFile) >= prologueEnd,
  );
  if (firstImport) {
    const at = firstImport.getStart(sourceFile);
    return { start: at, end: at, newText: `${decl}\n` };
  }
  if (prologueEnd > 0) {
    return { start: prologueEnd, end: prologueEnd, newText: `\n${decl}` };
  }
  return { start: 0, end: 0, newText: `${decl}\n\n` };
}

function hasNamedImport(sourceFile: ts.SourceFile, module: string, name: string): boolean {
  for (const stmt of sourceFile.statements) {
    if (!ts.isImportDeclaration(stmt) || !ts.isStringLiteral(stmt.moduleSpecifier)) {
      continue;
    }
    if (stmt.moduleSpecifier.text !== module) {
      continue;
    }
    const named = stmt.importClause?.namedBindings;
    if (named && ts.isNamedImports(named)) {
      if (named.elements.some((e) => (e.propertyName?.text ?? e.name.text) === name)) {
        return true;
      }
    }
  }
  return false;
}
