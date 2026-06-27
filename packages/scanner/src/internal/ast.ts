import ts from 'typescript';
import type { SourceRange } from '../types';

function scriptKindFor(path: string): ts.ScriptKind {
  if (path.endsWith('.tsx')) return ts.ScriptKind.TSX;
  if (path.endsWith('.jsx')) return ts.ScriptKind.JSX;
  if (path.endsWith('.js') || path.endsWith('.mjs') || path.endsWith('.cjs'))
    return ts.ScriptKind.JS;
  return ts.ScriptKind.TS;
}

/** Parse a single file to an AST (with parent links, for `getStart`/`getText`). */
export function parseSource(path: string, text: string): ts.SourceFile {
  return ts.createSourceFile(
    path,
    text,
    ts.ScriptTarget.Latest,
    /* setParentNodes */ true,
    scriptKindFor(path),
  );
}

/** Leading string-literal directives at the top of the module, e.g. `'use client'`. */
export function getLeadingDirectives(sourceFile: ts.SourceFile): string[] {
  const directives: string[] = [];
  for (const statement of sourceFile.statements) {
    if (ts.isExpressionStatement(statement) && ts.isStringLiteralLike(statement.expression)) {
      directives.push(statement.expression.text);
      continue;
    }
    // A non-directive statement ends the directive prologue.
    break;
  }
  return directives;
}

/**
 * True if the module imports `server-only` — Next.js's build-time guard that a module
 * never reaches the browser bundle (the build throws if it does). Such a module is, by
 * that contract, never client-reachable whatever the import graph says. Scans raw
 * statements because `collectImports` intentionally drops side-effect imports.
 */
export function importsServerOnly(sourceFile: ts.SourceFile): boolean {
  for (const statement of sourceFile.statements) {
    if (
      ts.isImportDeclaration(statement) &&
      ts.isStringLiteral(statement.moduleSpecifier) &&
      statement.moduleSpecifier.text === 'server-only'
    ) {
      return true;
    }
  }
  return false;
}

/** Depth-first visit of every node. */
export function forEachDescendant(node: ts.Node, visit: (node: ts.Node) => void): void {
  node.forEachChild((child) => {
    visit(child);
    forEachDescendant(child, visit);
  });
}

/** 1-based source range for a node. */
export function rangeOf(sourceFile: ts.SourceFile, node: ts.Node): SourceRange {
  const start = sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile));
  const end = sourceFile.getLineAndCharacterOfPosition(node.getEnd());
  return {
    startLine: start.line + 1,
    startColumn: start.character + 1,
    endLine: end.line + 1,
    endColumn: end.character + 1,
  };
}

export interface ImportBinding {
  /** The local name in this file. */
  readonly localName: string;
  /** The name as exported by the module (`default`, `*`, or the export identifier). */
  readonly importedName: string;
  /** The module specifier, e.g. `@/lib/supabase` or `next/server`. */
  readonly module: string;
  readonly isType: boolean;
}

/** Collect every import binding in a file (named, default, namespace, side-effect excluded). */
export function collectImports(sourceFile: ts.SourceFile): ImportBinding[] {
  const bindings: ImportBinding[] = [];
  for (const statement of sourceFile.statements) {
    if (!ts.isImportDeclaration(statement) || !ts.isStringLiteral(statement.moduleSpecifier)) {
      continue;
    }
    const module = statement.moduleSpecifier.text;
    const clause = statement.importClause;
    if (!clause) {
      continue;
    }
    const typeOnlyClause = clause.isTypeOnly;
    if (clause.name) {
      bindings.push({
        localName: clause.name.text,
        importedName: 'default',
        module,
        isType: typeOnlyClause,
      });
    }
    const named = clause.namedBindings;
    if (named && ts.isNamespaceImport(named)) {
      bindings.push({
        localName: named.name.text,
        importedName: '*',
        module,
        isType: typeOnlyClause,
      });
    } else if (named && ts.isNamedImports(named)) {
      for (const element of named.elements) {
        bindings.push({
          localName: element.name.text,
          importedName: element.propertyName?.text ?? element.name.text,
          module,
          isType: typeOnlyClause || element.isTypeOnly,
        });
      }
    }
  }
  return bindings;
}

/**
 * The exported function named `name` (a `function` declaration or an arrow/function-expression const),
 * or undefined. Enables depth-1 interprocedural resolution — following a call into a same-project helper.
 */
export function findExportedFunction(sourceFile: ts.SourceFile, name: string): ts.Node | undefined {
  for (const statement of sourceFile.statements) {
    const modifiers = ts.canHaveModifiers(statement) ? ts.getModifiers(statement) : undefined;
    const isExported = modifiers?.some((m) => m.kind === ts.SyntaxKind.ExportKeyword) ?? false;
    if (!isExported) {
      continue;
    }
    if (ts.isFunctionDeclaration(statement) && statement.name?.text === name) {
      return statement;
    }
    if (ts.isVariableStatement(statement)) {
      for (const decl of statement.declarationList.declarations) {
        if (
          ts.isIdentifier(decl.name) &&
          decl.name.text === name &&
          decl.initializer &&
          (ts.isArrowFunction(decl.initializer) || ts.isFunctionExpression(decl.initializer))
        ) {
          return decl.initializer;
        }
      }
    }
  }
  return undefined;
}

/** Names exported as functions/consts from this module (used to detect route handlers like `POST`). */
export function collectExportedNames(sourceFile: ts.SourceFile): Set<string> {
  const names = new Set<string>();
  for (const statement of sourceFile.statements) {
    const modifiers = ts.canHaveModifiers(statement) ? ts.getModifiers(statement) : undefined;
    const isExported = modifiers?.some((m) => m.kind === ts.SyntaxKind.ExportKeyword) ?? false;
    if (!isExported) {
      continue;
    }
    if (ts.isFunctionDeclaration(statement) && statement.name) {
      names.add(statement.name.text);
    } else if (ts.isVariableStatement(statement)) {
      for (const decl of statement.declarationList.declarations) {
        if (ts.isIdentifier(decl.name)) {
          names.add(decl.name.text);
        }
      }
    }
  }
  return names;
}

/**
 * A copy of the file's source with every comment blanked to spaces (newlines preserved, so line numbers
 * are unchanged) and all real code — including import specifiers and string literals — kept verbatim.
 *
 * This exists so substring/keyword heuristics (`hasAnyToken`) match only CODE, never prose in a comment.
 * A documentary mention is a real false-positive source: e.g. a Sentry-tunnel route whose comment reads
 * "the same status as `@supabase/ssr` in middleware" tripped the CSRF rule's cookie-auth detection,
 * flagging a handler that never touches cookies. Strings are deliberately KEPT — `from '@supabase/ssr'`
 * is a genuine cookie-auth signal — so only comments are removed.
 *
 * Guaranteed invariants (both hold regardless of how any ambiguous token is classified): the output has
 * the SAME length and line structure as the input, and every character is either kept verbatim or
 * replaced by a space — never added or altered. So this can only ever REMOVE code, never invent it, which
 * is exactly what keyword heuristics need: a comment can never manufacture a false match (fail-safe), and
 * line numbers are preserved. It is NOT guaranteed to equal "input minus comments": the bare lexer has no
 * parser context, so in division-/JSX-ambiguous positions it can misclassify real code as comment trivia
 * and blank it too (e.g. a regex literal whose body contains `/* *\/`, or JSX text containing `//`). That
 * only ever drops a signal (a possible false negative), never creates one, so it is safe for this use.
 * Strings and import specifiers are kept verbatim — `from '@supabase/ssr'` is a genuine cookie-auth signal.
 */
export function codeOnlyText(sourceFile: ts.SourceFile): string {
  const full = sourceFile.getFullText();
  const scanner = ts.createScanner(
    ts.ScriptTarget.Latest,
    /* skipTrivia */ false,
    sourceFile.languageVariant,
    full,
  );
  let out = '';
  for (let token = scanner.scan(); token !== ts.SyntaxKind.EndOfFileToken; token = scanner.scan()) {
    const text = scanner.getTokenText();
    out +=
      token === ts.SyntaxKind.SingleLineCommentTrivia ||
      token === ts.SyntaxKind.MultiLineCommentTrivia
        ? text.replace(/[^\n]/g, ' ')
        : text;
  }
  return out;
}

export { ts };
