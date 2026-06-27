/**
 * Per-function-scope structure for the taint engine. With no TypeScript type-checker available, value
 * identity is tracked by NAME within a scope; this module isolates the subtle part — discovering
 * function scopes and recording, per scope, which names are declared, re-declared (shadowed), or
 * reassigned. The dataflow engine uses `ambiguous`/`reassigned` to cap confidence so a name whose
 * binding it cannot prove never yields a high-confidence (CI-blocking) false positive.
 */

import { ts } from './ast';

/** True for every node that opens a new value scope (so taint does not leak across it — intraprocedural). */
export function isFunctionLike(node: ts.Node): boolean {
  return (
    ts.isFunctionDeclaration(node) ||
    ts.isFunctionExpression(node) ||
    ts.isArrowFunction(node) ||
    ts.isMethodDeclaration(node) ||
    ts.isGetAccessorDeclaration(node) ||
    ts.isSetAccessorDeclaration(node) ||
    ts.isConstructorDeclaration(node)
  );
}

/**
 * Visit every node belonging to one scope in source order, treating nested functions as opaque (the
 * nested function node is visited, but its body is not descended into — it is its own scope). The
 * body node itself is visited first, so an arrow with an expression body that *is* a sink
 * (`() => sink(x)`) is not missed.
 */
export function walkScope(body: ts.Node, visit: (node: ts.Node) => void): void {
  visit(body);
  body.forEachChild(function recur(child) {
    visit(child);
    if (!isFunctionLike(child)) {
      child.forEachChild(recur);
    }
  });
}

export interface ScopeSymbols {
  /** Names declared more than once in this scope — taint through them is confidence-capped. */
  readonly ambiguous: ReadonlySet<string>;
  /** Names reassigned after declaration (`x = …`) — also confidence-capped. */
  readonly reassigned: ReadonlySet<string>;
}

export interface FunctionScope {
  readonly node: ts.Node;
  readonly body: ts.Node;
  readonly parameters: readonly ts.ParameterDeclaration[];
  readonly symbols: ScopeSymbols;
}

export interface ScopeIndex {
  readonly scopes: readonly FunctionScope[];
}

function collectBoundNames(name: ts.BindingName, into: (n: string) => void): void {
  if (ts.isIdentifier(name)) {
    into(name.text);
    return;
  }
  for (const element of name.elements) {
    if (ts.isBindingElement(element)) {
      collectBoundNames(element.name, into);
    }
  }
}

function analyzeSymbols(body: ts.Node): ScopeSymbols {
  const declared = new Set<string>();
  const ambiguous = new Set<string>();
  const reassigned = new Set<string>();
  const declare = (n: string): void => {
    if (declared.has(n)) {
      ambiguous.add(n);
    }
    declared.add(n);
  };
  walkScope(body, (node) => {
    if (ts.isVariableDeclaration(node)) {
      collectBoundNames(node.name, declare);
    } else if (
      ts.isBinaryExpression(node) &&
      node.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
      ts.isIdentifier(node.left)
    ) {
      reassigned.add(node.left.text);
    }
  });
  return { ambiguous, reassigned };
}

function bodyOf(fn: ts.Node): ts.Node | undefined {
  if (
    (ts.isFunctionDeclaration(fn) ||
      ts.isFunctionExpression(fn) ||
      ts.isMethodDeclaration(fn) ||
      ts.isGetAccessorDeclaration(fn) ||
      ts.isSetAccessorDeclaration(fn) ||
      ts.isConstructorDeclaration(fn)) &&
    fn.body
  ) {
    return fn.body;
  }
  if (ts.isArrowFunction(fn)) {
    return fn.body; // a block OR an expression body
  }
  return undefined;
}

function parametersOf(fn: ts.Node): readonly ts.ParameterDeclaration[] {
  return ts.isFunctionLike(fn) ? fn.parameters : [];
}

/** Discover every analyzable function scope in the file, each with its parameters and symbol map. */
export function buildScopeIndex(sourceFile: ts.SourceFile): ScopeIndex {
  const scopes: FunctionScope[] = [];
  const visit = (node: ts.Node): void => {
    if (isFunctionLike(node)) {
      const body = bodyOf(node);
      if (body) {
        scopes.push({ node, body, parameters: parametersOf(node), symbols: analyzeSymbols(body) });
      }
    }
    node.forEachChild(visit);
  };
  sourceFile.forEachChild(visit);
  return { scopes };
}
