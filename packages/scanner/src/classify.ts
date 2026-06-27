import { basename } from 'node:path';
import { collectExportedNames, getLeadingDirectives, ts } from './internal/ast';

/** Where a module runs — the axis that distinguishes "secret in server code" from a leak. */
export type RuntimeContext = 'server' | 'client' | 'edge' | 'shared' | 'unknown';

export interface FileClassification {
  readonly path: string;
  readonly context: RuntimeContext;
  readonly isRouteHandler: boolean;
  readonly isServerAction: boolean;
  readonly isMiddleware: boolean;
  readonly isConfig: boolean;
  readonly directives: readonly string[];
  readonly runtime?: 'edge' | 'nodejs';
  readonly exportedNames: ReadonlySet<string>;
}

const ROUTE_HANDLER = /^route\.(?:ts|tsx|js|jsx)$/;
const MIDDLEWARE = /^(?:middleware|proxy)\.(?:ts|js)$/;
const NEXT_CONFIG = /^next\.config\.(?:ts|js|mjs|cjs)$/;

function readRuntimeExport(sourceFile: ts.SourceFile): 'edge' | 'nodejs' | undefined {
  for (const statement of sourceFile.statements) {
    if (!ts.isVariableStatement(statement)) {
      continue;
    }
    const exported = ts
      .getModifiers(statement)
      ?.some((m) => m.kind === ts.SyntaxKind.ExportKeyword);
    if (!exported) {
      continue;
    }
    for (const decl of statement.declarationList.declarations) {
      if (
        ts.isIdentifier(decl.name) &&
        decl.name.text === 'runtime' &&
        decl.initializer &&
        ts.isStringLiteralLike(decl.initializer)
      ) {
        const value = decl.initializer.text;
        if (value === 'edge' || value === 'nodejs') {
          return value;
        }
      }
    }
  }
  return undefined;
}

export function classifyFile(path: string, sourceFile: ts.SourceFile): FileClassification {
  const directives = getLeadingDirectives(sourceFile);
  const base = basename(path);
  const isRouteHandler = ROUTE_HANDLER.test(base);
  const isMiddleware = MIDDLEWARE.test(base);
  const isConfig = NEXT_CONFIG.test(base);
  const isServerAction = directives.includes('use server');
  const runtime = readRuntimeExport(sourceFile);

  let context: RuntimeContext;
  if (directives.includes('use client')) {
    context = 'client';
  } else if (runtime === 'edge' || isMiddleware) {
    context = 'edge';
  } else {
    // App Router modules are Server Components by default.
    context = 'server';
  }

  return {
    path,
    context,
    isRouteHandler,
    isServerAction,
    isMiddleware,
    isConfig,
    directives,
    exportedNames: collectExportedNames(sourceFile),
    ...(runtime !== undefined ? { runtime } : {}),
  };
}
