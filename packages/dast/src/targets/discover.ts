/**
 * Discover the attack surface. Static-derived targets (the basis of correlation) come from walking the
 * project's App-Router `route.ts` files and reusing the scanner's `classifyFile` to read each route's URL
 * path and exported HTTP methods. Explicit URL targets cover routes static can't see.
 */

import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { classifyFile, parseSource } from '@aegiskit/scanner';
import type { Target } from '../probes/types';
import { deriveRoutePath, fillParams } from './route-path';

const HTTP_METHODS: ReadonlySet<string> = new Set([
  'GET',
  'POST',
  'PUT',
  'PATCH',
  'DELETE',
  'HEAD',
  'OPTIONS',
]);
const SKIP_DIRS: ReadonlySet<string> = new Set([
  'node_modules',
  '.next',
  '.git',
  'dist',
  'coverage',
  'fixtures',
]);
const ROUTE_FILE = /^route\.(?:ts|tsx|js|jsx|mjs)$/;

function collectRouteFiles(dir: string, out: string[]): void {
  let entries: string[];
  try {
    entries = readdirSync(dir);
  } catch {
    return;
  }
  for (const entry of entries) {
    if (SKIP_DIRS.has(entry)) {
      continue;
    }
    const full = join(dir, entry);
    let isDir = false;
    try {
      isDir = statSync(full).isDirectory();
    } catch {
      continue;
    }
    if (isDir) {
      collectRouteFiles(full, out);
    } else if (ROUTE_FILE.test(entry)) {
      out.push(full);
    }
  }
}

/** Build targets from the project's route handler files under `cwd`. */
export function discoverRoutes(cwd: string, origin: string): Target[] {
  const base = origin.replace(/\/$/, '');
  const files: string[] = [];
  collectRouteFiles(cwd, files);
  const targets: Target[] = [];
  for (const file of files) {
    const routePath = deriveRoutePath(file);
    if (routePath === undefined) {
      continue;
    }
    let text: string;
    try {
      text = readFileSync(file, 'utf8');
    } catch {
      continue;
    }
    const classification = classifyFile(file, parseSource(file, text));
    if (!classification.isRouteHandler) {
      continue;
    }
    const methods = new Set(
      [...classification.exportedNames].filter((name) => HTTP_METHODS.has(name)),
    );
    if (methods.size === 0) {
      methods.add('GET');
    }
    targets.push({
      origin,
      path: routePath,
      url: base + fillParams(routePath),
      methods,
      sourceFile: file,
    });
  }
  return targets;
}

/** Build a single target from an explicit URL (methods unknown ⇒ GET). */
export function targetFromUrl(rawUrl: string, origin: string): Target {
  const parsed = new URL(rawUrl);
  return {
    origin,
    path: parsed.pathname + parsed.search,
    url: rawUrl,
    methods: new Set(['GET']),
  };
}
