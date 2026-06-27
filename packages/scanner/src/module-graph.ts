import { dirname, join, resolve } from 'node:path';

const EXTENSIONS = ['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs'];

/**
 * Resolve an import specifier to a known file path, or `undefined` for external packages.
 * Handles relative imports and a simple alias map (e.g. `@/` → the project's `src/`).
 */
export function resolveImportPath(
  fromPath: string,
  specifier: string,
  known: ReadonlySet<string>,
  aliases?: Record<string, string>,
): string | undefined {
  let spec = specifier;
  if (aliases) {
    for (const [prefix, target] of Object.entries(aliases)) {
      if (spec === prefix || spec.startsWith(prefix)) {
        spec = target + spec.slice(prefix.length);
        break;
      }
    }
  }
  if (!spec.startsWith('.') && !spec.startsWith('/')) {
    return undefined; // bare/external package specifier
  }
  const base = spec.startsWith('/') ? spec : resolve(dirname(fromPath), spec);
  const candidates = [
    base,
    ...EXTENSIONS.map((ext) => base + ext),
    ...EXTENSIONS.map((ext) => join(base, `index${ext}`)),
  ];
  return candidates.find((candidate) => known.has(candidate));
}

export interface GraphNode {
  readonly path: string;
  readonly importsResolved: ReadonlySet<string>;
}

/**
 * Every module transitively imported by a Client Component. AST-derived (not a filename
 * guess), this is what lets rules say "a secret is read in client-reachable code" with low
 * false-positive risk.
 *
 * `barriers` are modules that provably cannot reach the browser bundle (e.g. those importing
 * `server-only`). A barrier is excluded from the result and its out-edges are not followed,
 * so a subtree reachable *only* through a barrier is correctly treated as server-only too.
 * Barriers are checked on traversal targets, never on seeds: a seed is a Client Component by
 * its own directive, so a contradictory `'use client'` + `server-only` file (a Next build
 * error) still expands — erring toward more findings, which is the secure default.
 */
export function computeReachableFromClient(
  nodes: ReadonlyMap<string, GraphNode>,
  clientSeeds: readonly string[],
  barriers?: ReadonlySet<string>,
): Set<string> {
  const reachable = new Set<string>();
  const queue: string[] = [...clientSeeds];
  for (let i = 0; i < queue.length; i++) {
    const current = queue[i];
    if (current === undefined) {
      continue;
    }
    const node = nodes.get(current);
    if (!node) {
      continue;
    }
    for (const target of node.importsResolved) {
      if (!reachable.has(target) && !barriers?.has(target)) {
        reachable.add(target);
        queue.push(target);
      }
    }
  }
  return reachable;
}
