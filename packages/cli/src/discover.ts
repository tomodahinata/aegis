import { type Dirent, existsSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

const SKIP_DIRS = new Set([
  'node_modules',
  '.next',
  'dist',
  '.turbo',
  '.git',
  'coverage',
  'out',
  'build',
  '.vercel',
  // Machine-generated / vendored output (Prisma client, GraphQL codegen, protobuf, …). It is not
  // authored source the developer can fix, and its minified/wasm blobs trip high-entropy secret
  // heuristics — scanning it is pure false-positive surface, exactly like `dist`/`build`.
  'generated',
]);
const SOURCE_EXT = /\.(?:ts|tsx|js|jsx|mjs|cjs)$/;
const SKIP_FILE = /\.d\.ts$|\.(?:test|spec)\./;
const SQL_EXT = /\.sql$/;

/** Recursively collect scannable source files under `root` (skipping build/test/vendor dirs). */
export function discoverFiles(root: string): string[] {
  const out: string[] = [];

  function walk(dir: string): void {
    let entries: Dirent<string>[];
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      if (entry.isDirectory()) {
        if (!SKIP_DIRS.has(entry.name) && !entry.name.startsWith('.')) {
          walk(join(dir, entry.name));
        }
      } else if (SOURCE_EXT.test(entry.name) && !SKIP_FILE.test(entry.name)) {
        out.push(join(dir, entry.name));
      }
    }
  }

  walk(root);
  return out;
}

/**
 * A conventional `@/` → `<root>/src/` alias so the scanner's import-graph rules resolve in
 * typical apps. Shared by `scan`/`ci`/`doctor` so every command gates on the same edges —
 * omitting it silently weakens the import-reachability analysis (e.g. `env/secret-in-client`).
 */
export function defaultAliases(root: string): Record<string, string> | undefined {
  const src = join(root, 'src');
  return existsSync(src) ? { '@/': `${src}/` } : undefined;
}

// Only the SOURCE-OF-TRUTH *Supabase* schema is scanned: declarative `supabase/schemas/` and
// incremental `supabase/migrations/`. The `supabase/` ancestor is load-bearing, not cosmetic: the RLS
// rules' entire threat model is PostgREST exposing tables to the `anon`/`authenticated` roles over HTTP.
// That risk exists ONLY behind Supabase. A Prisma/Drizzle Postgres app reached through a privileged
// server-side connection has no such boundary, so a table without RLS is normal there — scanning its
// `prisma/migrations/` would flag every CREATE TABLE as a false positive. Scoping to `supabase/` makes
// the analysis fire exactly where its threat model holds (the product is, by definition, Supabase).
// Generated dumps (`schema-snapshot.sql`), pgTAP tests (`*.test.sql`, `tests/`), and seeds are NOT the
// authority and would produce false positives (a dump duplicates the migrations; tests create throwaway
// temp tables) — so they are excluded.
const SQL_AUTHORITY_DIR = /[/\\]supabase[/\\](?:migrations|schemas)[/\\]/;
const SQL_NON_AUTHORITY = /\.test\.sql$|_test\.sql$|(?:^|[/\\])seed(?:s)?[./\\]/i;

/**
 * Is `path` a source-of-truth Supabase schema file (see the rationale above)? The single authority
 * shared by directory discovery here and git-ref listing in `aegis diff`, so the two can never
 * disagree about what SQL counts.
 */
export function isAuthoritativeSqlPath(path: string): boolean {
  return SQL_EXT.test(path) && SQL_AUTHORITY_DIR.test(path) && !SQL_NON_AUTHORITY.test(path);
}

/** Collect source-of-truth Supabase schema `.sql` files (migrations + declarative schemas). */
export function discoverSqlFiles(root: string): string[] {
  const out: string[] = [];

  function walk(dir: string): void {
    let entries: Dirent<string>[];
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      if (entry.isDirectory()) {
        if (!SKIP_DIRS.has(entry.name) && !entry.name.startsWith('.')) {
          walk(join(dir, entry.name));
        }
      } else {
        const full = join(dir, entry.name);
        if (isAuthoritativeSqlPath(full)) {
          out.push(full);
        }
      }
    }
  }

  walk(root);
  return out;
}
