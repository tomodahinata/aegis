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

// Only the SOURCE-OF-TRUTH schema is scanned: declarative `schemas/` and incremental `migrations/`.
// Generated dumps (`schema-snapshot.sql`), pgTAP tests (`*.test.sql`, `tests/`), and seeds are NOT
// the authority and would produce false positives (a dump duplicates the migrations; tests create
// throwaway temp tables) — so they are excluded.
const SQL_AUTHORITY_DIR = /[/\\](?:migrations|schemas)[/\\]/;
const SQL_NON_AUTHORITY = /\.test\.sql$|_test\.sql$|(?:^|[/\\])seed(?:s)?[./\\]/i;

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
        if (
          SQL_EXT.test(entry.name) &&
          SQL_AUTHORITY_DIR.test(full) &&
          !SQL_NON_AUTHORITY.test(full)
        ) {
          out.push(full);
        }
      }
    }
  }

  walk(root);
  return out;
}
