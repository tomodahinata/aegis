/**
 * `aegis diff` — the semantic access diff between two migration states ("did this change widen who
 * can read or write what?"). Reads the authoritative Supabase SQL at a base git ref (and a head ref,
 * or the working tree) WITHOUT checking anything out, builds the two RLS models, and reports the
 * access delta. Read-only by design: the only git operations are `rev-parse`, `ls-tree`, and `show`.
 *
 * Architecture note (Action-first): this command IS the gate — it runs in the repo owner's own CI
 * with their compute and their token. Any hosted bot built on top posts the same rendering as an
 * advisory comment; merge enforcement stays in the customer's CI, never behind a third-party SPOF.
 */

import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { relative } from 'node:path';
import {
  type AccessDelta,
  diffAccess,
  renderDeltaMarkdown,
  summarizeDeltas,
} from '@aegiskit/policy-diff';
import { buildRlsModel, type SqlSource } from '@aegiskit/scanner';
import { discoverSqlFiles, isAuthoritativeSqlPath } from '../discover';
import { UsageError } from '../errors';
import { EXIT } from '../exit';

export type DiffFormat = 'pretty' | 'markdown' | 'json';

export interface DiffArgs {
  readonly cwd: string;
  /** Base git ref (e.g. `origin/main`, a SHA). Required — the state to compare FROM. */
  readonly base: string;
  /** Head git ref. Omitted ⇒ the working tree (what you are about to commit). */
  readonly head?: string;
  readonly format: DiffFormat;
  /** Trusted authorization-helper function names (see policy-diff `DiffOptions`). */
  readonly trust: readonly string[];
  /** When true, `attention` (notice-level widenings/reviews) also fails the run. */
  readonly strict: boolean;
}

/** Wall-clock bound per git call so a pathological repo cannot hang the MCP stdio loop (which drives
 *  this synchronously). 30s is far above any real rev-parse/ls-tree/show on a checked-out worktree. */
const GIT_TIMEOUT_MS = 30_000;

function git(cwd: string, args: readonly string[]): string {
  try {
    return execFileSync('git', [...args], {
      cwd,
      encoding: 'utf8',
      maxBuffer: 64 * 1024 * 1024,
      timeout: GIT_TIMEOUT_MS,
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new UsageError(
      `git ${args[0]} failed — is this a git repository and "${args[1] ?? ''}" a valid ref? (${message.split('\n')[0]})`,
    );
  }
}

/** The authoritative Supabase SQL sources at `ref`, read via `git show` (no checkout, no clone). */
export function sourcesAtRef(cwd: string, ref: string): SqlSource[] {
  // Resolve first so a typo'd ref fails with a usage error, not a confusing ls-tree message.
  git(cwd, ['rev-parse', '--verify', `${ref}^{commit}`]);
  // Paths are repo-root-relative; scope to the invocation directory so a monorepo diff of one app
  // does not pick up sibling apps' migrations (mirrors scanning `cwd` on the worktree side).
  const prefix = git(cwd, ['rev-parse', '--show-prefix']).trim();
  const files = git(cwd, ['ls-tree', '-r', '--name-only', '-z', ref])
    .split('\0')
    // ls-tree paths are repo-root-relative with NO leading separator (`supabase/…`); the authority
    // regex anchors on a separator before `supabase`, so test with one prepended.
    .filter((p) => p.length > 0 && p.startsWith(prefix) && isAuthoritativeSqlPath(`/${p}`))
    .sort();
  return files.map((path) => ({
    path: `${ref}:${path}`,
    text: git(cwd, ['show', `${ref}:${path}`]),
  }));
}

/** The authoritative Supabase SQL sources in the working tree. */
export function sourcesInWorktree(cwd: string): SqlSource[] {
  return discoverSqlFiles(cwd)
    .sort()
    .map((path) => ({ path: relative(cwd, path), text: readFileSync(path, 'utf8') }));
}

function renderPretty(deltas: readonly AccessDelta[], base: string, head: string): string {
  const summary = summarizeDeltas(deltas);
  const lines: string[] = [`aegis diff — access delta (${base} → ${head})`, ''];
  if (deltas.length === 0) {
    lines.push('No access-relevant change detected in the modeled surface.');
  } else {
    const badge: Record<AccessDelta['kind'], string> = {
      widening: 'WIDENING',
      narrowing: 'narrowing',
      neutral: 'neutral',
      'requires-review': 'REQUIRES REVIEW',
    };
    for (const d of deltas) {
      const table = d.schema === 'public' ? d.table : `${d.schema}.${d.table}`;
      const sev = d.severity === 'high' ? ' [high]' : '';
      lines.push(`  ${badge[d.kind]}${sev}  ${table}: ${d.summary}`);
    }
    lines.push(
      '',
      `${summary.widening} widening · ${summary.requiresReview} require review · ${summary.narrowing} narrowing → ${summary.conclusion}`,
    );
  }
  lines.push(
    '',
    'Scope: compares repo-managed Supabase SQL only; anything unverifiable is flagged for review,',
    'and a clean diff never means "this migration is safe".',
  );
  return `${lines.join('\n')}\n`;
}

export function runDiff(args: DiffArgs): number {
  const baseModel = buildRlsModel(sourcesAtRef(args.cwd, args.base));
  const headModel = buildRlsModel(
    args.head === undefined ? sourcesInWorktree(args.cwd) : sourcesAtRef(args.cwd, args.head),
  );
  const headLabel = args.head ?? 'working tree';
  const deltas = diffAccess(baseModel, headModel, { trustedFunctions: args.trust });
  const summary = summarizeDeltas(deltas);

  if (args.format === 'json') {
    process.stdout.write(
      `${JSON.stringify({ base: args.base, head: headLabel, summary, deltas }, null, 2)}\n`,
    );
  } else if (args.format === 'markdown') {
    process.stdout.write(
      `${renderDeltaMarkdown(deltas, { baseRef: args.base, headRef: headLabel })}\n`,
    );
  } else {
    process.stdout.write(renderPretty(deltas, args.base, headLabel));
  }

  // Exit-code contract mirrors the scanner's confidence gating: only high-severity deltas
  // (action-required) fail by default; --strict also fails on notice-level attention.
  if (summary.conclusion === 'action-required') {
    return EXIT.FINDINGS;
  }
  if (args.strict && summary.conclusion === 'attention') {
    return EXIT.FINDINGS;
  }
  return EXIT.CLEAN;
}
