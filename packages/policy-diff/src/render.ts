/**
 * Markdown rendering of an access diff — the sticky PR comment / CLI output. Pure string building:
 * no I/O, no network, so the same renderer serves the CLI, the GitHub Action, and any future host.
 */

import type { AccessDelta, DeltaKind } from './diff';
import { summarizeDeltas } from './diff';
import { qualifiedTable } from './policy';

/** Marker embedded in the output so a bot can find-and-update its own sticky comment. */
export const COMMENT_MARKER = '<!-- aegis-policy-diff -->';

export interface RenderOptions {
  readonly baseRef?: string;
  readonly headRef?: string;
}

const KIND_BADGE: Record<DeltaKind, string> = {
  widening: '**WIDENING**',
  narrowing: 'narrowing',
  neutral: 'neutral',
  'requires-review': '**REQUIRES REVIEW**',
};

const KIND_ICON: Record<DeltaKind, string> = {
  widening: '🔓',
  narrowing: '🔒',
  neutral: '·',
  'requires-review': '❓',
};

/** Non-negotiable honest-scope footer — present in every rendering, never elided. */
const SCOPE_FOOTER =
  '> **Scope.** This compares the *shape* of repo-managed Supabase SQL (policies, RLS state, table grants) between two refs. ' +
  'It does not know your data model or business rules, does not see policies changed outside these migrations (e.g. via the dashboard), ' +
  'and a clean diff means "no access-relevant change detected in the modeled surface" — never "this migration is safe". ' +
  'Anything it cannot interpret is flagged for review rather than ignored.';

/**
 * Neutralize a value placed as PLAIN TEXT in a markdown table cell. The PR comment is the surface a
 * reviewer trusts to make the merge call, and the interpolated table/role/policy names are authored by
 * the PR under review — so escape the markdown-active characters a formatter won't: `|` (cell break),
 * newline (row break), backtick (would open a code span and swallow later cells), and `<` (raw HTML).
 */
const escapeCell = (s: string): string =>
  s.replace(/\|/g, '\\|').replace(/\r?\n/g, ' ').replace(/`/g, '\\`').replace(/</g, '&lt;');

/**
 * Render a value INSIDE a backtick code span safely: strip backticks so attacker-authored SQL cannot
 * break out of the span (backticks are not valid Postgres SQL, so nothing real is lost) and collapse
 * newlines. Inside an intact code span GitHub treats `<`, `|`, etc. as literal text, so no further
 * escaping is needed — the only escape route is a stray backtick, which this closes.
 */
const code = (s: string): string => `\`${s.replace(/`/g, "'").replace(/\r?\n/g, ' ')}\``;

export function renderDeltaMarkdown(
  deltas: readonly AccessDelta[],
  options: RenderOptions = {},
): string {
  const summary = summarizeDeltas(deltas);
  const refs =
    options.baseRef && options.headRef
      ? ` (${code(options.baseRef)} → ${code(options.headRef)})`
      : '';
  const lines: string[] = [COMMENT_MARKER, `### 🛡️ Aegis access delta${refs}`, ''];

  if (deltas.length === 0) {
    lines.push(
      'No access-relevant change detected in the modeled surface (RLS state, policies, table grants).',
      '',
      SCOPE_FOOTER,
    );
    return lines.join('\n');
  }

  const headline: string[] = [];
  if (summary.widening > 0) {
    headline.push(
      `**${summary.widening} access-widening change${summary.widening === 1 ? '' : 's'}**${summary.high > 0 ? ` (${summary.high} high)` : ''}`,
    );
  }
  if (summary.requiresReview > 0) {
    headline.push(`**${summary.requiresReview} requiring review**`);
  }
  if (summary.narrowing > 0) {
    headline.push(`${summary.narrowing} narrowing`);
  }
  lines.push(`${headline.join(', ')}.`, '');

  // High first, then review, then the rest — reviewers read top-down.
  const order = (d: AccessDelta): number =>
    (d.severity === 'high' ? 0 : 2) +
    (d.kind === 'widening' ? 0 : d.kind === 'requires-review' ? 1 : 2);
  const sorted = [...deltas].sort((a, b) => order(a) - order(b));

  lines.push('| | Table | Change | Verdict |', '|---|---|---|---|');
  for (const d of sorted) {
    const table = qualifiedTable(d.schema, d.table);
    const icon = d.severity === 'high' ? '🔴' : KIND_ICON[d.kind];
    lines.push(`| ${icon} | ${code(table)} | ${escapeCell(d.summary)} | ${KIND_BADGE[d.kind]} |`);
  }
  lines.push('');

  // Before/after predicates for the policy deltas, collapsed — evidence without noise.
  const policyDeltas = sorted.filter(
    (d) =>
      d.change.type === 'policy-changed' ||
      d.change.type === 'policy-added' ||
      d.change.type === 'policy-removed',
  );
  if (policyDeltas.length > 0) {
    lines.push('<details><summary>Predicates (before → after)</summary>', '');
    for (const d of policyDeltas) {
      const c = d.change;
      const before =
        c.type === 'policy-changed' ? c.before : c.type === 'policy-removed' ? c.policy : undefined;
      const after =
        c.type === 'policy-changed' ? c.after : c.type === 'policy-added' ? c.policy : undefined;
      const name = (after ?? before)?.name ?? '';
      const show = (p: { usingExpr?: string; checkExpr?: string } | undefined): string =>
        p === undefined
          ? '—'
          : `USING (${p.usingExpr ?? '—'})${p.checkExpr !== undefined ? ` WITH CHECK (${p.checkExpr})` : ''}`;
      lines.push(
        `- ${code(d.table)} · ${code(name)}`,
        `  - before: ${code(show(before))}`,
        `  - after: ${code(show(after))}`,
      );
    }
    lines.push('', '</details>', '');
  }

  lines.push(SCOPE_FOOTER);
  return lines.join('\n');
}
