import { buildRlsModel } from '@aegiskit/scanner';
import { describe, expect, it } from 'vitest';
import { diffAccess } from './diff';
import { COMMENT_MARKER, renderDeltaMarkdown } from './render';

const model = (sql: string) =>
  buildRlsModel([{ path: '/supabase/migrations/0001.sql', text: sql }]);

const BASE = `
  create table public.docs (id uuid, user_id uuid);
  alter table public.docs enable row level security;
  create policy p on public.docs for select using (auth.uid() = user_id);
`;
const HEAD = `
  create table public.docs (id uuid, user_id uuid);
  alter table public.docs enable row level security;
  create policy p on public.docs for select using (auth.uid() is not null);
`;

describe('renderDeltaMarkdown', () => {
  it('always embeds the sticky-comment marker and the honest-scope footer', () => {
    for (const md of [
      renderDeltaMarkdown([]),
      renderDeltaMarkdown(diffAccess(model(BASE), model(HEAD))),
    ]) {
      expect(md).toContain(COMMENT_MARKER);
      expect(md).toContain('**Scope.**');
      expect(md).toContain('never "this migration is safe"');
    }
  });

  it('never claims safety or completeness (negative assertions, non-negotiable framing)', () => {
    const md = renderDeltaMarkdown(diffAccess(model(BASE), model(BASE)));
    for (const banned of ['completely protect', 'fully secure', 'guarantees', 'is safe to merge']) {
      expect(md.toLowerCase()).not.toContain(banned);
    }
  });

  it('renders the widening with table, verdict, and before/after predicates', () => {
    const md = renderDeltaMarkdown(diffAccess(model(BASE), model(HEAD)), {
      baseRef: 'main',
      headRef: 'feat/x',
    });
    expect(md).toContain('`main` → `feat/x`');
    expect(md).toContain('**WIDENING**');
    expect(md).toContain('`docs`');
    expect(md).toContain('auth.uid() = user_id');
    expect(md).toContain('auth.uid() is not null');
    expect(md).toContain('🔴');
  });

  it('escapes pipe characters in summaries so the table cannot be broken', () => {
    const md = renderDeltaMarkdown(diffAccess(model(BASE), model(HEAD)));
    const tableLines = md.split('\n').filter((l) => l.startsWith('|'));
    // Header + separator + at least one delta row, each with a stable cell count.
    expect(tableLines.length).toBeGreaterThanOrEqual(3);
    const cells = tableLines.map((l) => l.split(/(?<!\\)\|/).length);
    expect(new Set(cells).size).toBe(1);
  });

  it('neutralizes an attacker-authored backtick so the comment cannot be spoofed (SEC-01)', () => {
    // The PR author controls the migration SQL; a single stray backtick in a predicate must not break
    // out of its code span and let injected markdown/HTML rewrite the verdict a reviewer trusts.
    const evil = `status = 'x${'`'}y'`; // one backtick inside the string literal
    const base = `
      create table public.docs (id uuid, user_id uuid);
      alter table public.docs enable row level security;
    `;
    const head = `${base} create policy p on public.docs for select using (${evil});`;
    const md = renderDeltaMarkdown(diffAccess(model(base), model(head)));
    // Every line keeps its inline-code backticks balanced — the injected backtick would otherwise make
    // this line's count odd, which is exactly a code-span breakout.
    for (const line of md.split('\n')) {
      expect((line.match(/`/g) ?? []).length % 2, `unbalanced code span: ${line}`).toBe(0);
    }
  });

  it('states "no access-relevant change" (not "safe") for an empty diff', () => {
    const md = renderDeltaMarkdown([]);
    expect(md).toContain('No access-relevant change detected');
    expect(md.toLowerCase()).not.toContain('safe to merge');
  });
});
