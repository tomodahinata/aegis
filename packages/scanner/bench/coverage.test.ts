/**
 * Enforces the coverage matrix as a drift-proof, exhaustive artifact:
 *  1. Every built-in rule is classified by analysis method (no rule ships unclassified).
 *  2. No orphan classifications (a removed/renamed rule cannot leave stale metadata).
 *  3. The committed `docs/coverage.md` equals the generator output — so the doc can never drift from code.
 * Regenerate with `pnpm --filter @aegiskit/scanner coverage:matrix:write`.
 */

import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { allRuleIds, classifiedRuleIds, coverageMarkdown, DOC_PATH } from './coverage';

describe('coverage matrix', () => {
  it('classifies every built-in rule (no rule ships unclassified)', () => {
    const classified = new Set(classifiedRuleIds());
    const unclassified = allRuleIds().filter((id) => !classified.has(id));
    expect(unclassified).toEqual([]);
  });

  it('has no orphan classifications (every entry maps to a live rule)', () => {
    const live = new Set(allRuleIds());
    const orphans = classifiedRuleIds().filter((id) => !live.has(id));
    expect(orphans).toEqual([]);
  });

  it('matches the committed docs/coverage.md (regenerate with coverage:matrix:write)', () => {
    const onDisk = readFileSync(DOC_PATH, 'utf8');
    expect(onDisk).toBe(coverageMarkdown());
  });
});
