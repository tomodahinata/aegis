import { describe, expect, it } from 'vitest';
import { ALL_RULES } from '../rules';
import { ALL_SQL_RULES } from '../sql-rules';
import {
  frameworkControls,
  mappedCategories,
  owaspCategory,
  SUPPORTED_FRAMEWORKS,
} from './controls';

const ALL_RULE_METAS = [...ALL_RULES, ...ALL_SQL_RULES].map((rule) => rule.meta);

describe('compliance control mapping', () => {
  it('extracts the OWASP 2021 category prefix', () => {
    expect(owaspCategory('A01:2021 Broken Access Control')).toBe('A01');
    expect(owaspCategory('A10:2021 Server-Side Request Forgery')).toBe('A10');
    expect(owaspCategory(undefined)).toBeUndefined();
    expect(owaspCategory('not-an-owasp-category')).toBeUndefined();
  });

  for (const framework of SUPPORTED_FRAMEWORKS) {
    // The DRY completeness gate: a new rule whose OWASP category is unmapped fails CI
    // here — the single, intended trigger for editing the control table.
    it(`maps every registered rule's OWASP category to a ${framework} control`, () => {
      const mapped = mappedCategories(framework);
      for (const meta of ALL_RULE_METAS) {
        const category = owaspCategory(meta.owasp);
        expect(category, `rule ${meta.id} declares no OWASP category`).toBeDefined();
        expect(
          mapped.has(category ?? ''),
          `rule ${meta.id} (${category}) is not mapped to any ${framework} control`,
        ).toBe(true);
      }
    });

    it(`${framework} control definitions are well-formed`, () => {
      for (const control of frameworkControls(framework)) {
        expect(control.id).toMatch(/\S/);
        expect(control.title).toMatch(/\S/);
        expect(control.owasp.length).toBeGreaterThan(0);
      }
    });
  }
});
