import axe from 'axe-core';
import { expect } from 'vitest';

/**
 * Assert a rendered subtree has no axe accessibility violations. Runs under jsdom, where layout-
 * dependent rules (e.g. color-contrast) are auto-skipped — so this catches structural issues (missing
 * names, invalid ARIA, unlabeled controls, bad roles), which is exactly the class component tests can
 * own. Contrast is verified by design via the token palette.
 */
export async function expectNoA11yViolations(container: Element): Promise<void> {
  const results = await axe.run(container as HTMLElement, {
    // color-contrast needs canvas/layout (absent in jsdom) and is enforced by the token palette instead.
    rules: { 'color-contrast': { enabled: false } },
  });
  expect(results.violations.map((violation) => violation.id)).toEqual([]);
}
