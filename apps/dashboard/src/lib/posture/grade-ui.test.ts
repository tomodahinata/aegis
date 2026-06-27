import type { Grade } from '@aegiskit/observability';
import { describe, expect, it } from 'vitest';
import { gradeToVisual, severityToVisual } from './grade-ui';

describe('gradeToVisual', () => {
  it('always carries a text label AND an icon (WCAG 1.4.1 — never color alone)', () => {
    for (const grade of ['A', 'B', 'C', 'D', 'F'] as const satisfies readonly Grade[]) {
      const visual = gradeToVisual(grade);
      expect(visual.label.length).toBeGreaterThan(0);
      expect(visual.icon).toBeTruthy();
    }
  });
});

describe('severityToVisual', () => {
  it('carries a label AND a glyph for every severity', () => {
    for (const severity of ['low', 'medium', 'high'] as const) {
      const visual = severityToVisual(severity);
      expect(visual.label.length).toBeGreaterThan(0);
      expect(visual.glyph.length).toBeGreaterThan(0);
    }
  });
});
