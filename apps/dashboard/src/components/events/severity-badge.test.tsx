import { render } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { expectNoA11yViolations } from '@/test-utils/axe';
import { SeverityBadge } from './severity-badge';

describe('SeverityBadge', () => {
  it('renders a visible text label plus an aria-hidden glyph (never color alone)', async () => {
    const { container } = render(<SeverityBadge type="csrf_block" />);
    expect(container.textContent ?? '').toMatch(/High|Medium|Low/);
    // The glyph is decorative; the label carries the meaning for assistive tech.
    expect(container.querySelector('[aria-hidden="true"]')).not.toBeNull();
    await expectNoA11yViolations(container);
  });
});
