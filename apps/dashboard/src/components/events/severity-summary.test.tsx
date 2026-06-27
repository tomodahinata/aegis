import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { expectNoA11yViolations } from '@/test-utils/axe';
import { mkEvent } from '@/test-utils/events';
import { SeveritySummary } from './severity-summary';

describe('SeveritySummary', () => {
  it('shows a per-severity breakdown and a total, with no a11y violations', async () => {
    const { container } = render(
      <SeveritySummary
        events={[mkEvent('csrf_block', 1, 'a'), mkEvent('rate_limit_block', 2, 'b')]}
      />,
    );
    expect(screen.getByText('2 total')).not.toBeNull();
    expect(container.textContent ?? '').toMatch(/High/);
    await expectNoA11yViolations(container);
  });

  it('renders zero counts without crashing on an empty list', () => {
    render(<SeveritySummary events={[]} />);
    expect(screen.getByText('0 total')).not.toBeNull();
  });
});
