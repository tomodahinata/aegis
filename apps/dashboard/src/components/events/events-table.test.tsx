import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { expectNoA11yViolations } from '@/test-utils/axe';
import { mkEvent } from '@/test-utils/events';
import { EventsTable } from './events-table';

describe('EventsTable', () => {
  it('marks the active sort column with aria-sort and has no a11y violations', async () => {
    const { container } = render(
      <EventsTable
        events={[mkEvent('csrf_block', 1, 'a'), mkEvent('rate_limit_block', 2, 'b')]}
        caption="Security events"
        now={3}
        sort="severity"
      />,
    );
    const header = screen.getByRole('columnheader', { name: 'Severity' });
    expect(header.getAttribute('aria-sort')).toBe('descending');
    await expectNoA11yViolations(container);
  });

  it('distinguishes a filtered empty state from no-events-at-all', () => {
    const { rerender } = render(
      <EventsTable events={[]} caption="c" now={0} sort="recent" filtered />,
    );
    expect(screen.getByText('No events match this filter.')).not.toBeNull();
    rerender(<EventsTable events={[]} caption="c" now={0} sort="recent" />);
    expect(screen.getByText(/No events yet/)).not.toBeNull();
  });
});
