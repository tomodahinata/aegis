import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { LiveRegion } from './live-region';

describe('LiveRegion', () => {
  it('is a polite status region carrying the message', () => {
    render(<LiveRegion message="Showing 3 events" />);
    const region = screen.getByRole('status');
    expect(region.getAttribute('aria-live')).toBe('polite');
    expect(region.textContent).toContain('Showing 3 events');
  });
});
