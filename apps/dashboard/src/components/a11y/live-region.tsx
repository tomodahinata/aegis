'use client';

/**
 * A polite live region that announces a status message to screen readers (WCAG 4.1.3). The page is
 * server-navigated (force-dynamic), so this client component re-renders with new text on each filter/
 * sort change; `key`-ing it on the message in the parent guarantees the update is announced even when the
 * text node is otherwise reconciled in place. Visually hidden — sighted users see the same info in the
 * summary strip.
 */
export function LiveRegion({ message }: { message: string }) {
  return (
    <div role="status" aria-live="polite" aria-atomic="true" className="sr-only">
      {message}
    </div>
  );
}
