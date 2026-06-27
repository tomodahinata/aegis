/** "Skip to main content" — the first focusable element (WCAG 2.4.1 Bypass Blocks). */
export function SkipLink() {
  return (
    <a
      href="#main"
      className="sr-only focus:not-sr-only focus:absolute focus:left-2 focus:top-2 focus:z-50 focus:rounded focus:border focus:border-border focus:bg-card focus:px-3 focus:py-2 focus:text-foreground"
    >
      Skip to main content
    </a>
  );
}
