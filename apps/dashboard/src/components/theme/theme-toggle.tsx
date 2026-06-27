'use client';

import { useTheme } from 'next-themes';
import { useEffect, useState } from 'react';

// A native <select> is fully keyboard-accessible and labelled — no custom dropdown to get wrong.
export function ThemeToggle() {
  const { theme, setTheme } = useTheme();
  const [mounted, setMounted] = useState(false);
  useEffect(() => setMounted(true), []);

  return (
    <label className="flex items-center gap-2 text-sm text-muted">
      <span>Theme</span>
      <select
        aria-label="Color theme"
        value={mounted ? (theme ?? 'system') : 'system'}
        onChange={(event) => setTheme(event.target.value)}
        className="rounded border border-border bg-card px-2 py-1 text-foreground"
      >
        <option value="system">System</option>
        <option value="light">Light</option>
        <option value="dark">Dark</option>
        <option value="hc">High contrast</option>
      </select>
    </label>
  );
}
