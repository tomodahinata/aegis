'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';

const LINKS = [
  { href: '/', label: 'Posture' },
  { href: '/events', label: 'Events' },
  { href: '/csp', label: 'CSP' },
  { href: '/settings', label: 'Settings' },
] as const;

export function SidebarNav() {
  const pathname = usePathname();
  return (
    <nav aria-label="Primary" className="flex gap-1">
      {LINKS.map((link) => {
        const active = pathname === link.href;
        return (
          <Link
            key={link.href}
            href={link.href}
            aria-current={active ? 'page' : undefined}
            className={`rounded px-3 py-2 text-sm ${active ? 'bg-card font-medium text-foreground' : 'text-muted hover:text-foreground'}`}
          >
            {link.label}
          </Link>
        );
      })}
    </nav>
  );
}
