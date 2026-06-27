'use client';

import { useSearchParams } from 'next/navigation';

// VULN: a URL query value is written to the DOM as HTML — DOM-based XSS. `?html=<img src=x
// onerror=...>` executes script in the victim's session.
export function Preview() {
  const html = useSearchParams().get('html') ?? '';
  const el = typeof document !== 'undefined' ? document.getElementById('out') : null;
  if (el) {
    el.innerHTML = html;
  }
  return null;
}
