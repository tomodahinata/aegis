'use client';

import DOMPurify from 'dompurify';
import { useSearchParams } from 'next/navigation';

// SAFE: the untrusted value is sanitized with DOMPurify before being written to the DOM, so the HTML
// sink is neutralized and there is no finding.
export function Preview() {
  const dirty = useSearchParams().get('html') ?? '';
  const el = typeof document !== 'undefined' ? document.getElementById('out') : null;
  if (el) {
    el.innerHTML = DOMPurify.sanitize(dirty);
  }
  return null;
}
