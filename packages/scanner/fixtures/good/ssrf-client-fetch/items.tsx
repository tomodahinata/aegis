'use client';

import { useSearchParams } from 'next/navigation';

// SAFE: a client component fetching a same-origin RELATIVE path. There is no server-side egress and
// the host is fixed to the app's own origin, so it is not SSRF (the rule is server/edge-only anyway).
export function Items() {
  const id = useSearchParams().get('id') ?? '';
  void fetch(`/api/items/${id}`);
  return null;
}
