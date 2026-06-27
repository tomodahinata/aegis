'use client';

// Relative import (no alias config needed) so reachability resolves: this Client Component
// transitively pulls `billing.ts`, which reads a server secret.
import { stripeKey } from './billing';

export function Panel() {
  return stripeKey ? 'configured' : 'missing';
}
