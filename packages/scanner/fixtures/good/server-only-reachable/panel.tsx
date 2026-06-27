'use client';

// Relative import so reachability resolves: this Client Component transitively pulls `./admin`.
// Because admin.ts is `server-only`, it is a reachability barrier and the whole scan stays clean.
import { createAdminClient } from './admin';

export function Panel() {
  return typeof createAdminClient === 'function' ? 'ready' : 'missing';
}
