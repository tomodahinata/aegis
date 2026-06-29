'use server';

// A `"use server"` Server Actions module. When the Client Component in form.tsx imports `charge`, the
// bundler emits an RPC reference, never this module's code — so `./billing` (and its secret read) stay
// server-side. The import graph reaches billing.ts, but this module is a reachability barrier.
import { getStripe } from './billing';

export async function charge(): Promise<string> {
  return getStripe() ? 'ok' : 'unconfigured';
}
