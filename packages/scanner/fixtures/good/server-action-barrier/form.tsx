'use client';

// Relative import so reachability resolves: this Client Component pulls `./action`, a Server Action.
// Because action.ts is `"use server"`, it is a reachability barrier and the secret behind it stays
// server-only — the whole scan stays clean.
import { charge } from './action';

export function Form(): string {
  return typeof charge === 'function' ? 'ready' : 'missing';
}
