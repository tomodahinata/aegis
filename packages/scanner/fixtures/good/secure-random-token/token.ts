import { randomUUID } from 'node:crypto';

// SAFE: a cryptographically secure generator. No Math.random() to flag.
export function createResetToken(): string {
  return randomUUID();
}
