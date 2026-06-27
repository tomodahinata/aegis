// SAFE: Math.random() is fine for non-security jitter. The value is named `jitter`, not a token/secret,
// so the rule (which only flags security-named randomness) does not fire.
export function backoffDelay(attempt: number): number {
  const jitter = Math.random() * 100;
  return attempt * 1000 + jitter;
}
