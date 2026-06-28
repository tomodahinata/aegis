// SAFE: the same handler, but it verifies event.origin against an allowlist before trusting event.data,
// so a foreign window cannot drive it — nothing to flag.
const state: Record<string, unknown> = {};
const ALLOWED_ORIGIN = 'https://trusted.example';

export function listen(): void {
  window.addEventListener('message', (event) => {
    if (event.origin !== ALLOWED_ORIGIN) {
      return;
    }
    const { key, value } = event.data;
    state[key] = value;
  });
}
