import { describe, expect, it, vi } from 'vitest';

// `next/headers` only works inside a request scope; mock it so we can unit-test the reader.
const state = vi.hoisted(() => ({ store: new Headers() }));
vi.mock('next/headers', () => ({ headers: () => Promise.resolve(state.store) }));

const { getNonce } = await import('./nonce');

describe('getNonce', () => {
  it('reads the nonce from the request headers', async () => {
    state.store = new Headers({ 'x-aegis-nonce': 'abc123' });
    expect(await getNonce()).toBe('abc123');
  });

  it('returns undefined when the header is absent (secure() not installed)', async () => {
    state.store = new Headers();
    expect(await getNonce()).toBeUndefined();
  });
});
