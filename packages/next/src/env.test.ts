/**
 * `defineServerEnv` is a security seam: it hardcodes `isServer: true` (so server vars are always
 * validated, even off the request path) and defaults `runtimeEnv` to `process.env`. The
 * `import 'server-only'` it carries throws under the `node` test environment, so we mock it away
 * — we are exercising the validation/runtimeEnv behavior, not the build-time client/server guard.
 */

import { afterEach, describe, expect, it, vi } from 'vitest';
import { z } from 'zod';

vi.mock('server-only', () => ({}));

const { defineServerEnv } = await import('./env');

afterEach(() => {
  vi.unstubAllEnvs();
});

describe('defineServerEnv', () => {
  it('validates and exposes server vars given an explicit runtimeEnv', () => {
    const env = defineServerEnv({
      server: { API_SECRET: z.string().min(1) },
      client: { NEXT_PUBLIC_SITE_URL: z.string().url() },
      runtimeEnv: {
        API_SECRET: 's3cret',
        NEXT_PUBLIC_SITE_URL: 'https://app.example.com',
      },
    });

    // `isServer: true` is hardcoded, so the server var is parsed and exposed.
    expect(env.API_SECRET).toBe('s3cret');
    expect(env.NEXT_PUBLIC_SITE_URL).toBe('https://app.example.com');
  });

  it('throws when an explicit runtimeEnv fails validation', () => {
    expect(() =>
      defineServerEnv({
        server: { API_SECRET: z.string().min(1) },
        client: {},
        runtimeEnv: { API_SECRET: '' },
      }),
    ).toThrow(/server environment variables/i);
  });

  it('falls back to process.env when runtimeEnv is omitted', () => {
    vi.stubEnv('API_SECRET', 'from-process-env');
    vi.stubEnv('NEXT_PUBLIC_SITE_URL', 'https://from-process.example.com');

    const env = defineServerEnv({
      server: { API_SECRET: z.string().min(1) },
      client: { NEXT_PUBLIC_SITE_URL: z.string().url() },
    });

    expect(env.API_SECRET).toBe('from-process-env');
    expect(env.NEXT_PUBLIC_SITE_URL).toBe('https://from-process.example.com');
  });
});
