import { describe, expect, it } from 'vitest';
import { z } from 'zod';
import { defineEnv, EnvValidationError } from './env';

describe('defineEnv', () => {
  it('validates and exposes both server and client vars on the server', () => {
    const env = defineEnv({
      server: { SECRET_KEY: z.string().min(1) },
      client: { NEXT_PUBLIC_URL: z.string().min(1) },
      runtimeEnv: { SECRET_KEY: 'abc', NEXT_PUBLIC_URL: 'https://x.com' },
      isServer: true,
    });
    expect(env.SECRET_KEY).toBe('abc');
    expect(env.NEXT_PUBLIC_URL).toBe('https://x.com');
  });

  it('does not expose server vars when not on the server (the leak-prevention seam)', () => {
    const env = defineEnv({
      server: { SECRET_KEY: z.string().min(1) },
      client: { NEXT_PUBLIC_URL: z.string().min(1) },
      runtimeEnv: { SECRET_KEY: 'abc', NEXT_PUBLIC_URL: 'https://x.com' },
      isServer: false,
    });
    expect(Object.hasOwn(env, 'SECRET_KEY')).toBe(false);
    expect(env.NEXT_PUBLIC_URL).toBe('https://x.com');
  });

  it('throws a readable error on a missing required var', () => {
    expect(() =>
      defineEnv({
        server: { SECRET_KEY: z.string().min(1) },
        client: {},
        runtimeEnv: {},
        isServer: true,
      }),
    ).toThrow(EnvValidationError);
  });

  it('treats empty strings as undefined by default', () => {
    expect(() =>
      defineEnv({
        server: { SECRET_KEY: z.string().min(1) },
        client: {},
        runtimeEnv: { SECRET_KEY: '' },
        isServer: true,
      }),
    ).toThrow(EnvValidationError);
  });

  it('rejects a server key with a NEXT_PUBLIC_ prefix (would leak to the client)', () => {
    expect(() =>
      defineEnv({
        server: { NEXT_PUBLIC_SECRET: z.string() },
        client: {},
        runtimeEnv: { NEXT_PUBLIC_SECRET: 'x' },
        isServer: true,
      }),
    ).toThrow(/must not be prefixed/);
  });

  it('rejects a client key without a NEXT_PUBLIC_ prefix', () => {
    expect(() =>
      defineEnv({
        server: {},
        // Cast simulates bypassing the compile-time guard; the runtime guard still fires.
        client: { BAD: z.string() } as unknown as Record<`NEXT_PUBLIC_${string}`, z.ZodType>,
        runtimeEnv: { BAD: 'x' },
        isServer: true,
      }),
    ).toThrow(/must be prefixed/);
  });

  it('returns a frozen object', () => {
    const env = defineEnv({
      server: {},
      client: { NEXT_PUBLIC_X: z.string() },
      runtimeEnv: { NEXT_PUBLIC_X: 'x' },
      isServer: true,
    });
    expect(Object.isFrozen(env)).toBe(true);
  });

  it('skips validation when asked', () => {
    expect(() =>
      defineEnv({
        server: { SECRET_KEY: z.string().min(1) },
        client: {},
        runtimeEnv: {},
        isServer: true,
        skipValidation: true,
      }),
    ).not.toThrow();
  });

  it('characterization: skipValidation returns the full frozen source, bypassing the server/client split', () => {
    // Documents CURRENT behavior: when validation is skipped, `defineEnv` returns a frozen
    // copy of the entire runtimeEnv and does NOT apply the isServer leak-prevention split —
    // server keys appear even with `isServer: false`. Callers must therefore only set
    // `skipValidation` where no secrets are present (e.g. a Docker build), as documented.
    const env = defineEnv({
      server: { SECRET_KEY: z.string().min(1) },
      client: { NEXT_PUBLIC_URL: z.string().min(1) },
      runtimeEnv: { SECRET_KEY: 'abc', NEXT_PUBLIC_URL: 'https://x.com' },
      isServer: false,
      skipValidation: true,
    });
    expect(Object.hasOwn(env, 'SECRET_KEY')).toBe(true);
    expect((env as Record<string, unknown>)['SECRET_KEY']).toBe('abc');
    expect(env.NEXT_PUBLIC_URL).toBe('https://x.com');
    expect(Object.isFrozen(env)).toBe(true);
  });
});
