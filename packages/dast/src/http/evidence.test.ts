import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { captureResponse, redactHeaderValue, redactSecrets } from './evidence';

describe('redactSecrets', () => {
  it('masks a JWT', () => {
    const jwt = 'eyJhbGciOiJIUzI1Niated.eyJzdWIiOiIxMjM0NTY.SflKxwRJSMeKKF2QT4fwpM';
    expect(redactSecrets(`token=${jwt}`)).not.toContain(jwt);
    expect(redactSecrets(`token=${jwt}`)).toContain('[REDACTED]');
  });

  it('masks a long hex secret', () => {
    expect(redactSecrets('sig=0123456789abcdef0123456789abcdef0123456789')).toContain('[REDACTED]');
  });

  it('leaves benign text untouched', () => {
    expect(redactSecrets('hello world 42')).toBe('hello world 42');
  });

  it('property: a generated JWT never survives redaction', () => {
    const segment = fc.stringMatching(/^[A-Za-z0-9_-]{10,20}$/);
    fc.assert(
      fc.property(segment, segment, segment, (a, b, c) => {
        const jwt = `eyJ${a}.${b}.${c}`;
        expect(redactSecrets(`auth ${jwt} end`)).not.toContain(jwt);
      }),
      { numRuns: 50 },
    );
  });
});

describe('redactHeaderValue', () => {
  it('fully masks sensitive headers', () => {
    expect(redactHeaderValue('set-cookie', 'sid=secretvalue')).toBe('[REDACTED]');
    expect(redactHeaderValue('authorization', 'Bearer abc')).toBe('[REDACTED]');
  });

  it('passes through a non-sensitive header', () => {
    expect(redactHeaderValue('content-type', 'text/html')).toBe('text/html');
  });
});

describe('captureResponse — the body is bounded (never buffers an oversized response)', () => {
  it('truncates a body larger than the cap and flags it', async () => {
    const captured = await captureResponse(new Response('x'.repeat(10_000)), 5, 100);
    expect(captured.truncated).toBe(true);
    expect(captured.body.length).toBe(100);
  });

  it('returns a small body whole and not truncated', async () => {
    const captured = await captureResponse(new Response('ok'), 1, 100);
    expect(captured.truncated).toBe(false);
    expect(captured.body).toBe('ok');
  });
});
