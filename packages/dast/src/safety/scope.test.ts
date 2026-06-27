import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { checkScope, isLoopbackHost, type ScopePolicy } from './scope';

const loopback: ScopePolicy = {
  origin: 'http://localhost:3000',
  originHost: 'localhost',
  remoteConsented: false,
  allowHosts: new Set(['localhost']),
};
const remote: ScopePolicy = {
  origin: 'https://staging.acme.com',
  originHost: 'staging.acme.com',
  remoteConsented: true,
  allowHosts: new Set(['staging.acme.com']),
};

describe('checkScope', () => {
  it('allows the loopback target origin', () => {
    expect(checkScope('http://localhost:3000/api/x', loopback)).toEqual({ ok: true });
  });

  it('denies a non-loopback host without consent', () => {
    expect(checkScope('https://evil.example/x', loopback)).toEqual({
      ok: false,
      reason: 'non-loopback-without-consent',
    });
  });

  it('denies link-local / cloud-metadata IPs even WITH consent (SSRF-into-scanner defense)', () => {
    expect(checkScope('http://169.254.169.254/latest/meta-data/', remote)).toEqual({
      ok: false,
      reason: 'link-local-or-metadata',
    });
  });

  it('denies non-http(s) schemes', () => {
    expect(checkScope('file:///etc/passwd', loopback)).toEqual({
      ok: false,
      reason: 'disallowed-scheme',
    });
    expect(checkScope('gopher://localhost/', loopback).ok).toBe(false);
  });

  it('denies an off-origin host (a redirect bounce to a different loopback host)', () => {
    expect(checkScope('http://127.0.0.1:3000/x', loopback)).toEqual({
      ok: false,
      reason: 'off-origin',
    });
  });

  it('denies a malformed URL', () => {
    expect(checkScope('not a url', loopback)).toEqual({ ok: false, reason: 'malformed-url' });
  });

  it('allows a consented remote origin', () => {
    expect(checkScope('https://staging.acme.com/api/x', remote)).toEqual({ ok: true });
  });

  it('property: a URL accepted under the loopback policy is always a loopback host', () => {
    fc.assert(
      fc.property(fc.webUrl(), (url) => {
        if (checkScope(url, loopback).ok) {
          expect(isLoopbackHost(new URL(url).hostname.toLowerCase())).toBe(true);
        }
      }),
      { numRuns: 100 },
    );
  });
});
