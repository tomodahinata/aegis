import { NextRequest } from 'next/server';
import { describe, expect, it } from 'vitest';
import { clientIp, isMutating } from './request';

const req = (headers?: Record<string, string>) =>
  new NextRequest('https://app.example.com/api', {
    method: 'GET',
    ...(headers ? { headers } : {}),
  });

describe('isMutating', () => {
  it('flags state-changing methods (case-insensitive) and clears safe ones', () => {
    for (const m of ['POST', 'put', 'Patch', 'DELETE']) {
      expect(isMutating(m)).toBe(true);
    }
    for (const m of ['GET', 'HEAD', 'options']) {
      expect(isMutating(m)).toBe(false);
    }
  });
});

describe('clientIp', () => {
  it('returns a single X-Forwarded-For entry', () => {
    expect(clientIp(req({ 'x-forwarded-for': '203.0.113.9' }))).toBe('203.0.113.9');
  });

  it('ignores a spoofed leftmost value — the rightmost trusted entry wins (default 1 hop)', () => {
    // An attacker prepends spoofed addresses; the trusted proxy appends the real one on the right.
    const headers = { 'x-forwarded-for': '6.6.6.6, 7.7.7.7, 203.0.113.9' };
    expect(clientIp(req(headers))).toBe('203.0.113.9');
  });

  it('trims whitespace around the selected entry', () => {
    expect(clientIp(req({ 'x-forwarded-for': '  203.0.113.9  ' }))).toBe('203.0.113.9');
  });

  it('selects the correct entry with trustedProxyHops: 2 (two proxies in front)', () => {
    // Chain: client, proxyA-observed, proxyB-observed. With 2 trusted hops the address the
    // first trusted proxy saw (the real client) is the second-from-the-right entry.
    const headers = { 'x-forwarded-for': '203.0.113.9, 10.0.0.1, 10.0.0.2' };
    expect(clientIp(req(headers), { trustedProxyHops: 2 })).toBe('10.0.0.1');
  });

  it('clamps trustedProxyHops to the chain length (best-effort leftmost fallback)', () => {
    const headers = { 'x-forwarded-for': '203.0.113.9, 10.0.0.1' };
    expect(clientIp(req(headers), { trustedProxyHops: 5 })).toBe('203.0.113.9');
  });

  it('skips empty entries in the chain', () => {
    const headers = { 'x-forwarded-for': '203.0.113.9, , ' };
    expect(clientIp(req(headers))).toBe('203.0.113.9');
  });

  it('falls back to x-real-ip when X-Forwarded-For is absent', () => {
    expect(clientIp(req({ 'x-real-ip': '198.51.100.7' }))).toBe('198.51.100.7');
  });

  it("falls back to 'unknown' when no proxy headers are present", () => {
    expect(clientIp(req())).toBe('unknown');
  });
});
