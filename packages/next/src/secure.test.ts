import {
  createMemoryStore,
  RateLimiter,
  type SecurityEvent,
  type SecuritySink,
} from '@aegiskit/core';
import { NextRequest, NextResponse } from 'next/server';
import { describe, expect, it } from 'vitest';
import { NONCE_HEADER } from './constants';
import { secure } from './secure';

function collectingSink(): { sink: SecuritySink; events: SecurityEvent[] } {
  const events: SecurityEvent[] = [];
  return { sink: { emit: (event) => void events.push(event) }, events };
}

function cspHeaders(res: NextResponse): string[] {
  const found: string[] = [];
  const enforce = res.headers.get('content-security-policy');
  const reportOnly = res.headers.get('content-security-policy-report-only');
  if (enforce) found.push(enforce);
  if (reportOnly) found.push(reportOnly);
  return found;
}

const get = (path = '/dashboard', headers?: Record<string, string>) =>
  new NextRequest(`https://app.example.com${path}`, {
    method: 'GET',
    ...(headers ? { headers } : {}),
  });

describe('secure()', () => {
  it('applies the hardened security headers to the response', async () => {
    const res = await secure()(get());
    expect(res.headers.get('X-Frame-Options')).toBe('SAMEORIGIN');
    expect(res.headers.get('X-Content-Type-Options')).toBe('nosniff');
    expect(res.headers.get('Strict-Transport-Security')).toContain('max-age=');
    expect(res.headers.get('Referrer-Policy')).toBe('strict-origin-when-cross-origin');
  });

  it('emits EXACTLY ONE CSP header, and it carries the request nonce (the B1 regression)', async () => {
    const res = await secure({ cspMode: 'enforce' })(get());
    const headers = cspHeaders(res);
    expect(headers).toHaveLength(1);

    const nonceFromHeader = res.headers.get(NONCE_HEADER);
    expect(nonceFromHeader).toBeTruthy();
    const nonceInCsp = headers[0]?.match(/'nonce-([^']+)'/)?.[1];
    expect(nonceInCsp).toBe(nonceFromHeader);
  });

  it('defaults to report-only mode', async () => {
    const res = await secure()(get());
    expect(res.headers.get('content-security-policy-report-only')).toBeTruthy();
    expect(res.headers.get('content-security-policy')).toBeNull();
  });

  it('wires cspReportEndpoint into the CSP and a Reporting-Endpoints header', async () => {
    const res = await secure({ cspMode: 'enforce', cspReportEndpoint: '/api/aegis/csp-report' })(
      get(),
    );
    const csp = res.headers.get('content-security-policy') ?? '';
    expect(csp).toContain('report-uri /api/aegis/csp-report');
    expect(csp).toContain('report-to aegis');
    expect(res.headers.get('Reporting-Endpoints')).toContain('/api/aegis/csp-report');
  });

  it('can disable CSP entirely', async () => {
    const res = await secure({ csp: false })(get());
    expect(cspHeaders(res)).toHaveLength(0);
    // ...but still applies the other security headers.
    expect(res.headers.get('X-Content-Type-Options')).toBe('nosniff');
  });

  it('blocks a cross-origin mutating request with 403 and a security event', async () => {
    const { sink, events } = collectingSink();
    const req = new NextRequest('https://app.example.com/api/transfer', {
      method: 'POST',
      headers: { origin: 'https://evil.com' },
    });
    const res = await secure({ sink })(req);
    expect(res.status).toBe(403);
    expect(events[0]?.type).toBe('origin_block');
  });

  it('allows a same-origin mutating request', async () => {
    const req = new NextRequest('https://app.example.com/api/transfer', {
      method: 'POST',
      headers: { origin: 'https://app.example.com' },
    });
    const res = await secure()(req);
    expect(res.status).not.toBe(403);
  });

  it('rate-limits and returns 429 with Retry-After + standard headers', async () => {
    const limiter = new RateLimiter({ store: createMemoryStore(), now: () => 1_000_000 });
    const { sink, events } = collectingSink();
    const mw = secure({
      sink,
      rateLimit: { limiter, rule: { limit: 1, windowMs: 60_000, algorithm: 'fixed-window' } },
    });
    const headers = { 'x-forwarded-for': '203.0.113.9' };

    const first = await mw(get('/api', headers));
    expect(first.status).not.toBe(429);

    const second = await mw(get('/api', headers));
    expect(second.status).toBe(429);
    expect(second.headers.get('Retry-After')).toBeTruthy();
    expect(second.headers.get('X-RateLimit-Limit')).toBe('1');
    expect(events.at(-1)?.type).toBe('rate_limit_block');
  });

  it('runs the host app middleware via chain and still decorates the response', async () => {
    let receivedNonce = '';
    const res = await secure({
      chain: (_req, ctx) => {
        receivedNonce = ctx.nonce;
        // Simulate an app redirect (e.g. unauthenticated → /login). NextResponse (unlike a
        // plain Response.redirect) has mutable headers, so Aegis can still decorate it.
        return NextResponse.redirect(new URL('https://app.example.com/login'), 307);
      },
    })(get('/private'));
    expect(receivedNonce).toBeTruthy();
    // CSP + headers are applied even to the app's own response.
    expect(res.headers.get('content-security-policy-report-only')).toBeTruthy();
    expect(res.headers.get(NONCE_HEADER)).toBe(receivedNonce);
  });
});
