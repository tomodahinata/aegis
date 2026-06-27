import {
  createMemoryStore,
  RateLimiter,
  type SecurityEvent,
  type SecuritySink,
} from '@aegiskit/core';
import { describe, expect, it } from 'vitest';
import { createCspReportHandler } from './csp-report';

function collectingSink(): { sink: SecuritySink; events: SecurityEvent[] } {
  const events: SecurityEvent[] = [];
  return { sink: { emit: (e) => void events.push(e) }, events };
}

function cspRequest(body: string, contentType = 'application/csp-report'): Request {
  return new Request('https://app.example.com/api/aegis/csp-report', {
    method: 'POST',
    headers: { 'content-type': contentType },
    body,
  });
}

describe('createCspReportHandler', () => {
  it('emits a csp_violation for a legacy report and returns 204', async () => {
    const { sink, events } = collectingSink();
    const res = await createCspReportHandler({ sink })(
      cspRequest(
        JSON.stringify({
          'csp-report': {
            'effective-directive': 'script-src',
            'blocked-uri': 'https://evil.example/x.js',
            'document-uri': 'https://app.example.com/',
          },
        }),
      ),
    );
    expect(res.status).toBe(204);
    expect(events[0]).toMatchObject({
      type: 'csp_violation',
      directive: 'script-src',
      blockedUri: 'https://evil.example/x.js',
      path: 'https://app.example.com/',
    });
  });

  it('handles the Reporting-API array form and ignores non-CSP entries', async () => {
    const { sink, events } = collectingSink();
    const body = JSON.stringify([
      {
        type: 'csp-violation',
        body: {
          effectiveDirective: 'img-src',
          blockedURL: 'https://evil.example/p.png',
          documentURL: 'https://app/',
        },
      },
      { type: 'deprecation', body: {} },
    ]);
    const res = await createCspReportHandler({ sink })(
      cspRequest(body, 'application/reports+json'),
    );
    expect(res.status).toBe(204);
    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({
      type: 'csp_violation',
      directive: 'img-src',
      blockedUri: 'https://evil.example/p.png',
    });
  });

  it('rejects wrong method (405) and content-type (415)', async () => {
    const handler = createCspReportHandler({ sink: collectingSink().sink });
    expect((await handler(new Request('https://app/x', { method: 'GET' }))).status).toBe(405);
    expect(
      (
        await handler(
          new Request('https://app/x', {
            method: 'POST',
            headers: { 'content-type': 'text/plain' },
            body: 'x',
          }),
        )
      ).status,
    ).toBe(415);
  });

  it('swallows malformed JSON with 204 and emits nothing', async () => {
    const { sink, events } = collectingSink();
    const res = await createCspReportHandler({ sink })(cspRequest('not json'));
    expect(res.status).toBe(204);
    expect(events).toHaveLength(0);
  });

  it('returns 413 for an oversized body', async () => {
    const res = await createCspReportHandler({ sink: collectingSink().sink, maxBodyBytes: 10 })(
      cspRequest(JSON.stringify({ 'csp-report': { 'blocked-uri': 'x'.repeat(100) } })),
    );
    expect(res.status).toBe(413);
  });

  it('rate-limits report floods', async () => {
    const limiter = new RateLimiter({ store: createMemoryStore(), now: () => 1_000_000 });
    const handler = createCspReportHandler({
      sink: collectingSink().sink,
      rateLimit: { limiter, rule: { limit: 1, windowMs: 60_000, algorithm: 'fixed-window' } },
    });
    const req = () => cspRequest(JSON.stringify({ 'csp-report': { 'blocked-uri': 'x' } }));
    expect((await handler(req())).status).toBe(204);
    expect((await handler(req())).status).toBe(429);
  });

  it('never reflects input in the response body', async () => {
    const res = await createCspReportHandler({ sink: collectingSink().sink })(
      cspRequest(JSON.stringify({ 'csp-report': { 'blocked-uri': 'SENTINEL_VALUE' } })),
    );
    expect(await res.text()).toBe('');
  });
});
