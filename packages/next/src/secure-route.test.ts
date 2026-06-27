import { createMemoryStore, RateLimiter } from '@aegiskit/core';
import { NextRequest, NextResponse } from 'next/server';
import { describe, expect, it } from 'vitest';
import { z } from 'zod';
import { secureRoute } from './secure-route';

function jsonPost(body: unknown, headers: Record<string, string> = {}): NextRequest {
  return new NextRequest('https://app.example.com/api/items', {
    method: 'POST',
    headers: { origin: 'https://app.example.com', 'content-type': 'application/json', ...headers },
    body: JSON.stringify(body),
  });
}

describe('secureRoute', () => {
  it('validates the body and passes fully-typed input to the handler', async () => {
    const handler = secureRoute(
      { method: 'POST', body: z.object({ name: z.string() }) },
      async ({ body }) => NextResponse.json({ name: body.name }),
    );
    const res = await handler(jsonPost({ name: 'widget' }));
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ name: 'widget' });
  });

  it('returns 400 with structured issues on invalid input', async () => {
    const handler = secureRoute(
      { method: 'POST', body: z.object({ name: z.string() }) },
      async () => NextResponse.json({ ok: true }),
    );
    const res = await handler(jsonPost({ name: 123 }));
    expect(res.status).toBe(400);
    const payload = (await res.json()) as { error: { code: string; issues: unknown[] } };
    expect(payload.error.code).toBe('invalid_input');
    expect(payload.error.issues.length).toBeGreaterThan(0);
  });

  it('returns 405 for a disallowed method', async () => {
    const handler = secureRoute({ method: 'POST' }, async () => NextResponse.json({}));
    const res = await handler(
      new NextRequest('https://app.example.com/api/items', { method: 'GET' }),
    );
    expect(res.status).toBe(405);
  });

  it('blocks a cross-origin mutation with 403 (CSRF defense)', async () => {
    const handler = secureRoute({ method: 'POST', body: z.object({}) }, async () =>
      NextResponse.json({}),
    );
    const res = await handler(jsonPost({}, { origin: 'https://evil.com' }));
    expect(res.status).toBe(403);
  });

  it('rate-limits per the configured rule', async () => {
    const limiter = new RateLimiter({ store: createMemoryStore(), now: () => 1_000_000 });
    const handler = secureRoute(
      {
        method: 'POST',
        body: z.object({}),
        rateLimit: { limiter, rule: { limit: 1, windowMs: 60_000, algorithm: 'fixed-window' } },
      },
      async () => NextResponse.json({ ok: true }),
    );
    expect((await handler(jsonPost({}, { 'x-forwarded-for': '9.9.9.9' }))).status).toBe(200);
    expect((await handler(jsonPost({}, { 'x-forwarded-for': '9.9.9.9' }))).status).toBe(429);
  });

  it('validates query and params', async () => {
    const handler = secureRoute(
      { query: z.object({ page: z.string() }), params: z.object({ id: z.string() }) },
      async ({ query, params }) => NextResponse.json({ page: query.page, id: params.id }),
    );
    const req = new NextRequest('https://app.example.com/api/items?page=2', { method: 'GET' });
    const res = await handler(req, { params: Promise.resolve({ id: 'abc' }) });
    expect(await res.json()).toEqual({ page: '2', id: 'abc' });
  });
});
