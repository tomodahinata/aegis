/**
 * A hermetic mock target for tests: a loopback `node:http` server exposing a VULNERABLE and a SAFE
 * endpoint for each probe. It is the DAST analogue of the scanner's fixtures — every probe must fire on
 * its vulnerable endpoint (true positive) and stay silent on its safe twin (the zero-false-positive gate).
 */

import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';

export interface MockTarget {
  readonly origin: string;
  requestCount(): number;
  close(): Promise<void>;
}

function htmlEscape(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// Truthy boolean condition `'1'='1`; falsy `'1'='2` — same vs different digits (no trailing quote,
// matching a real injected tautology).
function isTruthyCondition(value: string): boolean {
  const match = /'(\d)'='(\d)/.exec(value);
  return match ? match[1] === match[2] : true;
}

export async function startMockTarget(): Promise<MockTarget> {
  let requests = 0;
  let rateLimitHits = 0;

  const server: Server = createServer(async (req, res) => {
    requests += 1;
    const url = new URL(req.url ?? '/', 'http://localhost');
    const path = url.pathname;
    const q = url.searchParams;
    const send = (status: number, body = '', headers: Record<string, string> = {}): void => {
      res.writeHead(status, headers);
      res.end(body);
    };

    switch (path) {
      case '/headers-missing':
        return send(200, 'ok');
      case '/headers-present':
        return send(200, 'ok', {
          'content-security-policy': "default-src 'self'",
          'x-frame-options': 'DENY',
          'x-content-type-options': 'nosniff',
          'referrer-policy': 'no-referrer',
        });
      case '/cookie-insecure':
        return send(200, 'ok', { 'set-cookie': 'sid=abc123' });
      case '/cookie-secure':
        return send(200, 'ok', { 'set-cookie': 'sid=abc123; HttpOnly; SameSite=Lax' });
      case '/error-stack':
        return send(
          500,
          'TypeError: x is not a function\n    at Object.<anonymous> (/app/route.ts:12:3)',
        );
      case '/error-generic':
        return send(400, JSON.stringify({ error: 'bad_request' }), {
          'content-type': 'application/json',
        });
      case '/redirect-open':
        return send(302, '', { location: q.get('next') ?? '/' });
      case '/redirect-safe':
        return send(302, '', { location: '/dashboard' });
      case '/xss-reflect':
        return send(200, `<div>${q.get('q') ?? ''}</div>`, { 'content-type': 'text/html' });
      case '/xss-escaped':
        return send(200, `<div>${htmlEscape(q.get('q') ?? '')}</div>`, {
          'content-type': 'text/html',
        });
      case '/xss-json':
        return send(200, JSON.stringify({ q: q.get('q') ?? '' }), {
          'content-type': 'application/json',
        });
      case '/sqli-boolean': {
        const id = q.get('id') ?? '';
        return send(200, isTruthyCondition(id) ? '<h1>Widget 1</h1><p>in stock</p>' : 'Not found', {
          'content-type': 'text/html',
        });
      }
      case '/sqli-error': {
        const id = q.get('id') ?? '';
        return id.includes("'")
          ? send(500, 'PostgresError: syntax error at or near "\'"')
          : send(200, '<h1>Widget 1</h1>', { 'content-type': 'text/html' });
      }
      case '/sqli-parameterized':
        return send(200, '<h1>Widget 1</h1><p>in stock</p>', { 'content-type': 'text/html' });
      case '/ssrf-fetch': {
        const target = q.get('url');
        if (target) {
          await fetch(target).catch(() => undefined); // the vulnerable server-side fetch
        }
        return send(200, 'fetched');
      }
      case '/ssrf-blocked':
        return send(200, 'blocked'); // validates host, never fetches
      case '/noratelimit':
        return send(200, 'ok');
      case '/ratelimited':
        rateLimitHits += 1;
        return rateLimitHits > 3 ? send(429, 'slow down') : send(200, 'ok');
      case '/protected-open':
        return send(200, 'TOP SECRET dashboard data');
      case '/protected-guarded':
        return req.headers.cookie || req.headers.authorization
          ? send(200, 'data')
          : send(401, 'unauthorized');
      case '/obj/1':
        return send(200, 'order #1 — total $42 — card ****1234', { 'content-type': 'text/plain' });
      case '/obj-scoped/1': {
        const cookie = req.headers.cookie ?? '';
        return cookie.includes('who=alice')
          ? send(200, 'order #1 — total $42 — card ****1234', { 'content-type': 'text/plain' })
          : send(403, 'forbidden');
      }
      default:
        return send(404, 'not found');
    }
  });

  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address() as AddressInfo;
  return {
    origin: `http://127.0.0.1:${address.port}`,
    requestCount: () => requests,
    close: () =>
      new Promise<void>((resolve, reject) =>
        server.close((error) => (error ? reject(error) : resolve())),
      ),
  };
}
