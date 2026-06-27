import {
  createConsoleSink,
  createMemoryStore,
  RATE_LIMIT_PRESETS,
  RateLimiter,
  resolveCspMode,
} from '@aegiskit/core';
import { secure } from '@aegiskit/next';
import { NextResponse } from 'next/server';
import { env } from '@/env.server';
import { SESSION_COOKIE } from '@/lib/auth/cookie';
import { verifySessionToken } from '@/lib/auth/session';

const limiter = new RateLimiter({ store: createMemoryStore() });

// Public surfaces: the login page, the login API, and the signature-/handler-gated ingest routes.
function isPublic(pathname: string): boolean {
  return (
    pathname === '/login' ||
    pathname.startsWith('/api/ingest') ||
    pathname.startsWith('/api/auth/login')
  );
}

// The dashboard dogfoods Aegis: secure() applies hardened headers + nonce CSP + rate limits,
// and the chain hook enforces the admin session (redirecting to /login).
export default secure({
  sink: createConsoleSink(),
  cspMode: resolveCspMode(env.NEXT_PUBLIC_CSP_MODE),
  cspReportEndpoint: '/api/ingest/csp',
  rateLimit: {
    limiter,
    rule: RATE_LIMIT_PRESETS.ip,
    match: (req) => req.nextUrl.pathname.startsWith('/api'),
  },
  chain: async (req, { requestHeaders }) => {
    if (isPublic(req.nextUrl.pathname)) {
      return NextResponse.next({ request: { headers: requestHeaders } });
    }
    const token = req.cookies.get(SESSION_COOKIE)?.value;
    const session = token
      ? await verifySessionToken(token, env.AEGIS_SESSION_SECRET)
      : ({ ok: false } as const);
    if (!session.ok) {
      const url = req.nextUrl.clone();
      url.pathname = '/login';
      return NextResponse.redirect(url);
    }
    return NextResponse.next({ request: { headers: requestHeaders } });
  },
});

export const config = {
  matcher: ['/((?!_next/static|_next/image|favicon.ico).*)'],
};
