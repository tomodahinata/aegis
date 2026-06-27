import { secureRoute } from '@aegiskit/next';
import { z } from 'zod';
import { env } from '@/env.server';
import { serializeSessionCookie } from '@/lib/auth/cookie';
import { constantTimeEqual } from '@/lib/auth/password';
import { signSessionToken } from '@/lib/auth/session';

// secureRoute applies the origin/CSRF check (login is same-origin) + Zod validation.
export const POST = secureRoute(
  { method: 'POST', body: z.object({ password: z.string().min(1).max(256) }) },
  async ({ body }) => {
    if (!constantTimeEqual(body.password, env.AEGIS_ADMIN_PASSWORD)) {
      return Response.json({ error: 'invalid_credentials' }, { status: 401 });
    }
    const issuedAt = Math.floor(Date.now() / 1000);
    const token = await signSessionToken(
      { sub: 'admin', iat: issuedAt, exp: issuedAt + env.AEGIS_SESSION_TTL_S },
      env.AEGIS_SESSION_SECRET,
    );
    return new Response(null, {
      status: 204,
      headers: { 'Set-Cookie': serializeSessionCookie(token, env.AEGIS_SESSION_TTL_S) },
    });
  },
);
