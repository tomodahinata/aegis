import { secureRoute } from '@aegiskit/next';
import { clearSessionCookie } from '@/lib/auth/cookie';

export const POST = secureRoute(
  { method: 'POST' },
  async () => new Response(null, { status: 204, headers: { 'Set-Cookie': clearSessionCookie() } }),
);
