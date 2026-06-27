import { cookies } from 'next/headers';

// Cookie-authed mutation that ALSO authenticates via a bearer token. CSRF needs ambient cookie
// authority to be exploitable; bearer/API-key auth is not ambient, so this is NOT a CSRF target.
export async function POST(req: Request) {
  const store = await cookies();
  void store.get('session');
  const token = req.headers.get('Authorization');
  if (!token?.startsWith('Bearer ')) {
    return new Response('unauthorized', { status: 401 });
  }
  return Response.json({ ok: true });
}
