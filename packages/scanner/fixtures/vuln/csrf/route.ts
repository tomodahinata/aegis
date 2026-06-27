import { cookies } from 'next/headers';

export async function POST(req: Request) {
  const store = await cookies();
  const session = store.get('session');
  // Cookie-authenticated mutation with NO Origin/CSRF check (Route Handlers get none by default).
  const body = await req.json();
  void session;
  void body;
  return Response.json({ ok: true });
}
