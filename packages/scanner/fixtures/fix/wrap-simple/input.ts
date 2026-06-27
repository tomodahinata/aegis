import { cookies } from 'next/headers';

export async function POST(req: Request) {
  const store = await cookies();
  const session = store.get('session');
  const body = await req.json();
  void session;
  void body;
  return Response.json({ ok: true });
}
