import { secureRoute } from '@aegiskit/next';
import { cookies } from 'next/headers';

export const POST = secureRoute({ origin: true }, async ({ req }) => {
  const store = await cookies();
  const session = store.get('session');
  const body = await req.json();
  void session;
  void body;
  return Response.json({ ok: true });
});
