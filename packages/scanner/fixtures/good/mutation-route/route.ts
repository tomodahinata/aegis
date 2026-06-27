import { secureRoute } from '@aegiskit/next';
import { cookies } from 'next/headers';

// Cookie-authenticated mutation, but wrapped in secureRoute (origin check on by default).
export const POST = secureRoute({ method: 'POST' }, async () => {
  const store = await cookies();
  void store.get('session');
  return Response.json({ ok: true });
});
