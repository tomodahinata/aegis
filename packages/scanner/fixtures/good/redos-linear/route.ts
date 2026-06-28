import { NextRequest } from 'next/server';

// SAFE: same validation intent and the same untrusted input, but the regex is LINEAR (one quantifier,
// no nesting), so there is no backtracking blowup even on hostile input — nothing to flag.
const USERNAME_RE = /^\w+$/;

export async function GET(req: NextRequest) {
  const username = req.nextUrl.searchParams.get('username') ?? '';
  return Response.json({ ok: USERNAME_RE.test(username) });
}
