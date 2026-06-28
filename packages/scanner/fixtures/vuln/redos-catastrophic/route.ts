import { NextRequest } from 'next/server';

// VULN: attacker-controlled input is validated with a regex that has nested unbounded quantifiers
// (`(\w+)+$` — star height 2). A short crafted string like "aaaaaaaaaaaaaaaaaaaa!" forces exponential
// backtracking, pinning the request thread at 100% CPU — a ReDoS denial of service. Length limits do
// not help: 2^n blows up well before any sane max length.
const USERNAME_RE = /^(\w+)+$/;

export async function GET(req: NextRequest) {
  const username = req.nextUrl.searchParams.get('username') ?? '';
  if (USERNAME_RE.test(username)) {
    return Response.json({ ok: true });
  }
  return new Response('invalid', { status: 400 });
}
