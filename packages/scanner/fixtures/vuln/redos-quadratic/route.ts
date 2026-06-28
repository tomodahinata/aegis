import { NextRequest } from 'next/server';

// VULN: untrusted input is validated with a regex whose two adjacent unbounded quantifiers over the same
// class, pinned by `$`, force O(n²) backtracking on a failing input. With no length limit, a ~100 KB
// string costs seconds of CPU per request (a quadratic ReDoS / denial of service).
const CODE_RE = /^\d+\d+$/;

export async function GET(req: NextRequest) {
  const code = req.nextUrl.searchParams.get('code') ?? '';
  return Response.json({ ok: CODE_RE.test(code) });
}
