import { NextRequest } from 'next/server';

// SAFE: the input is resolved against a FIXED base, pinning the host. The attacker controls only the
// path, never the destination server, so it is not SSRF.
const API_BASE = 'https://api.internal.example.com';

export async function GET(req: NextRequest) {
  const path = req.nextUrl.searchParams.get('path') ?? '';
  const url = new URL(path, API_BASE);
  const res = await fetch(url);
  return new Response(await res.text());
}
