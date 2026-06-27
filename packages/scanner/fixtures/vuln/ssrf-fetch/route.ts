import { NextRequest } from 'next/server';

// VULN: a fully attacker-controlled URL is fetched server-side — SSRF. The attacker points it at
// http://169.254.169.254/ (cloud metadata) or an internal service and exfiltrates the response.
export async function GET(req: NextRequest) {
  const target = req.nextUrl.searchParams.get('url') ?? '';
  const res = await fetch(target);
  return new Response(await res.text());
}
