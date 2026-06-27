import { redirect } from 'next/navigation';
import { NextRequest } from 'next/server';

// VULN: the redirect target comes straight from the query string. A crafted `?next=https://evil.example`
// link bounces the user to an attacker site (open redirect / phishing).
export async function GET(req: NextRequest) {
  const next = req.nextUrl.searchParams.get('next') ?? '';
  redirect(next);
}
