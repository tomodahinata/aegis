import { redirect } from 'next/navigation';
import { NextRequest } from 'next/server';

// SAFE: the redirect target is a same-site RELATIVE path (the input only fills a path segment), so it
// cannot send the user to another origin.
export async function GET(req: NextRequest) {
  const id = req.nextUrl.searchParams.get('id') ?? '';
  redirect(`/dashboard/${id}`);
}
