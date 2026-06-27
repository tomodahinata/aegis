'use client';

// A Client Component reading only a public NEXT_PUBLIC_ value — must NOT be flagged.
export function Header() {
  const url = process.env.NEXT_PUBLIC_SUPABASE_URL;
  return url ?? '';
}
