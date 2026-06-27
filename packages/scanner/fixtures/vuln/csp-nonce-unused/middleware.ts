import { NextResponse } from 'next/server';

function generateNonce() {
  return Math.random().toString(36).slice(2);
}

export function middleware() {
  const nonce = generateNonce();
  const response = NextResponse.next();
  // The nonce is set on a header but the emitted CSP relies on 'unsafe-inline' and never
  // references it — classic dangling-nonce bug.
  response.headers.set('x-nonce', nonce);
  response.headers.set(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self' 'unsafe-inline' https:",
  );
  return response;
}
