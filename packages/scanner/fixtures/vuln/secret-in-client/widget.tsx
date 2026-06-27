'use client';

export function Widget() {
  // A server secret read in a Client Component — bundled straight to the browser.
  const key = process.env.STRIPE_SECRET_KEY;
  return key ? 'configured' : 'missing';
}
