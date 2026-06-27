'use client';

export function Panel() {
  // Destructured secret read in a Client Component — bundled straight to the browser.
  const { STRIPE_SECRET_KEY } = process.env;
  return STRIPE_SECRET_KEY ? 'configured' : 'missing';
}
