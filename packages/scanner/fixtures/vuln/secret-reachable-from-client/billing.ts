// Not a Client Component itself, but a Client Component imports it (see panel.tsx), so a bundler
// pulls this secret into the browser build. Flagged via `reachableFromClient`, not direct context.
export const stripeKey = process.env.STRIPE_SECRET_KEY;
