import 'server-only';

// Secrets read in a server-only module — correct, never flagged.
export const databaseUrl = process.env.DATABASE_URL;
export const stripeSecret = process.env.STRIPE_SECRET_KEY;
