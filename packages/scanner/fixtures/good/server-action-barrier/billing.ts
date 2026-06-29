// Reads a server secret. A Client Component reaches this only THROUGH `./action`, which is a
// `"use server"` Server Actions module — an RPC boundary whose body and import subtree never enter the
// browser bundle. So the secret is NOT client-reachable and must not be flagged (env/secret-in-client).
// This is the canonical safe counterpart to vuln/secret-reachable-from-client, which lacks the boundary.
export function getStripe(): string {
  return process.env.STRIPE_SECRET_KEY ?? '';
}
