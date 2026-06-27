// VULN: a webhook signature is compared with === . String equality short-circuits on the first
// differing byte, leaking timing that lets an attacker forge a valid signature byte by byte.
export function verifyWebhook(providedSignature: string, expectedSignature: string): boolean {
  return providedSignature === expectedSignature;
}
