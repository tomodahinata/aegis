// VULN: a password-reset token is built from Math.random(), which is not cryptographically random.
// An attacker who knows the algorithm can predict tokens and take over accounts.
export function createResetToken(): string {
  const resetToken = Math.random().toString(36).slice(2);
  return resetToken;
}
