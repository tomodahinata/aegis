// SAFE: this regex DOES have catastrophic backtracking (`(a+)+$`), but it is only ever run against a
// trusted constant — no attacker-controlled input reaches it. Taint-gating keeps the rule silent: the
// pattern is a latent smell, not an exploitable ReDoS, and flagging it would be a false positive.
const RELEASE_TAG_RE = /^(a+)+$/;

export function isReleaseTag(): boolean {
  return RELEASE_TAG_RE.test('aaaaaaaa');
}
