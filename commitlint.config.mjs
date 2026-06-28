/** Conventional Commits — keeps history machine-readable and drives Changesets/release notes. */
export default {
  extends: ['@commitlint/config-conventional'],
  rules: {
    // config-conventional caps body/footer lines at 100 chars. That cap is wrong for our reality:
    // Dependabot auto-bodies embed long changelog/commit URLs, and `BREAKING CHANGE:` footers wrap
    // poorly when hard-wrapped (wrapping a URL also breaks it). We keep every rule that guards
    // machine-readability (type-enum, subject case, header length) and disable only the two length
    // caps that reject otherwise well-formed commits — the sole reason the Dependabot PRs went red.
    'body-max-line-length': [0, 'always', Infinity],
    'footer-max-line-length': [0, 'always', Infinity],
  },
};
