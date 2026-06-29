import { ts } from '../internal/ast';
import { looksLikeCharsetAlphabet, shannonEntropy } from '../internal/entropy';
import { collectStringLikes } from '../internal/patterns';
import { docsUrlFor, type Rule } from '../rule';

const ALLOW_PRAGMA = 'aegis-allow-secret';
const TEST_FILE = /\.(?:test|spec)\.[tj]sx?$/;

// Generic high-entropy fallback: only a long, unbroken token with mixed character classes.
const TOKEN_SHAPE = /^[A-Za-z0-9_-]{40,}$/;
const MIN_ENTROPY = 4.0;

// `selfProving`: the regex is fully anchored AND fixed-length, so the SHAPE alone proves a credential —
// the placeholder entropy guard below must NOT run on it. That guard keys on the lowercase-leading
// open-ended prefixes (`sk_`, `ghp_`, …), where it costs nothing; but the AWS id is the inverse — an
// UPPERCASE-only prefix over a `[0-9A-Z]` body, so a real digit-free id is single-class and the guard
// would silently drop it (a true false negative on a HIGH rule, ~1 in 180 real ids). `AKIA…{16}$` cannot
// be a dictionary placeholder, so it is exempt.
const KNOWN_PREFIXES: ReadonlyArray<{
  readonly re: RegExp;
  readonly label: string;
  readonly selfProving?: boolean;
}> = [
  { re: /^sk_live_[A-Za-z0-9]{10,}/, label: 'Stripe live secret key' },
  { re: /^sk_test_[A-Za-z0-9]{10,}/, label: 'Stripe test secret key' },
  { re: /^rk_live_[A-Za-z0-9]{10,}/, label: 'Stripe restricted key' },
  { re: /^AKIA[0-9A-Z]{16}$/, label: 'AWS access key id', selfProving: true },
  { re: /^ghp_[A-Za-z0-9]{30,}/, label: 'GitHub personal access token' },
  { re: /^github_pat_[A-Za-z0-9_]{20,}/, label: 'GitHub fine-grained PAT' },
  { re: /^xox[baprs]-[A-Za-z0-9-]{10,}/, label: 'Slack token' },
];

function maskSecret(value: string): string {
  return value.length <= 12 ? `${value.slice(0, 2)}…` : `${value.slice(0, 8)}…${value.slice(-4)}`;
}

/** The `role` claim of a JWT, if `value` is a decodable JWT. */
function jwtRole(value: string): string | undefined {
  const parts = value.split('.');
  const payload = parts[1];
  if (parts.length < 2 || payload === undefined || !value.startsWith('eyJ')) {
    return undefined;
  }
  try {
    const decoded: unknown = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    const role = (decoded as { role?: unknown }).role;
    return typeof role === 'string' ? role : undefined;
  } catch {
    return undefined;
  }
}

/**
 * A real credential body is high-entropy with mixed character classes; an obvious placeholder default —
 * a Stripe-prefixed dictionary word such as a "…_placeholder" or "…_your_key_here" stub — is single-class
 * yet happens to carry a known prefix. Require ≥ 2 of {lowercase, uppercase, digit} so a placeholder is not
 * mis-reported as a leaked credential, while a realistic mixed-class key still fires. This is a precision
 * guard, not a recall hole: a genuine key with a lowercase-leading prefix is overwhelmingly multi-class.
 * Applied ONLY to the open-ended prefixes; a `selfProving` shape (the anchored, fixed-length AWS id, whose
 * UPPERCASE-only prefix would make a digit-free key single-class) bypasses it — see KNOWN_PREFIXES.
 */
function carriesCredentialEntropy(value: string): boolean {
  return [/[a-z]/, /[A-Z]/, /[0-9]/].filter((re) => re.test(value)).length >= 2;
}

function looksLikeGenericSecret(value: string): boolean {
  return (
    TOKEN_SHAPE.test(value) &&
    // A base62/base64/hex encoder's alphabet table is long, mixed-case, and high-entropy — exactly the
    // generic-secret shape — but it is a public constant, not a credential. Exclude it (a real-world FP
    // on base62/base64url ALPHABET constants).
    !looksLikeCharsetAlphabet(value) &&
    /[a-z]/.test(value) &&
    /[A-Z]/.test(value) &&
    /[0-9]/.test(value) &&
    shannonEntropy(value) >= MIN_ENTROPY
  );
}

export const committedSecretLiteral: Rule = {
  meta: {
    id: 'secrets/committed-literal',
    title: 'Hard-coded secret in committed source',
    severity: 'HIGH',
    owasp: 'A05:2021 Security Misconfiguration',
    docsUrl: docsUrlFor('secrets/committed-literal'),
  },
  appliesTo: (file) => !TEST_FILE.test(file.path),
  check(ctx) {
    const sourceFile = ctx.file.sourceFile;
    const lines = ctx.file.text.split(/\r?\n/);

    for (const { node } of collectStringLikes(sourceFile)) {
      if (!ts.isStringLiteralLike(node)) {
        continue; // skip template expressions with substitutions
      }
      const value = node.text;
      if (value.length < 12) {
        continue;
      }
      const lineIndex = sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile)).line;
      if (
        (lines[lineIndex] ?? '').includes(ALLOW_PRAGMA) ||
        (lines[lineIndex - 1] ?? '').includes(ALLOW_PRAGMA)
      ) {
        continue;
      }

      const prefix = KNOWN_PREFIXES.find((entry) => entry.re.test(value));
      if (prefix) {
        if (!prefix.selfProving && !carriesCredentialEntropy(value)) {
          continue; // an open-ended-prefix shape but a single-class placeholder default — not a real credential
        }
        ctx.report({
          node,
          confidence: 'high',
          message: `A ${prefix.label} appears to be hard-coded in committed source.`,
          remediation:
            'Move it to a server-only env var (defineServerEnv) and ROTATE the exposed credential immediately.',
          evidence: maskSecret(value),
        });
        continue;
      }

      const role = jwtRole(value);
      if (role === 'service_role') {
        ctx.report({
          node,
          confidence: 'high',
          message:
            'A Supabase service_role JWT is hard-coded in source — it bypasses Row Level Security.',
          remediation: 'Remove it, rotate the key, and read it only from a server-only env var.',
          evidence: maskSecret(value),
        });
        continue;
      }
      if (role === 'anon') {
        continue; // anon/publishable key — safe by design
      }

      if (looksLikeGenericSecret(value)) {
        ctx.report({
          node,
          confidence: 'low',
          message: 'A long, high-entropy literal looks like it could be a hard-coded secret.',
          remediation:
            'If this is a credential, move it to an env var; otherwise ignore (low confidence).',
          evidence: maskSecret(value),
        });
      }
    }
  },
};
