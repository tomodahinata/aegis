import { ts } from '../internal/ast';
import { shannonEntropy } from '../internal/entropy';
import { collectStringLikes } from '../internal/patterns';
import { docsUrlFor, type Rule } from '../rule';

const ALLOW_PRAGMA = 'aegis-allow-secret';
const TEST_FILE = /\.(?:test|spec)\.[tj]sx?$/;

// Generic high-entropy fallback: only a long, unbroken token with mixed character classes.
const TOKEN_SHAPE = /^[A-Za-z0-9_-]{40,}$/;
const MIN_ENTROPY = 4.0;

const KNOWN_PREFIXES: ReadonlyArray<{ readonly re: RegExp; readonly label: string }> = [
  { re: /^sk_live_[A-Za-z0-9]{10,}/, label: 'Stripe live secret key' },
  { re: /^sk_test_[A-Za-z0-9]{10,}/, label: 'Stripe test secret key' },
  { re: /^rk_live_[A-Za-z0-9]{10,}/, label: 'Stripe restricted key' },
  { re: /^AKIA[0-9A-Z]{16}$/, label: 'AWS access key id' },
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

function looksLikeGenericSecret(value: string): boolean {
  return (
    TOKEN_SHAPE.test(value) &&
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
