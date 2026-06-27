import { forEachDescendant, ts } from '../internal/ast';
import { docsUrlFor, type Rule } from '../rule';

/** Names that mark a value as security-sensitive. Anchored enough to avoid `monkey`/`keyboard`. */
const SECURITY_NAME =
  /token|secret|otp|nonce|password|passcode|session|csrf|salt|api_?key|verif|reset|cookie/i;

function isMathRandom(node: ts.Node): node is ts.CallExpression {
  return (
    ts.isCallExpression(node) &&
    ts.isPropertyAccessExpression(node.expression) &&
    ts.isIdentifier(node.expression.expression) &&
    node.expression.expression.text === 'Math' &&
    node.expression.name.text === 'random'
  );
}

/** The name `node`'s value is bound to (declaration / property / assignment / function), if any. */
function namingContext(node: ts.Node): string | undefined {
  for (let cur = node.parent; cur; cur = cur.parent) {
    if (ts.isVariableDeclaration(cur) && ts.isIdentifier(cur.name)) {
      return cur.name.text;
    }
    if (ts.isPropertyAssignment(cur)) {
      return cur.name.getText();
    }
    if (ts.isBinaryExpression(cur) && cur.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
      return cur.left.getText();
    }
    if (ts.isFunctionDeclaration(cur)) {
      return cur.name?.text;
    }
    if (ts.isBlock(cur) || ts.isSourceFile(cur)) {
      return undefined; // do not cross a statement/scope boundary
    }
  }
  return undefined;
}

export const insecureRandomness: Rule = {
  meta: {
    id: 'crypto/insecure-randomness',
    title: 'Security token built from Math.random()',
    severity: 'HIGH',
    owasp: 'A02:2021 Cryptographic Failures',
    docsUrl: docsUrlFor('crypto/insecure-randomness'),
  },
  appliesTo: (file) => file.text.includes('Math.random'),
  check(ctx) {
    forEachDescendant(ctx.file.sourceFile, (node) => {
      if (!isMathRandom(node)) {
        return;
      }
      const name = namingContext(node);
      if (name && SECURITY_NAME.test(name)) {
        ctx.report({
          node,
          confidence: 'high',
          message:
            'Math.random() generates this security value — it is predictable (not cryptographically random), so an attacker can guess tokens, session ids, or one-time codes.',
          remediation:
            'Use crypto.getRandomValues() (or crypto.randomUUID() / node:crypto randomBytes) for any token, secret, salt, or session identifier.',
          evidence: 'Math.random()',
        });
      }
    });
  },
};

const WEAK_HASH = /^(?:md5|sha1)$/i;

export const weakHash: Rule = {
  meta: {
    id: 'crypto/weak-hash',
    title: 'Weak hash algorithm (MD5/SHA-1)',
    severity: 'HIGH',
    owasp: 'A02:2021 Cryptographic Failures',
    docsUrl: docsUrlFor('crypto/weak-hash'),
  },
  appliesTo: (file) => file.text.includes('createHash'),
  check(ctx) {
    forEachDescendant(ctx.file.sourceFile, (node) => {
      if (!ts.isCallExpression(node)) {
        return;
      }
      // Both `crypto.createHash('md5')` and the imported `createHash('md5')`.
      const callee = node.expression;
      const isCreateHash = ts.isPropertyAccessExpression(callee)
        ? callee.name.text === 'createHash'
        : ts.isIdentifier(callee) && callee.text === 'createHash';
      if (!isCreateHash) {
        return;
      }
      const algorithm = node.arguments[0];
      if (algorithm && ts.isStringLiteralLike(algorithm) && WEAK_HASH.test(algorithm.text)) {
        ctx.report({
          node,
          // Medium: it may be a non-security checksum, so it informs without blocking CI.
          confidence: 'medium',
          message: `${algorithm.text} is cryptographically broken — unsafe for signatures, integrity, or password hashing.`,
          remediation:
            'Use SHA-256 or stronger for integrity/signatures. For passwords use a KDF (scrypt, argon2, or bcrypt), never a plain hash.',
          evidence: `createHash('${algorithm.text}')`,
        });
      }
    });
  },
};

// Names of a value whose === comparison is a genuine secret-verification boundary. Deliberately NOT
// `token`/`password`/`otp`/`passcode` — those words are massively overloaded in real apps (parser
// tokens, `password === confirmPassword` form checks, `OTP_LENGTH` constants), so matching them is
// almost all false positives. A real timing attack targets a signature/MAC/digest comparison.
const SECRET_COMPARE = /signature|\bhmac\b|digest|\bmac\b|\bsecret\b|api_?key/i;

function comparedName(expr: ts.Expression): string | undefined {
  if (ts.isIdentifier(expr)) {
    return expr.text;
  }
  if (ts.isPropertyAccessExpression(expr)) {
    return expr.name.text;
  }
  return undefined;
}

/**
 * The non-secret operand of a *real* verification is the other party's value (a variable/property),
 * never a literal — you never hard-code the expected signature, and `x === undefined`/`=== 6` are
 * presence/length checks, not secret comparisons. So a literal operand means this is not a timing sink.
 */
function isTrivialOperand(expr: ts.Expression): boolean {
  return (
    expr.kind === ts.SyntaxKind.NullKeyword ||
    expr.kind === ts.SyntaxKind.TrueKeyword ||
    expr.kind === ts.SyntaxKind.FalseKeyword ||
    ts.isNumericLiteral(expr) ||
    ts.isStringLiteralLike(expr) ||
    (ts.isIdentifier(expr) && expr.text === 'undefined')
  );
}

const EQUALITY: ReadonlySet<ts.SyntaxKind> = new Set([
  ts.SyntaxKind.EqualsEqualsEqualsToken,
  ts.SyntaxKind.ExclamationEqualsEqualsToken,
  ts.SyntaxKind.EqualsEqualsToken,
  ts.SyntaxKind.ExclamationEqualsToken,
]);

export const nonConstantTimeCompare: Rule = {
  meta: {
    id: 'crypto/non-constant-time-compare',
    title: 'Secret compared with a non-constant-time operator',
    severity: 'HIGH',
    owasp: 'A02:2021 Cryptographic Failures',
    docsUrl: docsUrlFor('crypto/non-constant-time-compare'),
  },
  appliesTo: (file) => /[!=]==?/.test(file.text) && SECRET_COMPARE.test(file.text),
  check(ctx) {
    forEachDescendant(ctx.file.sourceFile, (node) => {
      if (!ts.isBinaryExpression(node) || !EQUALITY.has(node.operatorToken.kind)) {
        return;
      }
      const leftName = comparedName(node.left);
      const rightName = comparedName(node.right);
      const secretSide =
        leftName && SECRET_COMPARE.test(leftName)
          ? node.left
          : rightName && SECRET_COMPARE.test(rightName)
            ? node.right
            : undefined;
      if (!secretSide) {
        return;
      }
      const other = secretSide === node.left ? node.right : node.left;
      if (isTrivialOperand(other)) {
        return; // `if (token === undefined)` is a presence check, not a secret comparison
      }
      ctx.report({
        node,
        confidence: 'high',
        message:
          'A secret/token/signature is compared with === — the early-exit timing of string equality leaks how many leading characters match, enabling a timing attack.',
        remediation:
          'Compare secrets with crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b)) (guard equal lengths first). Never use ===/!== on a secret or signature.',
        evidence: node.getText(ctx.file.sourceFile).slice(0, 60),
      });
    });
  },
};
