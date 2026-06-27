/**
 * RLS predicate analysis — the core of "does this policy actually scope rows to the caller?". Two pure,
 * fail-secure responsibilities, deliberately NOT a SQL parser:
 *
 *  1. `extractClauseBody` — pull the raw expression out of `USING (…)` / `WITH CHECK (…)`, counting
 *     parentheses only over real code (string literals, comments, and dollar-quoted bodies are masked
 *     first, mirroring `lexer.ts`), so a `)` inside `'…'` or a trailing `-- comment` never truncates it.
 *  2. `classifyPredicate` — map a predicate to a `PredicateClass`. The one class that matters is
 *     `authenticated-only`: a predicate that proves a session exists (auth.role()/auth.uid() IS NOT NULL)
 *     but binds no row to the caller — RLS that exists yet lets every logged-in user read every row.
 *
 * Recall trade-off (documented, intentional): anything we cannot classify with confidence falls through
 * to `unknown` and is never flagged. On this rule class we prefer a false negative to a false positive —
 * the zero-false-positive gate is the product's trust wedge.
 */

import type { PolicyCommand } from './model';

export type PredicateClass =
  // No clause present (e.g. an INSERT policy has no USING).
  | 'absent'
  // Literally `true` — unconditional. Owned by `permissiveWritePolicy` / intentional reference reads.
  | 'unconditional'
  // An auth identity (auth.uid()/auth.jwt()->>'sub') compared to a column — the CORRECT pattern.
  | 'owner-bound'
  // Proves the caller is authenticated but binds no row to them — THE gap this feature closes.
  | 'authenticated-only'
  // A membership subquery (`… IN (SELECT … FROM memberships WHERE user_id = auth.uid())`) — the
  // legitimate multi-tenant pattern; unverifiable statically, so suppressed (fail-secure).
  | 'role-delegated'
  // Delegates the decision to a custom function (`has_access(id)`) — unverifiable, so suppressed.
  | 'function-delegated'
  // Anything else (e.g. `status = 'published'`) — not flagged (fail-secure).
  | 'unknown';

// ── Clause extraction ────────────────────────────────────────────────────────────────────────────

/** At a `$`, read a dollar-quote tag (`$$` → '', `$tag$` → 'tag'), or undefined. Mirrors `lexer.ts`. */
function readDollarTag(sql: string, at: number): string | undefined {
  let j = at + 1;
  if (/[A-Za-z_]/.test(sql.charAt(j))) {
    j += 1;
    while (/[A-Za-z0-9_]/.test(sql.charAt(j))) {
      j += 1;
    }
  }
  return sql.charAt(j) === '$' ? sql.slice(at + 1, j) : undefined;
}

/**
 * Return a same-length copy of `sql` with every non-code character (inside single-quoted strings, line/
 * block comments, or dollar-quoted bodies) replaced by a space — newlines preserved. Parentheses and
 * keywords that live inside strings/comments are thereby invisible to the clause scanner, so they can
 * neither be matched as the `USING` keyword nor miscounted as a paren. Replicates the state machine of
 * `lexer.ts` (which is, by contract, a statement *splitter* and is not extended for this).
 *
 * `maskStrings` (default true) controls single-quoted strings only: `false` leaves them intact (used by
 * `maskForClassification`, which needs the JWT-accessor literal to survive its own second pass) while
 * still blanking comments and dollar-quoted bodies. Comments/dollar-quotes are always masked.
 */
function maskNonCode(sql: string, maskStrings = true): string {
  const out: string[] = new Array(sql.length);
  let i = 0;
  let state: 'normal' | 'line-comment' | 'block-comment' | 'single-quote' | 'dollar-quote' =
    'normal';
  let closeToken = '';
  const keep = (idx: number): void => {
    out[idx] = sql.charAt(idx);
  };
  const blank = (idx: number): void => {
    out[idx] = sql.charAt(idx) === '\n' ? '\n' : ' ';
  };
  const blankRun = (from: number, len: number): void => {
    for (let k = 0; k < len; k += 1) {
      blank(from + k);
    }
  };

  while (i < sql.length) {
    const ch = sql.charAt(i);
    const next = sql.charAt(i + 1);
    if (state === 'normal') {
      if (ch === '-' && next === '-') {
        state = 'line-comment';
        blankRun(i, 2);
        i += 2;
      } else if (ch === '/' && next === '*') {
        state = 'block-comment';
        blankRun(i, 2);
        i += 2;
      } else if (ch === "'") {
        state = 'single-quote';
        if (maskStrings) {
          blank(i);
        } else {
          keep(i);
        }
        i += 1;
      } else if (ch === '$') {
        const tag = readDollarTag(sql, i);
        if (tag === undefined) {
          keep(i);
          i += 1;
        } else {
          closeToken = `$${tag}$`;
          state = 'dollar-quote';
          blankRun(i, closeToken.length);
          i += closeToken.length;
        }
      } else {
        keep(i);
        i += 1;
      }
    } else if (state === 'line-comment') {
      if (ch === '\n') {
        state = 'normal';
      }
      blank(i);
      i += 1;
    } else if (state === 'block-comment') {
      if (ch === '*' && next === '/') {
        state = 'normal';
        blankRun(i, 2);
        i += 2;
      } else {
        blank(i);
        i += 1;
      }
    } else if (state === 'single-quote') {
      const mark = maskStrings ? blank : keep;
      if (ch === "'" && next === "'") {
        if (maskStrings) {
          blankRun(i, 2); // escaped quote
        } else {
          keep(i);
          keep(i + 1);
        }
        i += 2;
      } else if (ch === "'") {
        state = 'normal';
        mark(i);
        i += 1;
      } else {
        mark(i);
        i += 1;
      }
    } else {
      // dollar-quote
      if (ch === '$' && sql.startsWith(closeToken, i)) {
        state = 'normal';
        blankRun(i, closeToken.length);
        i += closeToken.length;
      } else {
        blank(i);
        i += 1;
      }
    }
  }
  return out.join('');
}

/** Mask comments and dollar-quoted bodies but leave single-quoted strings intact (see `maskNonCode`). */
function maskNonCodeKeepingStrings(sql: string): string {
  return maskNonCode(sql, false);
}

/**
 * Extract the raw expression inside the first top-level `USING (…)` or `WITH CHECK (…)` of a policy
 * statement, or `undefined` if the clause is absent or its parentheses never balance (fail-secure). The
 * returned text is the ORIGINAL (un-masked) slice, so string literals survive for classification.
 */
export function extractClauseBody(
  statementText: string,
  keyword: 'using' | 'with check',
): string | undefined {
  const masked = maskNonCode(statementText);
  const lower = masked.toLowerCase();
  const kw = keyword === 'using' ? /\busing\b/g : /\bwith\s+check\b/g;
  let match: RegExpExecArray | null;
  // biome-ignore lint/suspicious/noAssignInExpressions: idiomatic global-regex iteration
  while ((match = kw.exec(lower)) !== null) {
    let j = match.index + match[0].length;
    while (j < masked.length && /\s/.test(masked.charAt(j))) {
      j += 1;
    }
    if (masked.charAt(j) !== '(') {
      continue; // this `using`/`with check` is not a clause opener — keep scanning
    }
    let depth = 0;
    for (let k = j; k < masked.length; k += 1) {
      const c = masked.charAt(k);
      if (c === '(') {
        depth += 1;
      } else if (c === ')') {
        depth -= 1;
        if (depth === 0) {
          return statementText.slice(j + 1, k).trim();
        }
      }
    }
    return undefined; // opened but never closed → fail secure
  }
  return undefined;
}

// ── Classification ───────────────────────────────────────────────────────────────────────────────

/**
 * Maximum length of the (whitespace-normalized, masked) classification string. Beyond this we return
 * `unknown` rather than run the call/owner-bound regexes, capping their cost on adversarial input. The
 * longest legitimate fixture predicate is ~79 chars, so 8192 is a ~100x safety margin — a real policy
 * never reaches it, and a pathological 200k-char `USING()` (reachable from untrusted SQL, no upstream
 * length cap) is suppressed fail-secure instead of hanging the scanner (REL-01). See the perf test.
 */
const MAX_CLASSIFY_LEN = 8192;

// An auth-identity primitive: the current caller's id, usable to bind a row to them.
const AUTH_ID = String.raw`(?:auth\.uid\(\)|\(\s*select\s+auth\.uid\(\)\s*\)|auth\.jwt\(\)\s*->>?\s*'[^']*')`;
// Owner-bound: an auth identity on one side of `=` and a (possibly qualified) column on the other. The
// column side must contain at least one letter or underscore (`[A-Za-z_]`), so a bare numeric/literal
// operand — `auth.uid() = 1` — is NOT mistaken for an ownership comparison (COR-02). Identifier runs are
// length-bounded (`{1,256}`) as defense-in-depth against pathological backtracking on long input (REL-01;
// Postgres identifiers cap at 63 bytes, so 256 never truncates a real column name).
//
// KNOWN RECALL GAP (documented, not fixed by regex): an OR-disjunction that mixes an owner-bound term
// with an authenticated-only term — `auth.uid() = user_id OR auth.role() = 'authenticated'` — matches
// here and classifies `owner-bound`, suppressing the finding. Detecting that the OR widens access back
// to every authenticated user needs boolean-structure analysis beyond this regex; we accept the false
// negative (fail-secure: never a false positive) rather than a fragile partial pattern.
const COLUMN_REF = String.raw`(?=[\w".]*[A-Za-z_])[\w".]{1,256}`;
const OWNER_BOUND = new RegExp(`${AUTH_ID}\\s*=\\s*${COLUMN_REF}|${COLUMN_REF}\\s*=\\s*${AUTH_ID}`);
// A correlated subquery (`… in (select … from …)`, `exists (select … from …)`) — multi-tenant membership.
const SUBQUERY = /\bselect\b[\s\S]*\bfrom\b/;
// Any auth primitive at all — reached only after owner-bound/subquery/function checks fail.
const AUTH_PRIMITIVE = /\bauth\.(?:uid|jwt|role)\b/;

/**
 * SQL builtins/keywords that look like a function call (`name(`) but are NOT a custom authorization
 * predicate. A custom call we don't list here is treated as `function-delegated` (suppressed) — a false
 * negative, never a false positive. `auth.*` calls are handled separately. `in`/`exists` matter most:
 * they front the membership subqueries that must classify as `role-delegated`, not function-delegated.
 */
const SAFE_BUILTINS: ReadonlySet<string> = new Set([
  'in',
  'exists',
  'any',
  'all',
  'coalesce',
  'nullif',
  'greatest',
  'least',
  'lower',
  'upper',
  'length',
  'char_length',
  'octet_length',
  'trim',
  'btrim',
  'substring',
  'position',
  'cast',
  'count',
  'sum',
  'avg',
  'min',
  'max',
  'array',
  'array_agg',
  'current_setting',
  'current_user',
  'session_user',
  'current_role',
  'now',
  'to_jsonb',
  'jsonb_build_object',
  'jsonb_extract_path',
  'jsonb_extract_path_text',
  'row_to_json',
  'concat',
  'abs',
  'round',
]);

/** True if the predicate calls a custom (non-auth, non-builtin) function — an unverifiable delegation. */
function callsCustomFunction(normalized: string): boolean {
  // The identifier run is bounded (`{0,255}`) — THE load-bearing REL-01 fix. The unbounded `[\w.]*`
  // made this O(n²) on a long predicate (a ~200k-char USING() hung scanSql 30-60s). 256 chars can never
  // truncate a real call name (Postgres identifiers cap at 63 bytes), so classification is unchanged.
  const callRe = /([a-z_][\w.]{0,255})\s*\(/g;
  let m: RegExpExecArray | null;
  // biome-ignore lint/suspicious/noAssignInExpressions: idiomatic global-regex iteration
  while ((m = callRe.exec(normalized)) !== null) {
    const name = m[1] ?? '';
    if (name.startsWith('auth.')) {
      continue; // auth.uid()/auth.jwt()/auth.role() — handled by the dedicated checks
    }
    if (!SAFE_BUILTINS.has(name)) {
      return true;
    }
  }
  return false;
}

/**
 * Build the string the classification regexes run against: a same-length copy of `expr` with every
 * non-code character blanked, so an `auth.*` token that lives inside a comment or a string literal is
 * NOT mistaken for real code (COR-01). Without this, `status = 'published' /* auth.uid() *​/` or
 * `note = 'see auth.role()'` would wrongly classify `authenticated-only` and fire — a false positive,
 * the worst outcome for a zero-FP scanner.
 *
 * Line/block comments and dollar-quoted bodies are blanked unconditionally (`maskNonCode`). Single-quoted
 * string literals are blanked too, with ONE exception that is load-bearing for recall: a literal that is
 * the right-hand operand of a JWT/claim accessor (`auth.jwt() ->> '…'`, `auth.jwt() -> '…'`) is KEPT,
 * because the `AUTH_ID` / owner-bound patterns read it (e.g. `auth.jwt() ->> 'sub' = user_id` must stay
 * owner-bound). Every OTHER single-quoted literal is content we never key on — blanking it cannot change
 * a class except to remove a false `auth.*` match — so this masking is safe against the full test suite.
 *
 * `current_setting('…')` and similar builtins are classified by their *name* (in `SAFE_BUILTINS`), never
 * by the literal argument, so blanking those literals is likewise inert.
 */
function maskForClassification(expr: string): string {
  // First pass: blank comments + dollar-quoted bodies, leaving single-quoted strings intact. Length is
  // preserved (blanks only), so indices into `firstPass` and `expr` coincide. EVERY subsequent step runs
  // over `firstPass`, never `expr`, so an apostrophe or a `auth.jwt() ->> '…'` that lives inside a comment
  // is already spaces and can neither open a phantom string nor be preserved as a JWT literal.
  const firstPass = maskNonCodeKeepingStrings(expr);
  const out = firstPass.split('');
  // Mark the right-hand literal of every JWT/claim accessor as KEEP, so it survives string-blanking
  // (`auth.jwt() ->> 'sub' = user_id` must stay owner-bound). Every other single-quoted literal is blanked.
  const jwtAccessorLiteral = /auth\.jwt\(\)\s*->>?\s*'(?:[^']|'')*'/gi;
  const keep = new Set<number>();
  let m: RegExpExecArray | null;
  // biome-ignore lint/suspicious/noAssignInExpressions: idiomatic global-regex iteration
  while ((m = jwtAccessorLiteral.exec(firstPass)) !== null) {
    for (let k = m.index; k < m.index + m[0].length; k += 1) {
      keep.add(k);
    }
  }
  let state: 'normal' | 'single-quote' = 'normal';
  let i = 0;
  while (i < firstPass.length) {
    const ch = firstPass.charAt(i);
    if (keep.has(i)) {
      i += 1;
      continue; // inside a preserved JWT-accessor literal — leave verbatim
    }
    if (state === 'normal') {
      if (ch === "'") {
        state = 'single-quote';
        out[i] = ' ';
      }
      i += 1;
    } else {
      if (ch === "'" && firstPass.charAt(i + 1) === "'") {
        out[i] = ' ';
        out[i + 1] = ' ';
        i += 2; // escaped quote stays inside the string
      } else if (ch === "'") {
        state = 'normal';
        out[i] = ' ';
        i += 1;
      } else {
        out[i] = ch === '\n' ? '\n' : ' ';
        i += 1;
      }
    }
  }
  return out.join('');
}

/**
 * Classify an RLS predicate. Total and fail-secure: never throws, and any ambiguity yields a class that
 * does NOT trigger a finding. Order matters and is load-bearing — see the inline notes.
 */
export function classifyPredicate(expr: string | undefined): PredicateClass {
  if (expr === undefined) {
    return 'absent';
  }
  const normalized = maskForClassification(expr).replace(/\s+/g, ' ').trim().toLowerCase();
  if (normalized.length === 0) {
    return 'unknown';
  }
  // Beyond the cap, suppress (fail-secure) rather than run the regexes on adversarial-length input.
  if (normalized.length > MAX_CLASSIFY_LEN) {
    return 'unknown';
  }
  if (/^\(*\s*true\s*\)*$/.test(normalized)) {
    return 'unconditional';
  }
  // Before anything else: a custom function call makes the predicate unverifiable (it may well be a
  // correct multi-tenant check). Suppress. Checked first so `has_access(id) AND auth.uid() IS NOT NULL`
  // is treated as delegated, not as the gap.
  if (callsCustomFunction(normalized)) {
    return 'function-delegated';
  }
  // A membership subquery is the legitimate "is the caller in this team/org" pattern. Suppress.
  if (SUBQUERY.test(normalized)) {
    return 'role-delegated';
  }
  // The correct pattern: an auth identity compared to a column. Never flagged.
  if (OWNER_BOUND.test(normalized)) {
    return 'owner-bound';
  }
  // Reaching here with an auth primitive means it mentions auth but does NOT bind a row to a column —
  // i.e. it only proves the caller is logged in. THE gap.
  if (AUTH_PRIMITIVE.test(normalized)) {
    return 'authenticated-only';
  }
  return 'unknown';
}

// ── Effective policy class ─────────────────────────────────────────────────────────────────────────

/**
 * The predicate class that governs whether a policy scopes rows to the caller. INSERT has only WITH
 * CHECK; every other command is governed by USING (which rows are visible/affected), and PostgreSQL
 * reuses USING as WITH CHECK when the latter is omitted — so USING is authoritative, with WITH CHECK as
 * the fallback only when there is no USING. Single source of truth shared by the RLS rule and the
 * code↔SQL correlation, so the two can never drift.
 */
export function effectivePolicyClass(policy: {
  readonly command: PolicyCommand;
  readonly usingClass: PredicateClass;
  readonly checkClass: PredicateClass;
}): PredicateClass {
  if (policy.command === 'insert') {
    return policy.checkClass;
  }
  return policy.usingClass !== 'absent' ? policy.usingClass : policy.checkClass;
}

/**
 * Whether a PERMISSIVE policy authenticates the caller but does not scope rows to them — the single
 * authority shared by `rls/policy-not-owner-scoped` and the code↔SQL correlation, so the two can never
 * drift. Two independent ways a policy is the gap:
 *
 *  1. `effectivePolicyClass` is `authenticated-only` — the read/affected-rows side (USING, or WITH CHECK
 *     for INSERT) only proves a session exists. Every authenticated user reads every row.
 *  2. For a write-capable command (anything but SELECT), the WITH CHECK is `authenticated-only` even when
 *     USING is owner-bound (SEC-01). WITH CHECK governs WRITES independently of USING: `FOR ALL USING
 *     (auth.uid() = user_id) WITH CHECK (auth.uid() IS NOT NULL)` lets a logged-in user INSERT rows they
 *     don't own or rewrite `user_id` to someone else's — CWE-639 IDOR-write — which case (1) alone misses
 *     because it reads only the USING side. A correct `WITH CHECK (auth.uid() = user_id)` is owner-bound
 *     and stays silent.
 *
 * Caller filters (RESTRICTIVE, no ownership column) stay at the call sites — this answers only "does the
 * predicate scope to the caller?".
 */
export function isAuthenticatedOnlyGap(policy: {
  readonly command: PolicyCommand;
  readonly usingClass: PredicateClass;
  readonly checkClass: PredicateClass;
}): boolean {
  if (effectivePolicyClass(policy) === 'authenticated-only') {
    return true;
  }
  return policy.command !== 'select' && policy.checkClass === 'authenticated-only';
}
