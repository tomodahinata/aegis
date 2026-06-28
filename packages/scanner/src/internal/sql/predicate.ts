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
  // Literally `false` — deny-all. No caller (anon or authenticated) can ever satisfy it, so it is the
  // *safest* possible predicate: the idiom for an append-only/immutable table (`FOR UPDATE USING (false)`).
  // A distinct class so the "anon can mutate" rule skips it instead of mistaking it for a row-state gap.
  | 'deny'
  // An auth identity (auth.uid()/auth.jwt()->>'sub') compared to a column — the CORRECT pattern.
  | 'owner-bound'
  // Proves the caller is authenticated but binds no row to them — THE gap this feature closes.
  | 'authenticated-only'
  // The decision delegates to something an anonymous caller can never satisfy and we cannot verify, so it
  // is suppressed (fail-secure): a membership subquery (`… IN (SELECT … FROM memberships WHERE user_id =
  // auth.uid())`), a specific-role gate (`auth.role() = 'service_role'`), or a JWT-claim gate
  // (`auth.jwt() ->> 'role' = 'admin'`, `auth.jwt() ? 'service_role'`). Distinct from `unknown` so the
  // anon-writable rule does NOT mistake it for an anon-satisfiable row-state predicate.
  | 'role-delegated'
  // Delegates the decision to a custom function (`has_access(id)`) — unverifiable, so suppressed.
  | 'function-delegated'
  // Anything else — not the gap, so not flagged here: a pure row-state predicate (`status = 'published'`),
  // an anon test (`auth.uid() IS NULL`), or an owner binding wrapped in a function (`coalesce(auth.uid(),
  // …)`). An anon CAN satisfy a row-state predicate, so this is the class `rls/anon-writable` keys on.
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

// A schema-qualified identifier that tolerates PostgreSQL's optional double-quoting — `auth.uid` and the
// `"auth"."uid"` form that pg_dump and declarative `supabase/schemas` emit. Quoting every auth-function
// regex through this is what lets the analyzer read declarative-schema repos (a whole repo class) rather
// than misclassifying every quoted predicate. DRY: one helper feeds owner-bound, the gap, and every gate.
const qIdent = (schema: string, name: string): string => `"?${schema}"?\\s*\\.\\s*"?${name}"?`;
// An auth call (quote-tolerant), with whitespace tolerance for the forms real migrations use (`auth.uid ()`).
const AUTH_UID = String.raw`${qIdent('auth', 'uid')}\s*\(\s*\)`;
const AUTH_JWT = String.raw`${qIdent('auth', 'jwt')}\s*\(\s*\)`;
const AUTH_ROLE = String.raw`${qIdent('auth', 'role')}\s*\(\s*\)`;
// An optional Postgres cast on an operand (`::text`, `::uuid`, `::"text"`, `::public.citext`). `auth.uid()::text
// = user_id::text` is owner-bound, not authenticated-only. The type run is length-bounded (`{0,64}`) as
// REL-01 defense-in-depth against backtracking.
const CAST = String.raw`(?:\s*::\s*"?[a-z_][\w.]{0,64}"?)?`;
// An auth identity usable to bind a row to the caller: `auth.uid()`, the Supabase-recommended `(select
// auth.uid())` performance wrapper (incl. the `as uid` alias its CLI emits), or the JWT subject claim.
const AUTH_ID = String.raw`(?:${AUTH_UID}|\(\s*select\s+${AUTH_UID}\s*(?:as\s+[a-z_]\w*\s*)?\)|${AUTH_JWT}\s*->>?\s*'[^']*')`;
// Owner-bound: an auth identity on one side of `=` and a (possibly qualified, possibly cast) column on the
// other. The column side must contain at least one letter or underscore (`[A-Za-z_]`), so a bare
// numeric/literal operand — `auth.uid() = 1` — is NOT mistaken for an ownership comparison (COR-02).
// Identifier runs are length-bounded (`{1,256}`) as defense-in-depth against pathological backtracking on
// long input (REL-01; Postgres identifiers cap at 63 bytes, so 256 never truncates a real column name).
//
// KNOWN RECALL GAP (documented, not fixed by regex): an OR-disjunction that mixes an owner-bound term
// with an authenticated-only term — `auth.uid() = user_id OR auth.role() = 'authenticated'` — matches
// here and classifies `owner-bound`, suppressing the finding. Detecting that the OR widens access back
// to every authenticated user needs boolean-structure analysis beyond this regex; we accept the false
// negative (fail-secure: never a false positive) rather than a fragile partial pattern.
const COLUMN_REF = String.raw`(?=[\w".]*[A-Za-z_])[\w".]{1,256}`;
const OWNER_BOUND = new RegExp(
  // `auth.uid() = col` / `col = auth.uid()` — the canonical single-owner binding (either operand order).
  `${AUTH_ID}${CAST}\\s*=\\s*${COLUMN_REF}${CAST}|${COLUMN_REF}${CAST}\\s*=\\s*${AUTH_ID}${CAST}` +
    // `auth.uid() IN (sender_id, receiver_id)` — the caller must BE one of these columns: a participant /
    // multi-owner binding (chat, shared docs). The list must start with a COLUMN (not a literal list, and
    // not a `(SELECT …)` membership subquery — that is `role-delegated`, already matched earlier).
    `|${AUTH_ID}${CAST}\\s+in\\s*\\(\\s*${COLUMN_REF}`,
);
// A correlated subquery (`… in (select … from …)`, `exists (select … from …)`) — multi-tenant membership.
const SUBQUERY = /\bselect\b[\s\S]*\bfrom\b/;
// An auth call, optionally inside the Supabase `(select …)` performance wrapper.
const selectWrap = (call: string): string => `(?:${call}|\\(\\s*select\\s+${call}\\s*\\))`;
// The CLOSED set of predicates that ARE the authenticated-only gap: a positive proof that a session exists
// while binding no row — `auth.uid()/auth.jwt() IS NOT NULL`, or `auth.role() = 'authenticated'`. Defining
// the gap by these forms (rather than the old "mentions any auth.* token") is what holds precision at 1.0 on
// real corpora. Checked BEFORE the role/claim gate below so a disjunction that widens access back to every
// authenticated user — `auth.role() = 'service_role' OR auth.uid() IS NOT NULL` — is still caught. The
// `'authenticated'` literal survives masking (see `maskForClassification`), distinguishing it from a role
// restriction.
const SESSION_PROOF = new RegExp(
  `(?:${selectWrap(AUTH_UID)}|${selectWrap(AUTH_JWT)})${CAST}\\s+is\\s+not\\s+null` +
    `|${selectWrap(AUTH_ROLE)}${CAST}\\s*=\\s*'authenticated'` +
    `|'authenticated'\\s*=\\s*${selectWrap(AUTH_ROLE)}${CAST}`,
);
// A gate on a SPECIFIC role or JWT claim that an anonymous caller can NEVER satisfy. NOT the gap (it does
// not let every authenticated user in) AND not anon-satisfiable — so it must classify as `role-delegated`,
// distinct from `unknown` (a row-state predicate an anon CAN satisfy), or `rls/anon-writable` would wrongly
// fire on `FOR ALL USING (auth.role() = 'service_role')`. Field-validated: this exact regression surfaced
// as 59 anon-writable false positives, all `service_role`, before this class was restored.
const ROLE_CALL = `${selectWrap(AUTH_ROLE)}${CAST}`;
const ROLE_RESTRICTED = new RegExp(
  `${ROLE_CALL}\\s*=\\s*'(?!authenticated')[^']*'|'(?!authenticated')[^']*'\\s*=\\s*${ROLE_CALL}`,
);
// A JWT claim/key access — `auth.jwt() ->> 'role'`, `auth.jwt() -> 'app_metadata'`, the jsonb key-exists
// `auth.jwt() ? 'service_role'`. Reached only after owner-bound and SESSION_PROOF, so it reads a claim to
// authorize, never proving mere session existence. Anon has no such claim ⇒ not anon-satisfiable.
const CLAIM_GATE = new RegExp(`${selectWrap(AUTH_JWT)}\\s*(?:->>?|#>>?|\\?[|&]?)`);
// A gate on the session's role/config via a Postgres identity function rather than `auth.*` — `current_user
// = 'service_role'`, `current_setting('role') = 'service_role'`. The role/identity forms an anonymous caller
// can never satisfy ⇒ `role-delegated`, never anon-satisfiable `unknown`.
//
// `current_setting(` is matched WITHOUT inspecting its argument: by the time this runs the literal is already
// blanked by `maskForClassification`, so a role GUC (`'role'`, `'request.jwt.*'`) is indistinguishable from an
// app GUC (`'app.tenant'`) here. Matching the call broadly keeps the dominant role-GUC case at zero false
// positives (an anon never has `service_role`). ACCEPTED RECALL GAP (fail-secure, never an FP): a row-state
// predicate that ORs in an app GUC — `is_public OR x = current_setting('app.tenant')` — is suppressed from
// `rls/anon-writable`. Per Aegis doctrine that rare false negative is preferable to a false positive.
const CONFIG_ROLE_GATE = /\b(?:current_user|session_user|current_role)\b|current_setting\s*\(/;

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
 * string literals are blanked too, with TWO exceptions that are load-bearing for classification, each a
 * literal adjacent to real auth code: (1) the right-hand operand of a JWT/claim accessor (`auth.jwt() ->>
 * '…'`, `auth.jwt() -> '…'`), so `auth.jwt() ->> 'sub' = user_id` stays owner-bound; and (2) the literal in
 * an `auth.role() = '…'` comparison, so the gap (`'authenticated'`) is distinguishable from a role
 * restriction (`'service_role'`). Every OTHER single-quoted literal is content we never key on — blanking
 * it cannot change a class except to remove a false `auth.*` match — so this masking stays safe.
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
  const keep = new Set<number>();
  // A single-quoted SQL literal in the UNROLLED-LOOP form (`'…'` with `''` escapes). This is linear — each
  // input char has exactly one path — unlike `'(?:[^']|'')*'`, whose ambiguity made `roleComparisonLiteral`
  // O(n²) under the global-`exec` loop (REL-01: a crafted `USING(…)` body could hang the scanner for tens of
  // seconds; the raw-length cap in `classifyPredicate` is the structural guard, this is defense in depth).
  const SQL_STRING = `'[^']*(?:''[^']*)*'`;
  // Mark every char of a match as KEEP, so it survives string-blanking. (A `"` inside such a kept literal is
  // neutralized later, in `classifyPredicate`'s identifier-quote strip, so it cannot forge a keyword.)
  const markKept = (re: RegExp): void => {
    let m: RegExpExecArray | null;
    // biome-ignore lint/suspicious/noAssignInExpressions: idiomatic global-regex iteration
    while ((m = re.exec(firstPass)) !== null) {
      for (let k = m.index; k < m.index + m[0].length; k += 1) {
        keep.add(k);
      }
    }
  };
  // The right-hand literal of every JWT/claim accessor — `auth.jwt() ->> 'sub' = user_id` must stay owner-bound.
  markKept(new RegExp(`${AUTH_JWT}\\s*->>?\\s*${SQL_STRING}`, 'gi'));
  // The literal in an `auth.role() = '…'` comparison (incl. the `(select auth.role())` performance wrapper),
  // so SESSION_PROOF can match the gap (`= 'authenticated'`) and not a role restriction (`= 'service_role'`).
  markKept(
    new RegExp(`${ROLE_CALL}\\s*=\\s*${SQL_STRING}|${SQL_STRING}\\s*=\\s*${ROLE_CALL}`, 'gi'),
  );
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
 * Remove identifier double-quotes so the pg_dump / declarative-`supabase/schemas` quoted form classifies
 * like the bare form (`"auth"."uid"()` → `auth.uid()`, `"public"."is_admin"(` → a custom call). Runs on the
 * already-masked string, where the ONLY single-quoted content left is the literals `maskForClassification`
 * deliberately kept (the JWT-accessor / role-comparison operands).
 *
 * A `"` OUTSIDE a literal is an identifier delimiter → dropped (so `"auth"."role"` splices to `auth.role`).
 * A `"` INSIDE a kept literal is data → replaced with a space, NOT dropped: splicing it out would let a
 * crafted literal forge a keyword — `auth.role() = 'authentic"ated'` would become `'authenticated'` and
 * match SESSION_PROOF, a false positive. Replacing keeps the value distinct (`'authentic ated'`).
 */
function stripIdentifierQuotes(masked: string): string {
  let result = '';
  let inString = false;
  for (let i = 0; i < masked.length; i += 1) {
    const ch = masked.charAt(i);
    if (ch === "'") {
      if (inString && masked.charAt(i + 1) === "'") {
        result += "''"; // SQL-escaped quote — stays inside the literal, does not toggle state
        i += 1;
        continue;
      }
      inString = !inString;
      result += ch;
    } else if (ch === '"') {
      result += inString ? ' ' : '';
    } else {
      result += ch;
    }
  }
  return result;
}

/**
 * Classify an RLS predicate. Total and fail-secure: never throws, and any ambiguity yields a class that
 * does NOT trigger a finding. Order matters and is load-bearing — see the inline notes.
 */
export function classifyPredicate(expr: string | undefined): PredicateClass {
  if (expr === undefined) {
    return 'absent';
  }
  // REL-01: cap the RAW input BEFORE masking. `maskForClassification` runs several global regexes over the
  // input, so the length guard must gate the raw `expr` — gating only the normalized result would let an
  // adversarial-length predicate reach those masking regexes first. Fail-secure: an over-long predicate
  // suppresses to `unknown` rather than risk pathological backtracking on attacker-supplied SQL.
  if (expr.length > MAX_CLASSIFY_LEN) {
    return 'unknown';
  }
  // Normalize the quoted (pg_dump / declarative) form to the bare form so both classify identically. See
  // `stripIdentifierQuotes`: identifier `"` are removed, a `"` inside a kept literal is spaced (not removed),
  // so a crafted literal cannot forge a keyword across the strip.
  const normalized = stripIdentifierQuotes(maskForClassification(expr))
    .replace(/\s+/g, ' ')
    .trim()
    .toLowerCase();
  if (normalized.length === 0) {
    return 'unknown';
  }
  if (/^\(*\s*true\s*\)*$/.test(normalized)) {
    return 'unconditional';
  }
  // `false` is deny-all: no row ever satisfies it, so it grants nothing to anyone. Classified before the
  // auth/owner regexes (which it can't match anyway) so `USING (false)` on an immutable table is never
  // mistaken for an unclassifiable row-state predicate and flagged as anon-writable.
  if (/^\(*\s*false\s*\)*$/.test(normalized)) {
    return 'deny';
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
  // The correct pattern: an auth identity compared to a column (tolerating casts/aliases). Never flagged.
  if (OWNER_BOUND.test(normalized)) {
    return 'owner-bound';
  }
  // THE gap, and ONLY this: a positive proof that a session exists which binds no row to the caller
  // (`auth.uid() IS NOT NULL`, `auth.role() = 'authenticated'`). Checked before the role/claim gate so a
  // disjunction that re-widens to every authenticated user is still caught.
  if (SESSION_PROOF.test(normalized)) {
    return 'authenticated-only';
  }
  // A gate on a specific role or JWT claim (via `auth.*` or a Postgres identity function) — authorizes by
  // role/claim, which an anon caller can never satisfy. Suppressed (not the gap), but kept DISTINCT from
  // `unknown` so `rls/anon-writable` does not treat it as an anon-satisfiable row-state predicate.
  if (
    ROLE_RESTRICTED.test(normalized) ||
    CLAIM_GATE.test(normalized) ||
    CONFIG_ROLE_GATE.test(normalized)
  ) {
    return 'role-delegated';
  }
  // Anything else that merely mentions an `auth.*` token (an anon test `auth.uid() IS NULL`, an owner
  // binding wrapped in `coalesce(…)`) or is a pure row-state predicate — not the gap, so `unknown`.
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
