import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import {
  classifyPredicate,
  effectivePolicyClass,
  extractClauseBody,
  isAuthenticatedOnlyGap,
  type PredicateClass,
} from './predicate';

describe('extractClauseBody', () => {
  it('extracts a simple USING body', () => {
    expect(
      extractClauseBody('create policy p on t for select using (auth.uid() = user_id)', 'using'),
    ).toBe('auth.uid() = user_id');
  });

  it('extracts WITH CHECK independently of USING', () => {
    const stmt = 'create policy p on t for all using (auth.uid() = a) with check (auth.uid() = b)';
    expect(extractClauseBody(stmt, 'using')).toBe('auth.uid() = a');
    expect(extractClauseBody(stmt, 'with check')).toBe('auth.uid() = b');
  });

  it('handles nested parentheses', () => {
    expect(
      extractClauseBody('create policy p on t for select using ((a or b) and c)', 'using'),
    ).toBe('(a or b) and c');
  });

  it('does not let a ) inside a string literal close the clause', () => {
    expect(extractClauseBody("create policy p on t for select using (name <> ')')", 'using')).toBe(
      "name <> ')'",
    );
  });

  it('does not let a ( inside a trailing line comment break the scan', () => {
    expect(
      extractClauseBody(
        'create policy p on t for select using (auth.uid() = user_id) -- a (note',
        'using',
      ),
    ).toBe('auth.uid() = user_id');
  });

  it('returns undefined when the keyword is absent', () => {
    expect(extractClauseBody('create policy p on t for insert', 'using')).toBeUndefined();
  });

  it('returns undefined for an unbalanced clause (fail secure)', () => {
    expect(
      extractClauseBody('create policy p on t for select using (auth.uid() = user_id', 'using'),
    ).toBeUndefined();
  });

  it('ignores the word "using" inside a string literal', () => {
    expect(
      extractClauseBody("create policy p on t for select using (note = 'using (x)')", 'using'),
    ).toBe("note = 'using (x)'");
  });
});

describe('classifyPredicate', () => {
  const cases: ReadonlyArray<readonly [string | undefined, PredicateClass]> = [
    [undefined, 'absent'],
    ['true', 'unconditional'],
    ['(true)', 'unconditional'],
    ['TRUE', 'unconditional'],
    // deny — literal `false`, the append-only/immutable idiom (`FOR UPDATE USING (false)`); satisfiable
    // by no caller, so it must never be flagged as an anon-writable row-state gap.
    ['false', 'deny'],
    ['(false)', 'deny'],
    ['FALSE', 'deny'],
    // owner-bound — the correct pattern (never flagged)
    ['auth.uid() = user_id', 'owner-bound'],
    ['user_id = auth.uid()', 'owner-bound'],
    ['(select auth.uid()) = user_id', 'owner-bound'],
    ["auth.jwt() ->> 'sub' = user_id::text", 'owner-bound'],
    ['auth.uid() = user_id and deleted = false', 'owner-bound'],
    // owner-bound written the ways real Supabase migrations write it — casts on both operands, the CLI's
    // `(select … as uid)` performance wrapper, whitespace — must stay owner-bound, never read as the gap.
    ['auth.uid()::text = user_id::text', 'owner-bound'],
    ['(select auth.uid() as uid) = user_id', 'owner-bound'],
    ['user_id = (select auth.uid() as uid)', 'owner-bound'],
    ['auth.uid () = user_id', 'owner-bound'],
    // `auth.uid() IN (cols)` — a participant / multi-owner binding (chat sender/receiver, shared docs). An
    // anon (null uid) is in no such list, so it is owner-bound, not an anon-satisfiable row-state predicate.
    ['auth.uid() in (sender_id, receiver_id)', 'owner-bound'],
    // owner-bound via a case-insensitive identity match — `lower(col) = lower(auth.jwt() ->> 'email')`, the
    // idiomatic email binding. A case-fold/trim wrapper (and the redundant parens it adds) is transparent
    // to ownership. The redundant `auth.uid() IS NOT NULL` conjunct must NOT re-classify it as the gap.
    // Field study: this exact shape was the one residual false positive on a fresh public corpus.
    ["lower(email) = lower(auth.jwt() ->> 'email')", 'owner-bound'],
    ["lower(email) = lower((auth.jwt() ->> 'email'))", 'owner-bound'],
    ["auth.uid() is not null and lower(email) = lower((auth.jwt() ->> 'email'))", 'owner-bound'],
    ["upper(handle) = upper(auth.jwt() ->> 'sub')", 'owner-bound'],
    ['(user_id) = (auth.uid())', 'owner-bound'], // redundant grouping parens on both operands
    // (`coalesce(auth.uid(), …)` stays `unknown` — it is NOT a transparent wrapper; asserted below.)
    // authenticated-only — THE gap (proves a session exists, binds no row, gates on no specific role).
    // Includes the Supabase `(select …)` performance wrapper, which the gap is just as often written with.
    ["auth.role() = 'authenticated'", 'authenticated-only'],
    ['auth.uid() is not null', 'authenticated-only'],
    ['(select auth.uid()) is not null', 'authenticated-only'],
    ["(select auth.role()) = 'authenticated'", 'authenticated-only'],
    ['auth.jwt() is not null', 'authenticated-only'],
    // role-delegated — membership subquery (suppressed)
    [
      'tenant_id in (select tenant_id from memberships where user_id = auth.uid())',
      'role-delegated',
    ],
    ['exists (select 1 from team_members m where m.user_id = auth.uid())', 'role-delegated'],
    // role-delegated — a gate on a SPECIFIC role or JWT claim RESTRICTS access to that role; an anon caller
    // can never satisfy it, so it is neither the gap NOR anon-satisfiable (kept distinct from `unknown` so
    // anon-writable does not fire on it). Field-validated: ~47% of this rule's FPs were `service_role`.
    ["auth.role() = 'service_role'", 'role-delegated'],
    ["'service_role' = auth.role()", 'role-delegated'],
    ["auth.role() = 'admin'", 'role-delegated'],
    ["(select auth.role()) = 'service_role'", 'role-delegated'], // select-wrapped role restriction
    ["(select auth.role())::text = 'service_role'", 'role-delegated'], // wrapped + cast
    ["auth.jwt() ->> 'role' = 'admin'", 'role-delegated'],
    ["(auth.jwt() -> 'app_metadata' ->> 'claims_admin')::boolean = true", 'role-delegated'],
    ["auth.jwt() ? 'service_role'", 'role-delegated'], // jsonb key-exists role check
    ["(select auth.jwt()) -> 'app_metadata' ->> 'role' = 'admin'", 'role-delegated'], // wrapped claim gate
    // role-delegated — PostgreSQL quoted-identifier forms (pg_dump / declarative `supabase/schemas`) and the
    // identity-function role gates. An anon caller can never satisfy any of these.
    [`("auth"."role"() = 'service_role'::"text")`, 'role-delegated'],
    [`(("auth"."jwt"() ->> 'role'::"text") = 'service_role'::"text")`, 'role-delegated'],
    ["current_user = 'service_role'", 'role-delegated'],
    ["current_setting('role', true) = 'service_role'", 'role-delegated'],
    // role-delegated — the LIST form `auth.role() IN (…specific roles…)`. An anon's role is never in such a
    // list, so it must NOT be read as an anon-satisfiable row-state predicate (field FP: `anon-writable`
    // fired on `WITH CHECK (auth.role() IN ('service_role', 'supabase_admin'))`).
    ["auth.role() in ('service_role', 'supabase_admin')", 'role-delegated'],
    ["auth.role() in ('admin', 'editor')", 'role-delegated'],
    // authenticated-only — a disjunction that re-widens to EVERY authenticated user is still the gap, even
    // though one arm is a role gate (SESSION_PROOF is checked before the role/claim gate, COR/SEC ordering).
    ["auth.role() = 'service_role' or auth.uid() is not null", 'authenticated-only'],
    // quoted-identifier forms of owner-bound and the gap must still resolve correctly (declarative schemas).
    [`"auth"."uid"() = "user_id"`, 'owner-bound'],
    [`("auth"."role"() = 'authenticated'::"text")`, 'authenticated-only'],
    [`(( select "auth"."uid"() as "uid") = "id")`, 'owner-bound'], // quoted (select … as "uid") wrapper
    // quoted CUSTOM functions / identity functions delegate the decision and an anon cannot satisfy them.
    [`"public"."is_admin"("auth"."uid"())`, 'function-delegated'],
    [`("org_id" = any ("public"."get_user_org_ids"()))`, 'function-delegated'],
    [`("organization_id" = ("current_setting"('app.org', true))::uuid)`, 'role-delegated'],
    // unknown — `auth.uid() IS NULL` is an ANON test (the caller is NOT logged in), the opposite of a session
    // proof; an owner binding wrapped in `coalesce(…)` is not a clean session proof. Both anon-satisfiable.
    ["auth.uid() is null and status = 'published'", 'unknown'],
    ["user_id = coalesce(auth.uid()::text, 'dev@example.com')", 'unknown'],
    // function-delegated — custom predicate function (suppressed)
    ['has_access(id)', 'function-delegated'],
    ['public.is_member(org_id)', 'function-delegated'],
    ['has_access(id) and auth.uid() is not null', 'function-delegated'],
    // function-delegated — a CUSTOM `auth.*` schema helper (NOT auth.uid/jwt/role) is as unverifiable as any
    // other custom function and an anon cannot satisfy it; it must be suppressed, not read as a row-state
    // gap. Field FPs: `anon-writable` fired on `auth.is_admin()`, `auth.email()`, `auth.user_role() IN (…)`.
    ['auth.is_admin()', 'function-delegated'],
    ['email = auth.email()', 'function-delegated'],
    ["auth.user_role() in ('admin', 'superadmin')", 'function-delegated'],
    ['auth.org_id() = org_id', 'function-delegated'],
    // unknown — no recognizable scoping (suppressed)
    ['is_public', 'unknown'],
    ["status = 'published'", 'unknown'],
    ['', 'unknown'],
    // COR-01 — an `auth.*` token inside a comment or a string literal is NOT real code (no false positive)
    ["status = 'published' /* auth.uid() */", 'unknown'],
    ['status = is_active -- auth.uid() = user_id', 'unknown'],
    ["note = 'see auth.role()'", 'unknown'],
    // COR-01 — the JWT/claim accessor literal still survives masking, so owner-bound is preserved
    ["auth.jwt() ->> 'sub' = user_id", 'owner-bound'],
    // COR-02 — a bare numeric/literal on the column side is NOT an ownership comparison; it is also not a
    // session proof, so it is suppressed as `unknown` (never silently treated as owner-bound — the genuine
    // column comparison `auth.uid() = user_id` is pinned owner-bound above).
    ['auth.uid() = 1', 'unknown'],
    ["auth.uid() = 'literal'", 'unknown'],
  ];

  for (const [expr, expected] of cases) {
    it(`classifies ${JSON.stringify(expr)} as ${expected}`, () => {
      expect(classifyPredicate(expr)).toBe(expected);
    });
  }

  it('is total — never throws on arbitrary input', () => {
    fc.assert(
      fc.property(fc.string(), (s) => {
        const result = classifyPredicate(s);
        expect(typeof result).toBe('string');
      }),
    );
  });

  it('treats builtins like a custom function only when truly custom (fast-check on call names)', () => {
    fc.assert(
      fc.property(fc.stringMatching(/^[a-z_][a-z0-9_]{0,12}$/), (name) => {
        const cls = classifyPredicate(`${name}(x)`);
        // A bare `name(x)` is either a recognized builtin (→ unknown, no auth) or a custom call.
        expect(['function-delegated', 'unknown']).toContain(cls);
      }),
    );
  });

  // COR-01: classification runs on a comment/string-masked copy, so an `auth.*` token that is not real
  // code cannot manufacture a finding — while the JWT-claim accessor literal it legitimately reads stays.
  describe('COR-01 — masks non-code auth tokens, preserves JWT literals', () => {
    it('does not treat auth.uid() inside a block comment as authenticated-only', () => {
      expect(classifyPredicate("status = 'published' /* auth.uid() */")).toBe('unknown');
    });

    it('does not treat auth.uid() inside a line comment as code', () => {
      expect(classifyPredicate('owner = current_owner -- auth.uid() = user_id')).toBe('unknown');
    });

    it('does not treat auth.role() inside a string literal as authenticated-only', () => {
      expect(classifyPredicate("note = 'see auth.role()'")).toBe('unknown');
    });

    it("keeps an owner-bound JWT subject claim (auth.jwt() ->> 'sub' = user_id)", () => {
      expect(classifyPredicate("auth.jwt() ->> 'sub' = user_id")).toBe('owner-bound');
      expect(classifyPredicate("auth.jwt() ->> 'sub' = user_id::text")).toBe('owner-bound');
    });

    it('classifies a role/claim gate as role-delegated (not the gap, not anon-satisfiable)', () => {
      // A role/claim gate RESTRICTS access to that role — not "every authenticated user reads every row" —
      // so it is not a session proof. It stays `role-delegated` (distinct from `unknown`) so anon-writable
      // never treats it as an anon-satisfiable row-state predicate. The genuine gap still fires.
      expect(classifyPredicate("auth.role() = 'service_role'")).toBe('role-delegated');
      expect(classifyPredicate("auth.jwt() ->> 'role' = 'admin'")).toBe('role-delegated');
      expect(classifyPredicate("auth.jwt() ? 'service_role'")).toBe('role-delegated');
      expect(classifyPredicate("auth.role() = 'authenticated'")).toBe('authenticated-only');
      expect(classifyPredicate('(select auth.uid()) is not null')).toBe('authenticated-only');
      // The disjunction is the gap despite a service_role arm (SESSION_PROOF precedes the role gate).
      expect(classifyPredicate("auth.role() = 'service_role' or auth.uid() is not null")).toBe(
        'authenticated-only',
      );
      // SEC: a `"` inside a KEPT role literal must not be stripped into a false `'authenticated'` match.
      // `maskForClassification` never keeps a `"`, so `'authentic"ated'` (a value no real role has) stays a
      // suppressed role restriction, not the gap — defending the global double-quote strip from forging the
      // SESSION_PROOF keyword.
      expect(classifyPredicate(`auth.role() = 'authentic"ated'`)).toBe('role-delegated');
    });

    it('an apostrophe inside a comment does not suppress real auth code that follows it', () => {
      // Regression: a `'` in `/* it's */` must not open a phantom string and blank the real predicate —
      // the comment is masked first, so the auth primitive after it still classifies (no false negative).
      expect(
        classifyPredicate("status = active /* it's a note */ and auth.uid() is not null"),
      ).toBe('authenticated-only');
      expect(classifyPredicate("auth.jwt() ->> 'sub' = user_id /* owner's row */")).toBe(
        'owner-bound',
      );
    });

    it('masks dollar-quoted bodies (tagged and untagged) so auth tokens inside them do not leak', () => {
      expect(classifyPredicate('auth.uid() = user_id and note = $$ auth.role() $$')).toBe(
        'owner-bound',
      );
      expect(classifyPredicate('auth.uid() = user_id and note = $tag$ auth.role() $tag$')).toBe(
        'owner-bound',
      );
    });

    it("masks SQL-escaped '' quotes so an auth token inside the string stays masked", () => {
      // `'it''s auth.role() = authenticated'` is one string literal; the doubled '' must not end it early.
      expect(classifyPredicate("note = 'it''s auth.role() = authenticated'")).toBe('unknown');
    });
  });

  // REL-01: the call/owner-bound regexes are length-bounded and the masked string is capped, so an
  // adversarial multi-hundred-kilobyte predicate is suppressed fail-secure instead of hanging the scanner.
  describe('REL-01 — bounded cost on adversarial-length input', () => {
    it('classifies a ~200k-char predicate well under budget (no O(n²) blowup)', () => {
      const huge = `auth.uid() = user_id and ${'a'.repeat(200_000)}`;
      const start = performance.now();
      const cls = classifyPredicate(huge);
      const elapsed = performance.now() - start;
      // Past the cap the predicate is suppressed (fail-secure), not classified by the bounded regexes.
      // This `unknown` assertion is the actual DoS guarantee and is unaffected by instrumentation.
      expect(cls).toBe('unknown');
      // The wall-clock smoke-check stays strict normally but tolerates v8 coverage overhead; even the
      // relaxed ceiling is orders of magnitude below the seconds an O(n²) regression would cost here.
      const budgetMs = process.env['VITEST_COVERAGE'] === '1' ? 2000 : 150;
      expect(elapsed).toBeLessThan(budgetMs);
    });

    it('does not blow up on a quote-dense literal (the masking regexes, not just the bounded ones)', () => {
      // Regression for a real O(n²) ReDoS: the cap once ran AFTER maskForClassification, so a crafted
      // single-quote-dense literal hit the masking regexes' ambiguous `(?:[^']|'')*` first — ~18s at 120 KB.
      // The raw-length cap now gates BEFORE masking (and the literals use the unrolled-loop form), so a
      // crafted `USING(…)` body is suppressed fail-secure in microseconds instead of hanging the scanner.
      const evil = `auth.jwt() ->> '${"''".repeat(60_000)}'`;
      const start = performance.now();
      const cls = classifyPredicate(evil);
      const elapsed = performance.now() - start;
      expect(cls).toBe('unknown');
      const budgetMs = process.env['VITEST_COVERAGE'] === '1' ? 2000 : 150;
      expect(elapsed).toBeLessThan(budgetMs);
    });

    it('still classifies an owner-bound predicate that sits just under the cap', () => {
      // Guards the 8192 cap from being silently lowered: a long-but-legal predicate must still classify.
      const justUnder = `auth.uid() = user_id and tag in ('${'a,'.repeat(2_000)}z')`;
      expect(justUnder.length).toBeLessThan(8192);
      expect(classifyPredicate(justUnder)).toBe('owner-bound');
    });

    it('suppresses (unknown) a predicate longer than the classification cap', () => {
      // Beyond the cap the predicate cannot be classified — fail-secure, never a finding.
      expect(classifyPredicate(`auth.uid() is not null and ${'x'.repeat(20_000)}`)).toBe('unknown');
    });

    it('still classifies a normal-length authenticated-only predicate (cap does not over-suppress)', () => {
      expect(classifyPredicate('auth.uid() is not null')).toBe('authenticated-only');
    });
  });
});

describe('effectivePolicyClass', () => {
  it('uses checkClass for INSERT', () => {
    expect(
      effectivePolicyClass({
        command: 'insert',
        usingClass: 'absent',
        checkClass: 'authenticated-only',
      }),
    ).toBe('authenticated-only');
  });

  it('uses usingClass for SELECT/UPDATE/ALL', () => {
    for (const command of ['select', 'update', 'all', 'delete'] as const) {
      expect(
        effectivePolicyClass({
          command,
          usingClass: 'authenticated-only',
          checkClass: 'owner-bound',
        }),
      ).toBe('authenticated-only');
    }
  });

  it('falls back to checkClass when a non-INSERT policy has no USING', () => {
    expect(
      effectivePolicyClass({ command: 'all', usingClass: 'absent', checkClass: 'owner-bound' }),
    ).toBe('owner-bound');
  });
});

// SEC-01: the WITH CHECK governs writes independently of USING, so an owner-bound read side with an
// authenticated-only write side is still the gap on a write-capable command.
describe('isAuthenticatedOnlyGap', () => {
  it('flags an owner-bound USING with an authenticated-only WITH CHECK on FOR ALL (the SEC-01 write gap)', () => {
    expect(
      isAuthenticatedOnlyGap({
        command: 'all',
        usingClass: 'owner-bound',
        checkClass: 'authenticated-only',
      }),
    ).toBe(true);
  });

  it('flags the same gap on UPDATE and INSERT', () => {
    expect(
      isAuthenticatedOnlyGap({
        command: 'update',
        usingClass: 'owner-bound',
        checkClass: 'authenticated-only',
      }),
    ).toBe(true);
    expect(
      isAuthenticatedOnlyGap({
        command: 'insert',
        usingClass: 'absent',
        checkClass: 'authenticated-only',
      }),
    ).toBe(true);
  });

  it('does NOT flag a fully owner-bound write policy (the correct WITH CHECK)', () => {
    expect(
      isAuthenticatedOnlyGap({
        command: 'all',
        usingClass: 'owner-bound',
        checkClass: 'owner-bound',
      }),
    ).toBe(false);
  });

  it('does NOT flag a read-only SELECT whose USING is owner-bound (no write side to govern)', () => {
    expect(
      isAuthenticatedOnlyGap({
        command: 'select',
        usingClass: 'owner-bound',
        checkClass: 'authenticated-only',
      }),
    ).toBe(false);
  });

  it('still flags an authenticated-only USING (the original case-(1) gap)', () => {
    expect(
      isAuthenticatedOnlyGap({
        command: 'select',
        usingClass: 'authenticated-only',
        checkClass: 'absent',
      }),
    ).toBe(true);
  });

  it('does NOT flag role-delegated / unconditional / unknown policies', () => {
    for (const cls of [
      'role-delegated',
      'function-delegated',
      'unconditional',
      'unknown',
    ] as const) {
      expect(isAuthenticatedOnlyGap({ command: 'all', usingClass: cls, checkClass: cls })).toBe(
        false,
      );
    }
  });
});
