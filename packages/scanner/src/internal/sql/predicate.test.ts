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
    // owner-bound — the correct pattern (never flagged)
    ['auth.uid() = user_id', 'owner-bound'],
    ['user_id = auth.uid()', 'owner-bound'],
    ['(select auth.uid()) = user_id', 'owner-bound'],
    ["auth.jwt() ->> 'sub' = user_id::text", 'owner-bound'],
    ['auth.uid() = user_id and deleted = false', 'owner-bound'],
    // authenticated-only — THE gap
    ["auth.role() = 'authenticated'", 'authenticated-only'],
    ['auth.uid() is not null', 'authenticated-only'],
    ["auth.jwt() ->> 'role' = 'admin'", 'authenticated-only'],
    // role-delegated — membership subquery (suppressed)
    [
      'tenant_id in (select tenant_id from memberships where user_id = auth.uid())',
      'role-delegated',
    ],
    ['exists (select 1 from team_members m where m.user_id = auth.uid())', 'role-delegated'],
    // function-delegated — custom predicate function (suppressed)
    ['has_access(id)', 'function-delegated'],
    ['public.is_member(org_id)', 'function-delegated'],
    ['has_access(id) and auth.uid() is not null', 'function-delegated'],
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
    ["auth.jwt() ->> 'role' = 'admin'", 'authenticated-only'],
    // COR-02 — a bare numeric/literal on the column side is NOT an ownership comparison, so it falls
    // through to authenticated-only (mentions auth, binds no column) instead of being mistaken owner-bound
    // (the genuine column comparison `auth.uid() = user_id` is pinned owner-bound above).
    ['auth.uid() = 1', 'authenticated-only'],
    ["auth.uid() = 'literal'", 'authenticated-only'],
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

    it("keeps a JWT role claim authenticated-only (auth.jwt() ->> 'role' = 'admin')", () => {
      expect(classifyPredicate("auth.jwt() ->> 'role' = 'admin'")).toBe('authenticated-only');
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
    it('classifies a ~200k-char predicate well under 150ms (no O(n²) blowup)', () => {
      const huge = `auth.uid() = user_id and ${'a'.repeat(200_000)}`;
      const start = performance.now();
      const cls = classifyPredicate(huge);
      const elapsed = performance.now() - start;
      // Past the cap the predicate is suppressed (fail-secure), not classified by the bounded regexes.
      expect(cls).toBe('unknown');
      expect(elapsed).toBeLessThan(150);
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
