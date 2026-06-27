import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { splitStatements } from './lexer';

const texts = (sql: string): string[] => splitStatements(sql).map((s) => s.text);

describe('splitStatements', () => {
  it('splits top-level statements on semicolons', () => {
    expect(texts('select 1; select 2;')).toEqual(['select 1', 'select 2']);
  });

  it('does not split inside a single-quoted string', () => {
    expect(texts("insert into t values ('a;b;c');")).toEqual(["insert into t values ('a;b;c')"]);
  });

  it('handles escaped single quotes', () => {
    expect(texts("select 'it''s; fine'; select 2;")).toEqual(["select 'it''s; fine'", 'select 2']);
  });

  it('does not split inside a dollar-quoted function body', () => {
    const sql =
      'create function f() returns void language plpgsql as $$ begin; perform 1; end; $$;';
    expect(splitStatements(sql)).toHaveLength(1);
  });

  it('does not split inside a tagged dollar-quote', () => {
    const sql = 'create function g() returns int language sql as $func$ select 1; $func$ stable;';
    expect(splitStatements(sql)).toHaveLength(1);
  });

  it('ignores line comments', () => {
    expect(texts('-- a; b; c\nselect 1;')).toEqual(['select 1']);
  });

  it('ignores block comments', () => {
    expect(texts('/* a; b */ select 1; /* c; */ select 2;')).toEqual(['select 1', 'select 2']);
  });

  it('treats $1 parameter placeholders as normal text (not a dollar-quote)', () => {
    expect(texts('select * from t where id = $1; select 2;')).toEqual([
      'select * from t where id = $1',
      'select 2',
    ]);
  });

  it('records the 1-based start line of each statement', () => {
    const stmts = splitStatements('\n\nselect 1;\n\n  select 2;');
    expect(stmts[0]?.line).toBe(3);
    expect(stmts[1]?.line).toBe(5);
  });

  it('property: semicolons inside a dollar-quoted body never increase the statement count', () => {
    fc.assert(
      fc.property(fc.nat({ max: 30 }), (semis) => {
        const body = `xx${';'.repeat(semis)}`;
        const sql = `create function f() returns void language plpgsql as $$ ${body} $$;`;
        expect(splitStatements(sql)).toHaveLength(1);
      }),
      { numRuns: 30 },
    );
  });
});
