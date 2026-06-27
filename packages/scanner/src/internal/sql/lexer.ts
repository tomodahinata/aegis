/**
 * A focused SQL statement splitter for Supabase migrations — not a full parser. It splits on top-level
 * `;` while correctly skipping the places a `;` does NOT end a statement: single-quoted strings,
 * line/block comments, and PostgreSQL dollar-quoted bodies (`$$ … $$`, `$tag$ … $tag$`) which contain
 * the semicolons of a function body. Mirrors the pure-analyzer style of `internal/csp.ts`; the model
 * layer does per-statement regex extraction over the result.
 */

export interface SqlStatement {
  /** Statement text, trimmed, without the terminating `;`. */
  readonly text: string;
  /** 1-based line of the statement's first non-whitespace character. */
  readonly line: number;
  /** 1-based column of the statement's first non-whitespace character. */
  readonly column: number;
}

type State = 'normal' | 'line-comment' | 'block-comment' | 'single-quote' | 'dollar-quote';

/** At a `$`, read a dollar-quote tag (`$$` → '', `$tag$` → 'tag'), or undefined if not a dollar quote. */
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

export function splitStatements(sql: string): SqlStatement[] {
  const out: SqlStatement[] = [];
  const n = sql.length;
  let i = 0;
  let line = 1;
  let column = 1;
  let state: State = 'normal';
  let closeToken = ''; // the `$tag$` that closes the current dollar-quote
  let startIndex = -1; // start of the current statement, or -1 between statements
  let startLine = 1;
  let startColumn = 1;

  const beginStatement = (index: number): void => {
    if (startIndex === -1) {
      startIndex = index;
      startLine = line;
      startColumn = column;
    }
  };
  const endStatement = (endIndex: number): void => {
    if (startIndex !== -1) {
      const text = sql.slice(startIndex, endIndex).trim();
      if (text.length > 0) {
        out.push({ text, line: startLine, column: startColumn });
      }
      startIndex = -1;
    }
  };
  const consume = (count: number): void => {
    for (let k = 0; k < count; k += 1) {
      if (sql.charAt(i + k) === '\n') {
        line += 1;
        column = 1;
      } else {
        column += 1;
      }
    }
    i += count;
  };

  while (i < n) {
    const ch = sql.charAt(i);
    const next = sql.charAt(i + 1);

    if (state === 'normal') {
      if (ch === '-' && next === '-') {
        state = 'line-comment';
        consume(2);
      } else if (ch === '/' && next === '*') {
        state = 'block-comment';
        consume(2);
      } else if (ch === "'") {
        beginStatement(i);
        state = 'single-quote';
        consume(1);
      } else if (ch === '$') {
        const tag = readDollarTag(sql, i);
        if (tag === undefined) {
          beginStatement(i);
          consume(1);
        } else {
          beginStatement(i);
          closeToken = `$${tag}$`;
          state = 'dollar-quote';
          consume(closeToken.length);
        }
      } else if (ch === ';') {
        endStatement(i);
        consume(1);
      } else {
        if (!/\s/.test(ch)) {
          beginStatement(i);
        }
        consume(1);
      }
    } else if (state === 'line-comment') {
      if (ch === '\n') {
        state = 'normal';
      }
      consume(1);
    } else if (state === 'block-comment') {
      if (ch === '*' && next === '/') {
        state = 'normal';
        consume(2);
      } else {
        consume(1);
      }
    } else if (state === 'single-quote') {
      if (ch === "'" && next === "'") {
        consume(2); // escaped quote
      } else if (ch === "'") {
        state = 'normal';
        consume(1);
      } else {
        consume(1);
      }
    } else {
      // dollar-quote
      if (ch === '$' && sql.startsWith(closeToken, i)) {
        state = 'normal';
        consume(closeToken.length);
      } else {
        consume(1);
      }
    }
  }
  endStatement(n);
  return out;
}
