import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { classifyRegex, type RegexComplexity } from './redos';

describe('classifyRegex', () => {
  // EXPONENTIAL — 2^n backtracking the rule MUST catch. Nested quantifiers + alternation overlap.
  const exponential: readonly string[] = [
    '(a+)+',
    '(a*)*',
    '(a+)*',
    '(a*)+',
    '(a+)+?',
    '(\\d+)+',
    '([a-z]+)*',
    '(\\w+)*',
    '(.+)+',
    '(.*)*',
    '(a+)+$',
    '^([a-zA-Z]+)*$',
    '(\\w+\\s?)*',
    '(\\s*\\S+)*',
    '(a*b*)*',
    '((a+))+',
    '((a+)+)+',
    'foo(a+)+bar',
    '(a{1,})+',
    '(a+){2,}',
    // alternation overlap (also exponential)
    '(a|a)*',
    '(\\w|\\d)*', // \d ⊆ \w → overlap on digits
    '(a|.)*', // `.` overlaps `a`
    '(a+|b)*', // a branch that is itself an unbounded repeat
  ];

  // QUADRATIC — O(n²) the rule reports at MEDIUM. Adjacent overlapping repeats pinned by an end anchor.
  const quadratic: readonly string[] = [
    '\\d+\\d+$',
    '^\\s+\\s+$',
    '\\w+\\w+$',
    '\\w+\\d+$', // \d ⊆ \w overlap
    '^[a]*\\w+\\d+$', // overlap pair before the end anchor
    '.+.+$',
    'x|\\d+\\d+$', // quadratic pair nested inside an alternation arm (exercises the 'alt' recursion)
  ];

  // LINEAR / SAFE — must classify 'linear' (the zero-false-positive corpus).
  const linear: readonly string[] = [
    '',
    'a+',
    '\\d+',
    '.*',
    '[a-z]+',
    'a*b*',
    '(ab)+',
    '(abc)*',
    '(ab+)+',
    '(a+b+)+',
    '(\\w+@\\w+)+',
    '(.*,)*',
    '(\\w+\\b)*',
    '(a|b)+', // disjoint branches
    '(a|b|c)*',
    '(foo|bar)+',
    '(\\d{1,3})+',
    '(a+){1,5}',
    '(a{2})+',
    '(a++)+',
    '(a+)++',
    '(?>a+)+',
    '^abc$',
    'https?://[\\w.-]+',
    '\\d{4}-\\d{2}-\\d{2}',
    '\\d+\\d+', // overlapping pair but NO end anchor ⇒ not quadratic
    'x|\\d+\\s+$', // alternation arm with a DISJOINT pair ⇒ the 'alt' recursion stays linear
    '\\d+\\s+$', // disjoint classes ⇒ not quadratic
    '\\d+x\\d+$', // a mandatory consuming separator between the repeats
    '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}',
  ];

  const expectClass = (re: string, cls: RegexComplexity): void => {
    expect(classifyRegex(re)).toBe(cls);
  };

  for (const re of exponential) {
    it(`classifies ${JSON.stringify(re)} as exponential`, () => expectClass(re, 'exponential'));
  }

  it('treats opaque [...] alternation branches as NON-overlapping (fail-secure ⇒ not exponential)', () => {
    // `[ab]`/`[0-9]` are opaque to the analyzer; without provable overlap it must NOT flag (zero-FP).
    expect(classifyRegex('(a|[ab])+')).toBe('linear');
    expect(classifyRegex('^(\\d|[0-9])*$')).not.toBe('exponential');
  });

  for (const re of quadratic) {
    it(`classifies ${JSON.stringify(re)} as quadratic`, () => expectClass(re, 'quadratic'));
  }

  for (const re of linear) {
    it(`classifies ${JSON.stringify(re)} as linear`, () => expectClass(re, 'linear'));
  }

  it('exponential takes precedence over quadratic', () => {
    expect(classifyRegex('(a+)+\\d+\\d+$')).toBe('exponential');
  });

  it('every flagged pattern is a real, compilable RegExp', () => {
    for (const re of [...exponential, ...quadratic]) {
      expect(() => new RegExp(re)).not.toThrow();
    }
  });

  it('declines (fail-secure) on over-long source', () => {
    expect(classifyRegex(`(${'a'.repeat(5000)}+)+`)).toBe('linear');
  });

  it('declines on malformed input rather than throw', () => {
    for (const bad of ['(a+', 'a)', '(((', '[a-z', '\\', '(?', '+']) {
      expect(classifyRegex(bad)).toBe('linear');
    }
  });

  it('never throws on arbitrary input (total function, fail-secure)', () => {
    fc.assert(
      fc.property(fc.string({ maxLength: 40 }), (s) => {
        expect(typeof classifyRegex(s)).toBe('string');
      }),
      { numRuns: 500 },
    );
  });

  it('never throws on REGEX-SHAPED input (exercises the parser/classifier recursion paths)', () => {
    // Plain strings rarely produce balanced groups or nested quantifiers, so they under-sample the
    // hasExponential/hasQuadratic/MAX_DEPTH paths. This alphabet biases toward real regex structure.
    const metachars = '()[]{}|+*?.^$\\dwsDWS,';
    fc.assert(
      fc.property(
        fc.string({ unit: fc.constantFrom(...metachars.split('')), maxLength: 60 }),
        (s) => {
          expect(typeof classifyRegex(s)).toBe('string');
        },
      ),
      { numRuns: 1000 },
    );
  });

  it('ignores flags', () => {
    expect(classifyRegex('(a+)+', 'gimsuy')).toBe('exponential');
    expect(classifyRegex('abc', 'gimsuy')).toBe('linear');
  });
});
