/**
 * Worst-case complexity classifier for a regular expression — the engine behind the ReDoS rules. It
 * answers ONE question per pattern: can attacker input force super-linear backtracking (CWE-1333, a DoS)?
 *
 *   • 'exponential' — a short crafted string blows up to 2^n work. The nested-unbounded-quantifier /
 *     star-height≥2 family (`(a+)+`, `(\w+\s?)*`, `((a+))+`) AND alternation overlap under a repeat
 *     (`(\w|\d)*`, `(a|a)*`, `(a+|b)*`), where two ways to match the same characters compound.
 *   • 'quadratic' — O(n²): two adjacent unbounded quantifiers over OVERLAPPING character sets that an
 *     end-anchor forces to re-partition on a failing match (`\d+\d+$`, `^\s+\s+$`). Lower impact (needs a
 *     large input), so the rule reports it at MEDIUM and the taint layer suppresses length-bounded input.
 *   • 'linear' — everything else.
 *
 * Deliberately conservative — the engine-wide stance is to prefer a false negative to a false positive,
 * because zero false positives is the product's trust wedge. Character-set OVERLAP is asserted only when
 * provable (identical classes, `.`, literal membership, `\d ⊆ \w`); any uncertainty (a `[...]` class, an
 * exotic escape) is treated as NON-overlapping ⇒ no finding. Out of scope by design (documented recall
 * trade-off): prefix-alternation `(a|ab)*`, and quadratic shapes not pinned by an end-anchor. Anything it
 * cannot parse within fixed bounds is 'linear' (fail-secure). NOT a general regex engine.
 */

export type RegexComplexity = 'exponential' | 'quadratic' | 'linear';

/** Beyond this source length, decline to analyze (fail-secure) rather than risk a costly/incorrect parse. */
const MAX_SOURCE_LEN = 2000;
/** Recursion ceiling for pathological nesting — exceeding it ends the walk (fail-secure). */
const MAX_DEPTH = 60;

/** The character set a consuming atom matches, modeled only as far as overlap can be proven. */
type CharClass =
  | { readonly t: 'lit'; readonly c: string } // a single literal character
  | { readonly t: 'dot' } // `.` — any character except newline
  | { readonly t: 'd' } // \d
  | { readonly t: 'D' } // \D
  | { readonly t: 'w' } // \w
  | { readonly t: 'W' } // \W
  | { readonly t: 's' } // \s
  | { readonly t: 'S' } // \S
  | { readonly t: 'opaque' }; // a `[...]` class or anything we will not reason about

type AtomKind = 'char' | 'start' | 'end' | 'boundary';

type Node =
  | { readonly k: 'alt'; readonly opts: readonly Node[] }
  | { readonly k: 'seq'; readonly items: readonly Node[] }
  | { readonly k: 'quant'; readonly child: Node; readonly unbounded: boolean; readonly min: number }
  | { readonly k: 'group'; readonly body: Node; readonly atomic: boolean }
  // `kind` distinguishes a consuming character (carrying `cls`) from a zero-width anchor (`^ $ \b`).
  | { readonly k: 'atom'; readonly kind: AtomKind; readonly cls: CharClass };

class ParseGaveUp extends Error {}

const CLASS_ESCAPE: Readonly<Record<string, CharClass['t']>> = {
  d: 'd',
  D: 'D',
  w: 'w',
  W: 'W',
  s: 's',
  S: 'S',
};

/** Recursive-descent parser for the structural fragment we need. Pure; never executes the regex. */
class RegexParser {
  private pos = 0;
  private depth = 0;
  constructor(private readonly src: string) {}

  parse(): Node {
    const node = this.alternation();
    if (this.pos < this.src.length) {
      throw new ParseGaveUp(); // leftover `)` or stray input ⇒ our model diverged from the grammar
    }
    return node;
  }

  private enter(): void {
    if (++this.depth > MAX_DEPTH) {
      throw new ParseGaveUp();
    }
  }

  private alternation(): Node {
    this.enter();
    const opts: Node[] = [this.sequence()];
    while (this.peek() === '|') {
      this.pos += 1;
      opts.push(this.sequence());
    }
    this.depth -= 1;
    return opts.length === 1 ? (opts[0] as Node) : { k: 'alt', opts };
  }

  private sequence(): Node {
    const items: Node[] = [];
    while (this.pos < this.src.length && this.peek() !== '|' && this.peek() !== ')') {
      items.push(this.quantified());
    }
    return items.length === 1 ? (items[0] as Node) : { k: 'seq', items };
  }

  private quantified(): Node {
    const atom = this.atom();
    const q = this.quantifier();
    if (!q) {
      return atom;
    }
    let unbounded = q.unbounded;
    const mod = this.peek();
    if (mod === '+') {
      this.pos += 1;
      unbounded = false; // possessive: cannot backtrack
    } else if (mod === '?') {
      this.pos += 1; // lazy: still backtracks ⇒ unchanged
    }
    return { k: 'quant', child: atom, unbounded, min: q.min };
  }

  private quantifier(): { unbounded: boolean; min: number } | undefined {
    const c = this.peek();
    if (c === '*') {
      this.pos += 1;
      return { unbounded: true, min: 0 };
    }
    if (c === '+') {
      this.pos += 1;
      return { unbounded: true, min: 1 };
    }
    if (c === '?') {
      this.pos += 1;
      return { unbounded: false, min: 0 };
    }
    if (c === '{') {
      const m = /^\{(\d+)(,(\d*)?)?\}/.exec(this.src.slice(this.pos));
      if (!m) {
        return undefined; // a bare `{` is a literal brace
      }
      this.pos += m[0].length;
      return {
        unbounded: m[2] !== undefined && (m[3] === undefined || m[3] === ''),
        min: Number(m[1]),
      };
    }
    return undefined;
  }

  private atom(): Node {
    const c = this.peek();
    if (c === '(') {
      return this.group();
    }
    if (c === '[') {
      this.charClass();
      return { k: 'atom', kind: 'char', cls: { t: 'opaque' } };
    }
    if (c === '\\') {
      return this.escape();
    }
    if (c === '^') {
      this.pos += 1;
      return { k: 'atom', kind: 'start', cls: { t: 'opaque' } };
    }
    if (c === '$') {
      this.pos += 1;
      return { k: 'atom', kind: 'end', cls: { t: 'opaque' } };
    }
    if (c === '.') {
      this.pos += 1;
      return { k: 'atom', kind: 'char', cls: { t: 'dot' } };
    }
    if (c === '' || c === ')' || c === '|' || c === '*' || c === '+' || c === '?') {
      throw new ParseGaveUp(); // a quantifier with no atom, or end of input
    }
    this.pos += 1; // any other literal character
    return { k: 'atom', kind: 'char', cls: { t: 'lit', c } };
  }

  private group(): Node {
    this.enter();
    this.pos += 1; // consume '('
    let atomic = false;
    if (this.src.startsWith('(?', this.pos - 1)) {
      const rest = this.src.slice(this.pos);
      const named = /^\?<[A-Za-z_$][\w$]*>/.exec(rest);
      if (named) {
        this.pos += named[0].length;
      } else if (/^\?[:=!]/.test(rest) || /^\?<[=!]/.test(rest)) {
        this.pos += rest.startsWith('?<') ? 3 : 2;
      } else if (rest.startsWith('?>')) {
        atomic = true;
        this.pos += 2;
      }
    }
    const body = this.alternation();
    if (this.peek() !== ')') {
      throw new ParseGaveUp();
    }
    this.pos += 1; // consume ')'
    this.depth -= 1;
    return { k: 'group', body, atomic };
  }

  private charClass(): void {
    this.pos += 1; // consume '['
    if (this.peek() === '^') {
      this.pos += 1;
    }
    if (this.peek() === ']') {
      this.pos += 1; // a `]` right after `[` is a literal member
    }
    while (this.pos < this.src.length && this.peek() !== ']') {
      this.pos += this.peek() === '\\' ? 2 : 1;
    }
    if (this.peek() !== ']') {
      throw new ParseGaveUp();
    }
    this.pos += 1; // consume ']'
  }

  private escape(): Node {
    this.pos += 1; // consume '\'
    const c = this.peek();
    if (c === '') {
      throw new ParseGaveUp();
    }
    this.pos += 1;
    if (c === 'b' || c === 'B') {
      return { k: 'atom', kind: 'boundary', cls: { t: 'opaque' } };
    }
    const named = CLASS_ESCAPE[c];
    const cls: CharClass = named ? ({ t: named } as CharClass) : { t: 'lit', c };
    return { k: 'atom', kind: 'char', cls };
  }

  private peek(): string {
    return this.pos < this.src.length ? (this.src[this.pos] as string) : '';
  }
}

// ── Character-set overlap (only ever true when PROVABLE — fail-secure toward no false positive) ─────────

const WORD = /[0-9A-Za-z_]/;
const DIGIT = /[0-9]/;
const SPACE = /\s/;

/** Is the single literal `c` a member of class `t`? */
function litInClass(c: string, t: CharClass['t']): boolean {
  switch (t) {
    case 'dot':
      return c !== '\n';
    case 'd':
      return DIGIT.test(c);
    case 'D':
      return !DIGIT.test(c);
    case 'w':
      return WORD.test(c);
    case 'W':
      return !WORD.test(c);
    case 's':
      return SPACE.test(c);
    case 'S':
      return !SPACE.test(c);
    default:
      return false;
  }
}

/** Do two character classes provably share at least one character? Uncertain ⇒ false (fail-secure). */
function classesOverlap(a: CharClass, b: CharClass): boolean {
  if (a.t === 'opaque' || b.t === 'opaque') {
    return false; // cannot reason about a [...] class
  }
  if (a.t === 'lit' && b.t === 'lit') {
    return a.c === b.c;
  }
  if (a.t === 'lit') {
    return litInClass(a.c, b.t);
  }
  if (b.t === 'lit') {
    return litInClass(b.c, a.t);
  }
  if (a.t === b.t) {
    return true; // identical class
  }
  if (a.t === 'dot' || b.t === 'dot') {
    return true; // `.` shares characters with every non-empty class
  }
  // Remaining: two distinct named classes. Only `\d ⊆ \w` is asserted; all else stays unproven (false).
  const pair = `${a.t}|${b.t}`;
  return pair === 'd|w' || pair === 'w|d';
}

// ── Nullability / consumption ──────────────────────────────────────────────────────────────────────

// INVARIANT: the walks below (nullable/consumes/classesOverlap and the detectors) recurse on the AST
// WITHOUT their own depth guard. They are bounded only because `RegexParser.enter()` caps parse depth at
// MAX_DEPTH, so any AST that parses is ≤ MAX_DEPTH deep. Do not add a recursive parser production that
// skips `enter()`, or these become unbounded.

/** Conservatively, an atom never "vanishes" (anchors block re-partition; consuming atoms obviously do). */
function nullable(node: Node): boolean {
  switch (node.k) {
    case 'atom':
      return false;
    case 'quant':
      return node.min === 0 || nullable(node.child);
    case 'group':
      return nullable(node.body);
    case 'seq':
      return node.items.every(nullable);
    case 'alt':
      return node.opts.some(nullable);
  }
}

function consumes(node: Node): boolean {
  switch (node.k) {
    case 'atom':
      return node.kind === 'char';
    case 'quant':
      return node.min >= 1 && consumes(node.child);
    case 'group':
      return consumes(node.body);
    case 'seq':
      return node.items.some(consumes);
    case 'alt':
      return node.opts.some(consumes);
  }
}

/** An unbounded quantifier over something that consumes input — the inner half of the ReDoS signature. */
function isRepartitionableRepeat(node: Node): boolean {
  return node.k === 'quant' && node.unbounded && consumes(node.child);
}

/** A consuming single-character atom directly under an unbounded quantifier — for class-overlap checks. */
function unboundedCharClass(node: Node): CharClass | undefined {
  return node.k === 'quant' &&
    node.unbounded &&
    node.child.k === 'atom' &&
    node.child.kind === 'char'
    ? node.child.cls
    : undefined;
}

// ── Exponential detection (nested unbounded quantifiers + alternation overlap) ───────────────────────

/**
 * Given the subexpression an OUTER unbounded quantifier repeats, can it be re-partitioned exponentially?
 * Two provable shapes: (1) a SEQUENCE with one unbounded consuming repeat whose siblings are all nullable
 * (`(a+)+`, `(\w+\s?)*`, `(\s*\S+)*`); (2) an ALTERNATION under the repeat where two ways match the same
 * characters — a branch that is itself an unbounded repeat (`(a+|b)*`) or two single-atom branches whose
 * classes overlap (`(\w|\d)*`, `(a|a)*`). A redundant group is unwrapped; an atomic group blocks it.
 */
function repartitionable(child: Node, depth: number): boolean {
  if (depth > MAX_DEPTH) {
    return false;
  }
  let node = child;
  while (node.k === 'group') {
    if (node.atomic) {
      return false;
    }
    node = node.body;
  }
  if (node.k === 'alt') {
    return alternationOverlaps(node, depth);
  }
  const items = node.k === 'seq' ? node.items : [node];
  return items.some((el, i) => {
    const isRepeat =
      isRepartitionableRepeat(el) ||
      (el.k === 'group' && !el.atomic && repartitionable(el, depth + 1));
    return isRepeat && items.every((other, j) => j === i || nullable(other));
  });
}

/** An alternation under a repeat is exponential if two branches can match the same input. */
function alternationOverlaps(alt: { readonly opts: readonly Node[] }, depth: number): boolean {
  // A branch that is itself an unbounded consuming repeat compounds with the outer repeat.
  if (
    alt.opts.some(
      (o) => isRepartitionableRepeat(o) || (o.k === 'group' && repartitionable(o, depth + 1)),
    )
  ) {
    return true;
  }
  // Two single-character branches whose classes overlap → ambiguous per shared character.
  const classes = alt.opts.map(branchCharClass).filter((c): c is CharClass => c !== undefined);
  for (let i = 0; i < classes.length; i++) {
    for (let j = i + 1; j < classes.length; j++) {
      if (classesOverlap(classes[i] as CharClass, classes[j] as CharClass)) {
        return true;
      }
    }
  }
  return false;
}

/** The character class of a branch that is a single consuming atom (else undefined). */
function branchCharClass(node: Node): CharClass | undefined {
  return node.k === 'atom' && node.kind === 'char' ? node.cls : undefined;
}

function hasExponential(node: Node, depth: number): boolean {
  if (depth > MAX_DEPTH) {
    return false;
  }
  if (node.k === 'quant') {
    return (
      (node.unbounded && repartitionable(node.child, depth + 1)) ||
      hasExponential(node.child, depth + 1)
    );
  }
  if (node.k === 'group') {
    return hasExponential(node.body, depth + 1);
  }
  if (node.k === 'seq') {
    return node.items.some((n) => hasExponential(n, depth + 1));
  }
  if (node.k === 'alt') {
    return node.opts.some((n) => hasExponential(n, depth + 1));
  }
  return false;
}

// ── Quadratic detection (two overlapping adjacent unbounded repeats pinned by an end-anchor) ──────────

function isEndAnchor(node: Node): boolean {
  return node.k === 'atom' && node.kind === 'end';
}

/** A sequence `… Qa Qb [nullable…] $` where Qa,Qb are overlapping unbounded char-repeats ⇒ O(n²). */
function seqIsQuadratic(items: readonly Node[]): boolean {
  for (let i = 0; i + 1 < items.length; i++) {
    const ca = unboundedCharClass(items[i] as Node);
    const cb = unboundedCharClass(items[i + 1] as Node);
    if (!ca || !cb || !classesOverlap(ca, cb)) {
      continue;
    }
    // After the pair, the match must be forced to the end (only nullable elements before a `$`), so a
    // failing input re-partitions the overlap O(n²) times instead of bailing early.
    for (let j = i + 2; j < items.length; j++) {
      if (isEndAnchor(items[j] as Node)) {
        if (items.slice(i + 2, j).every(nullable)) {
          return true;
        }
      }
    }
  }
  return false;
}

function hasQuadratic(node: Node, depth: number): boolean {
  if (depth > MAX_DEPTH) {
    return false;
  }
  switch (node.k) {
    case 'seq':
      return seqIsQuadratic(node.items) || node.items.some((n) => hasQuadratic(n, depth + 1));
    case 'group':
      return hasQuadratic(node.body, depth + 1);
    case 'quant':
      return hasQuadratic(node.child, depth + 1);
    case 'alt':
      return node.opts.some((n) => hasQuadratic(n, depth + 1));
    case 'atom':
      return false;
  }
}

/**
 * Classify a regex body (WITHOUT delimiters or flags). `flags` are irrelevant to backtracking complexity
 * — no JavaScript flag linearizes a pattern — so they are accepted and ignored.
 */
export function classifyRegex(source: string, _flags?: string): RegexComplexity {
  if (source.length === 0 || source.length > MAX_SOURCE_LEN) {
    return 'linear';
  }
  let ast: Node;
  try {
    ast = new RegexParser(source).parse();
  } catch {
    return 'linear'; // unparseable ⇒ decline rather than risk a false positive
  }
  if (hasExponential(ast, 0)) {
    return 'exponential';
  }
  return hasQuadratic(ast, 0) ? 'quadratic' : 'linear';
}
