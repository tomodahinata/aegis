/** Shannon entropy in bits/char — a cheap "does this look random?" signal for secret detection. */
export function shannonEntropy(value: string): number {
  if (value.length === 0) {
    return 0;
  }
  const counts = new Map<string, number>();
  for (const char of value) {
    counts.set(char, (counts.get(char) ?? 0) + 1);
  }
  let entropy = 0;
  for (const count of counts.values()) {
    const p = count / value.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

/**
 * Is `value` a character-set "alphabet" constant — the digit table behind a base62 / base64 / base58
 * encoder (`"ABC…XYZabc…xyz0…9"`)? Such tables are long, high-entropy, and mixed-case, so the generic
 * secret heuristic mistakes them for credentials. (A pure hex table like `"0123456789abcdef"` also returns
 * true here, but never reaches this guard: the caller requires mixed case first, which single-case hex
 * fails — so this is purely the safety net for the mixed-case base62/base64 tables.) Their tell is
 * structural:
 * almost every adjacent character pair is consecutive in code-point order (the `A→B→C…`, `a→b…`, `0→1…`
 * runs an encoder needs), whereas a real random secret's adjacent pairs are consecutive only by rare
 * chance. We treat a string whose adjacent pairs are ≥ 50% consecutive as an alphabet, never a secret:
 * the standard 62/64-char tables sit near 95%, a random 40-char token near 0%, so the gap is wide and
 * stable, and a real credential is never excluded by accident (it would need half its characters to fall
 * in ascending runs).
 */
export function looksLikeCharsetAlphabet(value: string): boolean {
  if (value.length < 16) {
    return false; // too short to be a meaningful encoder table; let the entropy gate decide
  }
  let consecutive = 0;
  for (let i = 1; i < value.length; i += 1) {
    if (value.charCodeAt(i) === value.charCodeAt(i - 1) + 1) {
      consecutive += 1;
    }
  }
  return consecutive / (value.length - 1) >= 0.5;
}
