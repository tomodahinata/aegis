// VULN: builds a single-quoted string by backslash-escaping the quote, but never escapes the backslash
// first. An input ending in `\` becomes `\'`, which escapes the escape and closes the quote — the
// sanitizer is bypassable (incomplete escaping, CWE-116).
export function quote(input: string): string {
  return `'${input.replace(/'/g, "\\'")}'`;
}
