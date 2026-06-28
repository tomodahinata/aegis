// SAFE: the backslash is escaped FIRST, so a trailing `\` in the input can no longer escape the quote
// that follows — the quote-escape cannot be bypassed.
export function quote(input: string): string {
  return `'${input.replace(/\\/g, '\\\\').replace(/'/g, "\\'")}'`;
}
