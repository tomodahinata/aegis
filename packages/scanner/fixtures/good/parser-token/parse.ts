// SAFE: a domain parser comparing a string "token" against literal codes (e.g. baseball position
// markers PH/PR). `token` here is a parser symbol, not a security token — the crypto rule must not flag it.
export function roleGlyph(token: string): string {
  if (token === 'PH') {
    return 'batter';
  }
  if (token === 'PR') {
    return 'runner';
  }
  return token;
}
