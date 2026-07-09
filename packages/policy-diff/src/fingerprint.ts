/**
 * FNV-1a 64-bit over a delta's stable identity — used for dedup and sticky-comment identity across
 * re-pushes/re-runs. NOT a security primitive: collision-resistance is irrelevant here, only that
 * the same logical change hashes the same regardless of file path or line position.
 */
export function fingerprint(parts: readonly (string | number)[]): string {
  let h = 0xcbf29ce484222325n;
  const prime = 0x100000001b3n;
  const s = parts.join('\x00');
  for (let i = 0; i < s.length; i += 1) {
    h ^= BigInt(s.charCodeAt(i));
    h = (h * prime) & 0xffffffffffffffffn;
  }
  return h.toString(16).padStart(16, '0');
}
