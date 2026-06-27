import { resolve } from 'node:path';

/**
 * Resolve the directory a command should operate on.
 *
 * Precedence: an explicit positional path (e.g. `aegis scan apps/dashboard`) wins, resolved
 * against the `--cwd` base when given, otherwise against the process cwd. With no positional,
 * the base itself is the target.
 *
 * This is what makes `aegis scan <dir>` actually scan `<dir>`. Without it the path argument is
 * silently ignored and every command falls back to the current directory — a dangerous failure
 * mode for a security scanner, since it reports on the wrong tree while looking like it worked.
 */
export function resolveRoot(
  positionalPath: string | undefined,
  cwdFlag: string | undefined,
  processCwd: string,
): string {
  const base = cwdFlag ?? processCwd;
  return positionalPath !== undefined ? resolve(base, positionalPath) : base;
}
