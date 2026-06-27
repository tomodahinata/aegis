import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, relative } from 'node:path';

const MARKER = '/* aegis:managed */';

const MIDDLEWARE_TEMPLATE = `${MARKER}
import { secure } from '@aegiskit/next';

// One line of defense-in-depth: hardened headers, nonce-based CSP, origin checks.
// IMPORTANT: remove any Content-Security-Policy block from next.config — secure() owns CSP.
export default secure();

export const config = {
  matcher: ['/((?!_next/static|_next/image|favicon.ico).*)'],
};
`;

/** Whether a middleware already exists (and is ours), or is absent and can be scaffolded. */
export type ScaffoldStatus = 'managed' | 'unmanaged' | 'absent';

export interface MiddlewareScaffold {
  readonly status: ScaffoldStatus;
  /** Absolute path to create when `absent`, or the existing file otherwise. */
  readonly target: string;
  /** Display path relative to cwd. */
  readonly shown: string;
  readonly contents: string;
}

/**
 * Decide where/whether a `secure()` middleware should be scaffolded — pure (no writes), so both
 * `init` and `fix` share one source of truth for the template and target resolution.
 */
export function planMiddlewareScaffold(cwd: string): MiddlewareScaffold {
  const candidates = ['src/middleware.ts', 'middleware.ts', 'src/proxy.ts', 'proxy.ts'].map((p) =>
    join(cwd, p),
  );
  const existing = candidates.find((p) => existsSync(p));
  const hasSrc = existsSync(join(cwd, 'src'));
  const target = existing ?? join(cwd, hasSrc ? 'src/middleware.ts' : 'middleware.ts');
  const shown = relative(cwd, target) || target;

  let status: ScaffoldStatus = 'absent';
  if (existing) {
    status = readFileSync(existing, 'utf8').includes(MARKER) ? 'managed' : 'unmanaged';
  }
  return { status, target, shown, contents: MIDDLEWARE_TEMPLATE };
}

/** Write the scaffold to disk (creating parent dirs). Caller must check `status === 'absent'`. */
export function writeMiddlewareScaffold(scaffold: MiddlewareScaffold): void {
  mkdirSync(dirname(scaffold.target), { recursive: true });
  writeFileSync(scaffold.target, scaffold.contents);
}

export interface InitArgs {
  readonly cwd: string;
  readonly dryRun: boolean;
}

/** Idempotently scaffold a `secure()` middleware, detecting middleware.ts vs proxy.ts. */
export function runInit(args: InitArgs): number {
  const scaffold = planMiddlewareScaffold(args.cwd);

  if (scaffold.status === 'managed') {
    process.stdout.write(`aegis: ${scaffold.shown} is already Aegis-managed — nothing to do.\n`);
    return 0;
  }
  if (scaffold.status === 'unmanaged') {
    process.stdout.write(
      `aegis: ${scaffold.shown} exists and is not Aegis-managed. Add \`export default secure()\` from @aegiskit/next yourself (not overwriting your file).\n`,
    );
    return 0;
  }

  if (args.dryRun) {
    process.stdout.write(
      `aegis (dry-run): would create ${scaffold.shown}:\n\n${scaffold.contents}\n`,
    );
    return 0;
  }

  writeMiddlewareScaffold(scaffold);
  process.stdout.write(
    `aegis: created ${scaffold.shown}. Next: install @aegiskit/next, then remove any CSP header from next.config (secure() is the single CSP emitter).\n`,
  );
  return 0;
}
