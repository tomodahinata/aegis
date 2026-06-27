import { EXIT } from '../exit';
import { scanProject } from '../project-scan';

export interface DoctorArgs {
  readonly cwd: string;
  /** Optionally fetch a running app and assert headers are actually emitted. */
  readonly url?: string;
}

const LIVE_HEADER_CHECKS: ReadonlyArray<readonly [label: string, header: string]> = [
  ['Content-Security-Policy', 'content-security-policy'],
  ['Strict-Transport-Security', 'strict-transport-security'],
  ['X-Content-Type-Options', 'x-content-type-options'],
  ['X-Frame-Options', 'x-frame-options'],
  ['Referrer-Policy', 'referrer-policy'],
];

export async function runDoctor(args: DoctorArgs): Promise<number> {
  const result = scanProject(args.cwd);
  const lines: string[] = ['Aegis doctor'];
  lines.push(
    `  static scan: ${result.scannedFiles} files, ${result.findings.length} findings (BLOCKER ${result.summary.BLOCKER}, HIGH ${result.summary.HIGH})`,
  );

  let liveMissingCritical = false;
  // Fail secure: a requested live check that could not run (timeout/DNS/TLS/refused) must
  // NOT exit clean — otherwise `doctor --url` against a down app reports GREEN.
  let liveProbeFailed = false;
  if (args.url !== undefined) {
    lines.push(`  live headers @ ${args.url}:`);
    try {
      const response = await fetch(args.url, {
        redirect: 'manual',
        signal: AbortSignal.timeout(5000),
      });
      for (const [label, header] of LIVE_HEADER_CHECKS) {
        const present =
          response.headers.get(header) !== null ||
          (header === 'content-security-policy' &&
            response.headers.get('content-security-policy-report-only') !== null);
        lines.push(`    ${present ? '✓' : '✗'} ${label}`);
        if (
          !present &&
          (header === 'content-security-policy' || header === 'strict-transport-security')
        ) {
          liveMissingCritical = true;
        }
      }
    } catch (error) {
      lines.push(`    could not fetch: ${error instanceof Error ? error.message : String(error)}`);
      liveProbeFailed = true;
    }
  }

  process.stdout.write(`${lines.join('\n')}\n`);
  return result.summary.BLOCKER > 0 || liveMissingCritical || liveProbeFailed
    ? EXIT.FINDINGS
    : EXIT.CLEAN;
}
