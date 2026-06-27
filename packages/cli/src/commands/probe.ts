import { probe, type RemoteConsent, ScopeError, toScanResult } from '@aegiskit/dast';
import { type ScanResult, type Severity, toJson, toSarif } from '@aegiskit/scanner';
import { EXIT, exitCodeFor } from '../exit';
import { colorEnabled } from '../internal/colors';
import { scanProject } from '../project-scan';
import { renderReport } from '../reporters/pretty';
import type { OutputFormat } from './scan';

export interface ProbeArgs {
  readonly cwd: string;
  /** Target origin, e.g. `http://localhost:3000`. */
  readonly url: string;
  readonly format: OutputFormat;
  readonly severity: Severity;
  readonly strict: boolean;
  readonly noColor: boolean;
  readonly plain: boolean;
  readonly mode: 'passive' | 'active' | 'dry-run';
  /** Run a static scan of `cwd` and correlate confirmed findings. */
  readonly correlate: boolean;
  readonly allowRemote: boolean;
  /** The ownership attestation required (with --allow-remote) for a non-loopback target. */
  readonly iOwn?: string;
  readonly maxRequests?: number;
}

export async function runProbe(args: ProbeArgs): Promise<number> {
  let ackOrigin: string;
  try {
    ackOrigin = new URL(args.url).origin;
  } catch {
    process.stderr.write(`aegis: invalid target URL "${args.url}"\n`);
    return EXIT.USAGE;
  }

  // Optionally run a static scan first, so runtime confirmations can upgrade static suspicions.
  // Use the same full-project scan (TS + SQL/RLS) as scan/ci/doctor so the prober correlates against
  // the identical static picture every other command reports — not a TS-only subset.
  let staticResult: ScanResult | undefined;
  if (args.correlate) {
    staticResult = scanProject(args.cwd);
  }

  const consent: RemoteConsent | undefined =
    args.allowRemote || args.iOwn !== undefined
      ? {
          allowRemote: args.allowRemote,
          ...(args.iOwn !== undefined ? { ack: { origin: ackOrigin, statement: args.iOwn } } : {}),
        }
      : undefined;

  let result: Awaited<ReturnType<typeof probe>>;
  try {
    result = await probe({
      origin: args.url,
      // Always probe the given URL itself, plus any routes discovered under cwd.
      targets: [args.url],
      cwd: args.cwd,
      mode: args.mode,
      ...(consent ? { consent } : {}),
      ...(staticResult ? { staticResult } : {}),
      ...(args.maxRequests !== undefined ? { budget: { maxRequests: args.maxRequests } } : {}),
    });
  } catch (error) {
    if (error instanceof ScopeError) {
      process.stderr.write(`aegis: ${error.message}\n`);
      return EXIT.USAGE;
    }
    throw error;
  }

  const shaped = toScanResult(result.findings, result.durationMs);

  if (args.format === 'json') {
    process.stdout.write(`${toJson(shaped)}\n`);
  } else if (args.format === 'sarif') {
    process.stdout.write(`${toSarif(shaped)}\n`);
  } else {
    const header: string[] = [`Aegis probe — ${result.mode} mode @ ${args.url}`];
    const confirmed =
      result.correlations.length > 0 ? `, ${result.correlations.length} confirmed exploitable` : '';
    header.push(
      `  ${result.targets.length} route(s), ${result.requestsSent} request(s) sent${confirmed}`,
    );
    if (result.probesFailed > 0) {
      header.push(`  ${result.probesFailed} probe(s) errored — results are partial`);
    }
    if (result.authorizedBy !== undefined) {
      header.push(`  authorized by: ${result.authorizedBy}`);
    }
    if (result.mode === 'dry-run') {
      header.push(`  dry-run — no requests sent; ${result.plan.length} planned`);
    }
    process.stdout.write(`${header.join('\n')}\n\n`);
    process.stdout.write(
      renderReport(shaped, { color: colorEnabled(args.noColor), plain: args.plain, cwd: args.cwd }),
    );
  }

  // A dry-run never fails the build; a real run uses the standard confidence-gated exit code.
  return args.mode === 'dry-run'
    ? EXIT.CLEAN
    : exitCodeFor(shaped, { threshold: args.severity, strict: args.strict });
}
