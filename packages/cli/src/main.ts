#!/usr/bin/env node
import { parseArgs } from 'node:util';
import type { Severity } from '@aegiskit/scanner';
import { runCi } from './commands/ci';
import { type DiffFormat, runDiff } from './commands/diff';
import { runDoctor } from './commands/doctor';
import { runFix } from './commands/fix';
import { runInit } from './commands/init';
import { runProbe } from './commands/probe';
import { parseFramework, parseReportFormat, runReport } from './commands/report';
import { type OutputFormat, runScan } from './commands/scan';
import { UsageError } from './errors';
import { EXIT } from './exit';
import { resolveRoot } from './root';

const HELP = `aegis — application-layer security for Next.js / Supabase

Usage: aegis <command> [path] [options]

Commands:
  scan      Scan the project and print findings
  fix       Preview safe auto-fixes (and a remediation plan); apply with --write
  ci        Scan for CI: SARIF output, GitHub annotations, stable exit codes
  init      Scaffold a secure() middleware (idempotent)
  doctor    Audit effective security config (optionally against a running URL)
  probe     Dynamically probe a RUNNING app you own; confirm findings at runtime
  report    Map findings to SOC 2 / ISO 27001 control evidence (reference mapping)
  diff      Semantic access diff of Supabase RLS between two git refs (PR gate)

[path] is an optional directory to operate on (default: --cwd, else current directory).

Options:
  --format <pretty|json|sarif>   scan output format (default: pretty); fix: pretty|json; report: md|json|html
  --framework <soc2|iso27001>    (report) compliance framework to map findings to
  --out <file>                   (report) write the report to a file instead of stdout
  --record                       (report) append this scan to the history ledger (remediation evidence)
  --history <file>               (report) scan-history ledger path (default: .aegis/history.jsonl)
  --commit <sha>                 (report, with --record) commit SHA to stamp on the recorded scan (e.g. CI's github.sha)
  --severity <BLOCKER|HIGH|MEDIUM|LOW|INFO>   threshold that fails the run (default: HIGH)
  --strict                       fail on findings of any confidence (default: high only)
  --no-color                     disable ANSI color
  --plain                        screen-reader-friendly output
  --write                        (fix) apply the auto-fixes (default: preview only)
  --rule <id>                    (fix) limit remediation to a single rule
  --baseline <file>              (scan) apply a baseline; fail only on NEW findings
  --update-baseline              (scan) write/refresh aegis-baseline.json from current findings
  --show-suppressed              (scan) include suppressed findings, flagged
  --sarif-out <file>             (ci) write SARIF to a file
  --annotations                  (ci) emit GitHub ::error:: annotations
  --url <url>                    (doctor) check live response headers
  --dry-run                      (init) print the scaffold; (probe) plan requests without sending
  --correlate                    (probe) run a static scan and confirm matching findings at runtime
  --active                       (probe) enable active (state-changing) probes; auth/IDOR also need test identities, supplied only via the @aegiskit/dast API
  --allow-remote                 (probe) allow a non-loopback target (with --i-own)
  --i-own <statement>            (probe) ownership attestation required for a remote target
  --max-requests <n>             (probe) hard cap on total requests (default 500)
  --base <ref>                   (diff) git ref to compare FROM (e.g. origin/main) — required
  --head <ref>                   (diff) git ref to compare TO (default: the working tree)
  --trust <fn>                   (diff, repeatable) trusted authorization helper, e.g. public.is_member
  --cwd <dir>                    project root (default: current directory)
  --help                         show this help

Diff verdicts: WIDENING (access grew), narrowing, REQUIRES REVIEW (not mechanically comparable —
fails closed, never silently "no change"). --format markdown emits a PR-comment-ready body.
Exit: high-severity deltas → 1; with --strict, notice-level widenings/reviews also → 1.

Probe targets default to localhost only; a remote host requires --allow-remote AND --i-own.

Exit codes: 0 clean · 1 findings · 2 usage error · 3 internal error
`;

const SEVERITIES: readonly string[] = ['BLOCKER', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
const FORMATS: readonly string[] = ['pretty', 'json', 'sarif'];

function parseSeverity(value: string | undefined): Severity {
  if (value === undefined) {
    return 'HIGH';
  }
  const upper = value.toUpperCase();
  if (SEVERITIES.includes(upper)) {
    return upper as Severity;
  }
  throw new UsageError(`invalid --severity "${value}"`);
}

function parseFormat(value: string | undefined): OutputFormat {
  if (value === undefined) {
    return 'pretty';
  }
  if (FORMATS.includes(value)) {
    return value as OutputFormat;
  }
  throw new UsageError(`invalid --format "${value}"`);
}

function str(value: string | boolean | undefined): string | undefined {
  return typeof value === 'string' ? value : undefined;
}

const DIFF_FORMATS: readonly string[] = ['pretty', 'markdown', 'json'];

function parseDiffFormat(value: string | undefined): DiffFormat {
  if (value === undefined) {
    return 'pretty';
  }
  if (DIFF_FORMATS.includes(value)) {
    return value as DiffFormat;
  }
  throw new UsageError(`diff supports --format pretty|markdown|json (got "${value}")`);
}

async function main(): Promise<number> {
  const { values, positionals } = parseArgs({
    allowPositionals: true,
    options: {
      format: { type: 'string' },
      base: { type: 'string' },
      head: { type: 'string' },
      trust: { type: 'string', multiple: true },
      severity: { type: 'string' },
      strict: { type: 'boolean', default: false },
      'no-color': { type: 'boolean', default: false },
      plain: { type: 'boolean', default: false },
      baseline: { type: 'string' },
      'update-baseline': { type: 'boolean', default: false },
      'show-suppressed': { type: 'boolean', default: false },
      write: { type: 'boolean', default: false },
      rule: { type: 'string' },
      'sarif-out': { type: 'string' },
      annotations: { type: 'boolean', default: false },
      url: { type: 'string' },
      'dry-run': { type: 'boolean', default: false },
      correlate: { type: 'boolean', default: false },
      active: { type: 'boolean', default: false },
      'allow-remote': { type: 'boolean', default: false },
      'i-own': { type: 'string' },
      'max-requests': { type: 'string' },
      framework: { type: 'string' },
      out: { type: 'string' },
      history: { type: 'string' },
      record: { type: 'boolean', default: false },
      commit: { type: 'string' },
      cwd: { type: 'string' },
      help: { type: 'boolean', default: false },
    },
  });

  const command = positionals[0];
  if (values.help === true || command === undefined) {
    process.stdout.write(HELP);
    return values.help === true ? EXIT.CLEAN : EXIT.USAGE;
  }

  // Honor an optional positional path (`aegis scan apps/dashboard`); fall back to --cwd, then cwd.
  const cwd = resolveRoot(positionals[1], str(values.cwd), process.cwd());
  const severity = parseSeverity(str(values.severity));
  const strict = values.strict === true;
  const sarifOut = str(values['sarif-out']);
  const url = str(values.url);

  switch (command) {
    case 'scan': {
      const baseline = str(values.baseline);
      return runScan({
        cwd,
        format: parseFormat(str(values.format)),
        severity,
        strict,
        noColor: values['no-color'] === true,
        plain: values.plain === true,
        showSuppressed: values['show-suppressed'] === true,
        updateBaseline: values['update-baseline'] === true,
        ...(baseline !== undefined ? { baseline } : {}),
      });
    }
    case 'fix': {
      const format = parseFormat(str(values.format));
      if (format === 'sarif') {
        throw new UsageError('fix supports --format pretty|json');
      }
      const rule = str(values.rule);
      return runFix({
        cwd,
        write: values.write === true,
        format,
        noColor: values['no-color'] === true,
        plain: values.plain === true,
        ...(rule !== undefined ? { rule } : {}),
      });
    }
    case 'ci':
      return runCi({
        cwd,
        ...(sarifOut !== undefined ? { sarifOut } : {}),
        annotations: values.annotations === true,
        severity,
        strict,
      });
    case 'init':
      return runInit({ cwd, dryRun: values['dry-run'] === true });
    case 'doctor':
      return runDoctor({ cwd, ...(url !== undefined ? { url } : {}) });
    case 'probe': {
      // For `probe`, the positional is the TARGET URL (not a path); cwd comes from --cwd.
      const target = positionals[1] ?? url;
      if (target === undefined) {
        throw new UsageError(
          'probe requires a target URL, e.g. `aegis probe http://localhost:3000`',
        );
      }
      const iOwn = str(values['i-own']);
      const maxRequests = str(values['max-requests']);
      const mode =
        values['dry-run'] === true ? 'dry-run' : values.active === true ? 'active' : 'passive';
      return runProbe({
        cwd: str(values.cwd) ?? process.cwd(),
        url: target,
        format: parseFormat(str(values.format)),
        severity,
        strict,
        noColor: values['no-color'] === true,
        plain: values.plain === true,
        mode,
        correlate: values.correlate === true,
        allowRemote: values['allow-remote'] === true,
        ...(iOwn !== undefined ? { iOwn } : {}),
        ...(maxRequests !== undefined ? { maxRequests: Number(maxRequests) } : {}),
      });
    }
    case 'report': {
      const out = str(values.out);
      const history = str(values.history);
      const commit = str(values.commit);
      return runReport({
        cwd,
        framework: parseFramework(str(values.framework)),
        format: parseReportFormat(str(values.format)),
        record: values.record === true,
        ...(out !== undefined ? { out } : {}),
        ...(history !== undefined ? { history } : {}),
        ...(commit !== undefined ? { commit } : {}),
      });
    }
    case 'diff': {
      const base = str(values.base);
      if (base === undefined) {
        throw new UsageError('diff requires --base <ref>, e.g. `aegis diff --base origin/main`');
      }
      const head = str(values.head);
      return runDiff({
        cwd,
        base,
        format: parseDiffFormat(str(values.format)),
        trust: values.trust ?? [],
        strict,
        ...(head !== undefined ? { head } : {}),
      });
    }
    default:
      process.stderr.write(`aegis: unknown command "${command}"\n\n${HELP}`);
      return EXIT.USAGE;
  }
}

main()
  .then((code) => process.exit(code))
  .catch((error: unknown) => {
    const code = error instanceof UsageError ? EXIT.USAGE : EXIT.INTERNAL;
    process.stderr.write(`aegis: ${error instanceof Error ? error.message : String(error)}\n`);
    process.exit(code);
  });
