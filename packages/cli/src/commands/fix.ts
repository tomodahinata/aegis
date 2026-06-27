import { readFileSync, writeFileSync } from 'node:fs';
import { relative } from 'node:path';
import { type AutoFix, type Finding, planFileFixes, scan } from '@aegiskit/scanner';
import { defaultAliases, discoverFiles } from '../discover';
import { EXIT } from '../exit';
import { colorEnabled } from '../internal/colors';
import {
  buildPlan,
  miniDiff,
  type RemediationItem,
  renderRemediationJson,
  renderRemediationPretty,
  SCAFFOLD_RULE_ID,
} from '../reporters/remediation';
import { type MiddlewareScaffold, planMiddlewareScaffold, writeMiddlewareScaffold } from './init';

export type FixFormat = 'pretty' | 'json';

export interface FixArgs {
  readonly cwd: string;
  /** Apply the auto-fixes. Default (false): preview only. */
  readonly write: boolean;
  readonly format: FixFormat;
  readonly noColor: boolean;
  readonly plain: boolean;
  /** Limit to a single rule id. */
  readonly rule?: string;
}

/**
 * `aegis fix` — preview-first, idempotent remediation. Auto-fixes are applied only with `--write`;
 * everything else is reported as guided steps. The same plan renders as a coding-agent handoff
 * under `--format json`.
 */
export function runFix(args: FixArgs): number {
  const files = discoverFiles(args.cwd);
  const aliases = defaultAliases(args.cwd);
  const result = scan({ files, ...(aliases ? { aliases } : {}), computeFixes: true });
  const findings = result.findings.filter((f) => args.rule === undefined || f.ruleId === args.rule);

  // 1. In-file auto-fixes, composed per file (so multiple fixes in one file resolve together).
  const fixesByFile = new Map<string, AutoFix[]>();
  for (const f of findings) {
    if (f.fix) {
      const list = fixesByFile.get(f.file) ?? [];
      list.push(f.fix);
      fixesByFile.set(f.file, list);
    }
  }
  const newTextByFile = new Map<string, string>();
  const diffByFile = new Map<string, string>();
  for (const [file, fixes] of fixesByFile) {
    const original = readFileSync(file, 'utf8');
    const plan = planFileFixes(file, original, fixes);
    if (plan.newText !== original) {
      newTextByFile.set(file, plan.newText);
      diffByFile.set(file, miniDiff(original, plan.newText).join('\n'));
    }
  }

  // 2. The headers finding's fix is a file creation — reuse the init scaffold.
  const scaffold: MiddlewareScaffold | undefined = findings.some(
    (f) => f.ruleId === SCAFFOLD_RULE_ID,
  )
    ? planMiddlewareScaffold(args.cwd)
    : undefined;
  const canScaffold = scaffold?.status === 'absent';

  // 3. Build the remediation plan (one item per finding).
  const items = findings.map((f) => toItem(f, args.cwd, diffByFile, scaffold, canScaffold));
  const plan = buildPlan(items);

  // 4. Apply, if asked. (No writes happen in preview mode.)
  if (args.write) {
    for (const [file, text] of newTextByFile) {
      writeFileSync(file, text);
    }
    if (scaffold && canScaffold) {
      writeMiddlewareScaffold(scaffold);
    }
  }

  // 5. Render.
  const output =
    args.format === 'json'
      ? renderRemediationJson(plan)
      : renderRemediationPretty(plan, {
          color: colorEnabled(args.noColor),
          plain: args.plain,
          applied: args.write,
        });
  process.stdout.write(output);
  return EXIT.CLEAN;
}

function toItem(
  f: Finding,
  cwd: string,
  diffByFile: ReadonlyMap<string, string>,
  scaffold: MiddlewareScaffold | undefined,
  canScaffold: boolean,
): RemediationItem {
  const base = {
    ruleId: f.ruleId,
    severity: f.severity,
    confidence: f.confidence,
    file: relative(cwd, f.file) || f.file,
    line: f.range.startLine,
    problem: f.message,
    docsUrl: f.docsUrl,
  };

  if (f.fix) {
    const diff = diffByFile.get(f.file);
    return { ...base, mode: 'auto', action: f.fix.title, ...(diff ? { diff } : {}) };
  }
  if (f.ruleId === SCAFFOLD_RULE_ID && scaffold && canScaffold) {
    return {
      ...base,
      mode: 'auto',
      action: `Scaffold ${scaffold.shown} with secure() (creates the file)`,
    };
  }
  return { ...base, mode: 'guided', action: f.remediation };
}
