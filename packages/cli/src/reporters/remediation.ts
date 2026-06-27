import type { Severity } from '@aegiskit/scanner';
import { palette } from '../internal/colors';

/** The rule whose fix is "create a `secure()` middleware" (a file-creation, not an in-file edit). */
export const SCAFFOLD_RULE_ID = 'headers/missing-security-headers';

/** `auto` = Aegis can apply it safely; `guided` = needs human judgement (precise steps given). */
export type FixMode = 'auto' | 'guided';

export interface RemediationItem {
  readonly ruleId: string;
  readonly severity: Severity;
  readonly confidence: string;
  /** Path relative to cwd. */
  readonly file: string;
  readonly line: number;
  readonly problem: string;
  readonly mode: FixMode;
  /** What applying the fix does (auto), or the manual remediation (guided). */
  readonly action: string;
  readonly docsUrl: string;
  /** Unified-ish diff for an auto in-file fix; absent for guided items and scaffolds. */
  readonly diff?: string;
}

export interface RemediationPlan {
  readonly items: readonly RemediationItem[];
  readonly auto: number;
  readonly guided: number;
}

export function buildPlan(items: readonly RemediationItem[]): RemediationPlan {
  return {
    items,
    auto: items.filter((i) => i.mode === 'auto').length,
    guided: items.filter((i) => i.mode === 'guided').length,
  };
}

/**
 * A compact single-hunk line diff (one line of context each side). Adequate for the small,
 * localized files Aegis rewrites; intentionally not a full multi-hunk differ (YAGNI).
 */
export function miniDiff(before: string, after: string): string[] {
  const a = before.split('\n');
  const b = after.split('\n');
  let p = 0;
  while (p < a.length && p < b.length && a[p] === b[p]) {
    p += 1;
  }
  let ea = a.length;
  let eb = b.length;
  while (ea > p && eb > p && a[ea - 1] === b[eb - 1]) {
    ea -= 1;
    eb -= 1;
  }
  const out: string[] = [];
  if (p > 0) {
    out.push(` ${a[p - 1] ?? ''}`);
  }
  for (let i = p; i < ea; i += 1) {
    out.push(`-${a[i] ?? ''}`);
  }
  for (let i = p; i < eb; i += 1) {
    out.push(`+${b[i] ?? ''}`);
  }
  if (ea < a.length) {
    out.push(` ${a[ea] ?? ''}`);
  }
  return out;
}

export interface RenderRemediationOptions {
  readonly color: boolean;
  /** Screen-reader-friendly: label-prefixed fields, no glyphs. */
  readonly plain: boolean;
  /** True for `--write` (past tense: "applied"); false for a preview. */
  readonly applied: boolean;
}

// Mode is conveyed by a TEXT label AND a glyph — never color alone (a11y, mirrors the scan report).
const MODE_GLYPH: Record<FixMode, string> = { auto: '✎', guided: '◆' };

export function renderRemediationPretty(
  plan: RemediationPlan,
  options: RenderRemediationOptions,
): string {
  const c = palette(options.color);
  const lines: string[] = [];

  if (plan.items.length === 0) {
    return `${c.green('✓ Nothing to remediate.')}\n`;
  }

  for (const item of plan.items) {
    const loc = `${item.file}:${item.line}`;
    if (options.plain) {
      lines.push(
        `Mode: ${item.mode.toUpperCase()} | Rule: ${item.ruleId} | Severity: ${item.severity}`,
      );
      lines.push(`File: ${loc}`);
      lines.push(`Problem: ${item.problem}`);
      lines.push(`${options.applied ? 'Applied' : 'Action'}: ${item.action}`);
      if (item.diff) {
        for (const dl of item.diff.split('\n')) {
          lines.push(`  ${dl}`);
        }
      }
      lines.push(`Docs: ${item.docsUrl}`);
      lines.push('');
      continue;
    }

    const label = item.mode === 'auto' ? c.green : c.cyan;
    lines.push(
      `${label(`${item.mode.toUpperCase()} ${MODE_GLYPH[item.mode]}`)} ${c.bold(item.ruleId)} ${c.dim(`[${item.severity}]`)}`,
    );
    lines.push(`  ${c.dim(loc)}`);
    lines.push(`  ${item.problem}`);
    lines.push(`  ${c.cyan(options.applied ? '✓ Applied:' : '→ Fix:')} ${item.action}`);
    if (item.diff) {
      for (const dl of item.diff.split('\n')) {
        const colored = dl.startsWith('+')
          ? c.green(dl)
          : dl.startsWith('-')
            ? c.red(dl)
            : c.dim(dl);
        lines.push(`    ${colored}`);
      }
    }
    lines.push('');
  }

  const verb = options.applied ? 'Applied' : 'Remediation';
  lines.push(
    `${c.bold(verb)}  ${c.green(`AUTO ${plan.auto}`)}  ${c.cyan(`GUIDED ${plan.guided}`)}   ${c.dim(`(${plan.items.length} findings)`)}`,
  );
  if (!options.applied && plan.auto > 0) {
    lines.push(c.dim('Run `aegis fix --write` to apply the AUTO fixes (review with `git diff`).'));
  }
  return `${lines.join('\n')}\n`;
}

/** The machine-readable remediation plan — the handoff for a coding agent. */
export function renderRemediationJson(plan: RemediationPlan): string {
  return `${JSON.stringify(
    {
      summary: { auto: plan.auto, guided: plan.guided, total: plan.items.length },
      items: plan.items,
    },
    null,
    2,
  )}\n`;
}
