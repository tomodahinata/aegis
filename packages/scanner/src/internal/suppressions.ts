/**
 * Inline suppression directives, so a team can adopt Aegis on a real codebase without a wall
 * of findings:
 *
 *   // aegis-disable-next-line <ruleId> -- <reason>   (suppresses the line below; trailing form suppresses its own line)
 *   // aegis-disable-file <ruleId> -- <reason>        (suppresses the whole file)
 *
 * A reason is MANDATORY: a reasonless directive still suppresses, but the engine surfaces an
 * `aegis/suppression-without-reason` finding so the suppression is never *silent*.
 */

export const SUPPRESSION_WITHOUT_REASON_RULE = 'aegis/suppression-without-reason';

export interface Suppression {
  /** A rule id, or `*` for all rules. */
  readonly ruleId: string;
  readonly scope: 'next-line' | 'file';
  /** `undefined` when no `-- <reason>` was given (itself a finding). */
  readonly reason: string | undefined;
  /** 1-based line the directive comment sits on. */
  readonly directiveLine: number;
}

export interface FileSuppressions {
  readonly fileLevel: readonly Suppression[];
  /** Suppressions keyed by the 1-based line they target. */
  readonly byTargetLine: ReadonlyMap<number, readonly Suppression[]>;
  /** Every directive, for surfacing reasonless ones. */
  readonly all: readonly Suppression[];
}

// Body is the trimmed text after `//`. ruleId is a non-space token; reason follows `-- `.
const DIRECTIVE = /^aegis-disable-(next-line|file)\s+(\S+)(?:\s+--\s+(.*\S))?\s*$/;

const EMPTY: FileSuppressions = { fileLevel: [], byTargetLine: new Map(), all: [] };

export function parseSuppressions(text: string): FileSuppressions {
  if (!text.includes('aegis-disable-')) {
    return EMPTY; // cheap fast-path: most files have none
  }
  const lines = text.split(/\r?\n/);
  const fileLevel: Suppression[] = [];
  const byTargetLine = new Map<number, Suppression[]>();
  const all: Suppression[] = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line === undefined) {
      continue;
    }
    const commentIndex = line.indexOf('//');
    if (commentIndex === -1) {
      continue;
    }
    const match = DIRECTIVE.exec(line.slice(commentIndex + 2).trim());
    if (!match) {
      continue;
    }
    const scope = match[1] === 'file' ? 'file' : 'next-line';
    const ruleId = match[2];
    if (ruleId === undefined) {
      continue;
    }
    const reason = match[3];
    const directiveLine = i + 1;
    const suppression: Suppression = { ruleId, scope, reason, directiveLine };
    all.push(suppression);

    if (scope === 'file') {
      fileLevel.push(suppression);
      continue;
    }
    // A standalone directive targets the next line; a trailing one targets its own line.
    const hasCodeBefore = line.slice(0, commentIndex).trim().length > 0;
    const targetLine = hasCodeBefore ? directiveLine : directiveLine + 1;
    const existing = byTargetLine.get(targetLine);
    if (existing) {
      existing.push(suppression);
    } else {
      byTargetLine.set(targetLine, [suppression]);
    }
  }

  return { fileLevel, byTargetLine, all };
}

function matches(suppression: Suppression, ruleId: string): boolean {
  return suppression.ruleId === '*' || suppression.ruleId === ruleId;
}

/** Is a finding for `ruleId` at `line` suppressed (file-level or line-targeted)? */
export function isSuppressed(
  suppressions: FileSuppressions,
  ruleId: string,
  line: number,
): boolean {
  if (suppressions.fileLevel.some((s) => matches(s, ruleId))) {
    return true;
  }
  return suppressions.byTargetLine.get(line)?.some((s) => matches(s, ruleId)) ?? false;
}
