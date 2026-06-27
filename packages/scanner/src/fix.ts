import type { AutoFix, TextEdit } from './types';

/**
 * Apply text edits to `text`. Edits are `[start, end)` offsets into the ORIGINAL text; applying
 * back-to-front keeps every offset valid. Overlapping edits throw — a fixer bug must surface loudly,
 * never silently corrupt a user's file.
 */
export function applyTextEdits(text: string, edits: readonly TextEdit[]): string {
  const sorted = [...edits].sort((a, b) => b.start - a.start || b.end - a.end);
  for (let i = 0; i < sorted.length - 1; i += 1) {
    const cur = sorted[i];
    const next = sorted[i + 1];
    if (cur && next && next.end > cur.start) {
      throw new Error(
        `overlapping text edits: [${next.start},${next.end}) and [${cur.start},${cur.end})`,
      );
    }
  }
  let out = text;
  for (const edit of sorted) {
    out = out.slice(0, edit.start) + edit.newText + out.slice(edit.end);
  }
  return out;
}

export interface FilePlan {
  readonly file: string;
  readonly originalText: string;
  readonly newText: string;
  /** Fixes whose edits were applied. */
  readonly applied: readonly AutoFix[];
  /** Fixes skipped because their edits overlapped an already-accepted fix; a re-run resolves them. */
  readonly deferred: readonly AutoFix[];
}

/**
 * Compose all of a file's auto-fixes into one new text, greedily dropping any fix that would
 * overlap an already-accepted one (deferred to a re-run rather than mis-applied). Pure: the caller
 * owns reading and writing the file.
 */
export function planFileFixes(
  file: string,
  originalText: string,
  fixes: readonly AutoFix[],
): FilePlan {
  const accepted: TextEdit[] = [];
  const applied: AutoFix[] = [];
  const deferred: AutoFix[] = [];

  for (const fix of fixes) {
    const conflicts = fix.edits.some((edit) => accepted.some((a) => overlaps(edit, a)));
    if (conflicts) {
      deferred.push(fix);
      continue;
    }
    accepted.push(...fix.edits);
    applied.push(fix);
  }

  const newText = accepted.length > 0 ? applyTextEdits(originalText, accepted) : originalText;
  return { file, originalText, newText, applied, deferred };
}

/** Interval overlap, treating two pure insertions at the same point as non-conflicting. */
function overlaps(a: TextEdit, b: TextEdit): boolean {
  if (a.start === a.end && b.start === b.end) {
    return false;
  }
  return a.start < b.end && b.start < a.end;
}
