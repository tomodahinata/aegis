/**
 * A file the scanner could not read or parse, surfaced as a LOW finding rather than swallowed.
 *
 * Fail secure: a single unreadable/unparseable file must never abort the whole scan and silently
 * drop every other file's findings (that would be a coverage gap with no signal — fail OPEN). The
 * engine isolates each file and, on failure, emits this finding so the gap is always visible.
 */

import { docsUrlFor } from '../rule';
import type { Finding } from '../types';

export const ANALYSIS_ERROR_RULE = 'scan/analysis-error';

/** Build the LOW "could not analyze" finding for a file the scanner had to skip. */
export function analysisErrorFinding(file: string, error: unknown): Finding {
  const reason = error instanceof Error ? error.message : String(error);
  return {
    ruleId: ANALYSIS_ERROR_RULE,
    severity: 'LOW',
    confidence: 'high',
    message: `Could not analyze "${file}" (${reason}); the file was skipped, so any issues in it are not reported.`,
    file,
    range: { startLine: 1, startColumn: 1, endLine: 1, endColumn: 1 },
    docsUrl: docsUrlFor(ANALYSIS_ERROR_RULE),
    remediation:
      'Ensure the file is readable UTF-8 text reachable by the scanner (check symlinks/permissions), then re-run.',
  };
}

/**
 * The LOW finding for a single rule that threw on a file. Unlike a parse failure, only THIS rule's
 * analysis of this file is lost — every other rule and file is unaffected — so the message says so.
 * Fail secure: a rule throwing on an unusual AST must surface here, never abort the whole scan and
 * silently drop every finding (fail open).
 */
export function ruleErrorFinding(file: string, ruleId: string, error: unknown): Finding {
  const reason = error instanceof Error ? error.message : String(error);
  return {
    ruleId: ANALYSIS_ERROR_RULE,
    severity: 'LOW',
    confidence: 'high',
    message: `Rule "${ruleId}" failed on "${file}" (${reason}); that rule was skipped for this file, so issues it would catch here are not reported.`,
    file,
    range: { startLine: 1, startColumn: 1, endLine: 1, endColumn: 1 },
    docsUrl: docsUrlFor(ANALYSIS_ERROR_RULE),
    remediation:
      'This is most likely a scanner bug on an unusual code shape — please report it with the triggering file. Other rules and files were unaffected.',
  };
}
