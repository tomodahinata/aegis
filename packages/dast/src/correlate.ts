/**
 * The headline feature: cross-check static suspicion against runtime proof. When the scanner flagged a
 * *possible* injection on `app/api/x/route.ts` and a high-confidence dynamic probe reproduced it on
 * `/api/x`, the static finding becomes **confirmed exploitable** — its confidence is raised to `high`
 * (so it now fails the build) and the runtime HTTP exchange is attached as evidence.
 */

import type { Finding, ScanResult } from '@aegiskit/scanner';
import type { DynamicFinding } from './probes/types';
import { toFinding } from './report';
import { deriveRoutePath } from './targets/route-path';

// Equivalence between a static rule family and a dynamic probe (the same vulnerability class).
const VULN_CLASSES: ReadonlyArray<readonly [staticRule: RegExp, dynamicProbe: RegExp]> = [
  [/^injection\/sql$/, /^dast\/sql-injection$/],
  [/^ssrf\//, /^dast\/ssrf$/],
  [/^redirect\//, /^dast\/open-redirect$/],
  [/^xss\//, /^dast\/reflected-xss$/],
  [/^headers\//, /^dast\/security-headers$/],
  [/^ratelimit\//, /^dast\/missing-rate-limit$/],
  [/^authz\//, /^dast\/(?:auth-required|idor)$/],
];

/** The vulnerability-class index a ruleId/probeId belongs to, or -1 if none. */
function vulnClass(ruleId: string): number {
  return VULN_CLASSES.findIndex(
    ([staticRule, dynamicProbe]) => staticRule.test(ruleId) || dynamicProbe.test(ruleId),
  );
}

export interface Correlation {
  readonly routePath: string;
  readonly staticRuleId: string;
  readonly dynamicProbeId: string;
}

export interface CorrelatedResult {
  /** Unified list ready for any reporter: static findings (some confirmed) + standalone dynamic findings. */
  readonly findings: readonly Finding[];
  readonly correlations: readonly Correlation[];
}

/**
 * Merge a prior static `ScanResult` with the dynamic findings from a probe run. High-confidence dynamic
 * findings confirm matching static findings (by route path + vuln class); both views are kept so the
 * file-located and URL-located findings remain navigable.
 */
export function correlate(
  staticResult: ScanResult | undefined,
  dynamic: readonly DynamicFinding[],
  origin: string,
): CorrelatedResult {
  const dynamicFindings = dynamic.map((finding) => toFinding(finding, origin));
  if (!staticResult || staticResult.findings.length === 0) {
    return { findings: dynamicFindings, correlations: [] };
  }

  const confirmedByKey = new Map<string, DynamicFinding>();
  for (const finding of dynamic) {
    if (finding.confidence !== 'high') {
      continue;
    }
    const cls = vulnClass(finding.probeId);
    if (cls >= 0) {
      confirmedByKey.set(`${finding.routePath}::${cls}`, finding);
    }
  }

  const correlations: Correlation[] = [];
  const staticFindings = staticResult.findings.map((finding): Finding => {
    const routePath = deriveRoutePath(finding.file);
    const cls = vulnClass(finding.ruleId);
    if (routePath === undefined || cls < 0) {
      return finding;
    }
    const confirmation = confirmedByKey.get(`${routePath}::${cls}`);
    if (!confirmation) {
      return finding;
    }
    correlations.push({
      routePath,
      staticRuleId: finding.ruleId,
      dynamicProbeId: confirmation.probeId,
    });
    return {
      ...finding,
      confidence: 'high',
      message: `Confirmed exploitable at runtime — ${finding.message}`,
      target: confirmation.target,
    };
  });

  return { findings: [...staticFindings, ...dynamicFindings], correlations };
}
