import type { Finding, ScanResult, Severity, SourceRange } from '../types';

function sarifLevel(severity: Severity): 'error' | 'warning' | 'note' {
  if (severity === 'BLOCKER' || severity === 'HIGH') {
    return 'error';
  }
  if (severity === 'MEDIUM') {
    return 'warning';
  }
  return 'note';
}

// GitHub code-scanning sorts by this numeric (CVSS-like) score.
function securitySeverity(severity: Severity): string {
  switch (severity) {
    case 'BLOCKER':
      return '9.5';
    case 'HIGH':
      return '8.0';
    case 'MEDIUM':
      return '5.0';
    case 'LOW':
      return '3.0';
    default:
      return '1.0';
  }
}

// Stable across runs and unaffected by unrelated line shifts → GitHub dedupes annotations.
function fingerprint(finding: Finding): string {
  return `${finding.ruleId}::${finding.file}::${finding.evidence ?? finding.range.startLine}`;
}

function toRegion(range: SourceRange) {
  return {
    startLine: range.startLine,
    startColumn: range.startColumn,
    endLine: range.endLine,
    endColumn: range.endColumn,
  };
}

// A taint finding's source→sink path, as SARIF's first-class dataflow. GitHub code-scanning renders
// each step as a clickable location, so a reviewer follows the actual flow rather than a bare line.
function codeFlowsFor(finding: Finding) {
  if (!finding.trace?.length) {
    return undefined;
  }
  return [
    {
      threadFlows: [
        {
          locations: finding.trace.map((stepItem) => ({
            location: {
              physicalLocation: {
                artifactLocation: { uri: finding.file },
                region: toRegion(stepItem.range),
              },
              message: { text: stepItem.label },
            },
          })),
        },
      ],
    },
  ];
}

/** Render a SARIF 2.1.0 document for GitHub code-scanning. */
export function toSarif(result: ScanResult): string {
  const representativeByRule = new Map<string, Finding>();
  for (const finding of result.findings) {
    if (!representativeByRule.has(finding.ruleId)) {
      representativeByRule.set(finding.ruleId, finding);
    }
  }

  const rules = [...representativeByRule.values()].map((finding) => ({
    id: finding.ruleId,
    name: finding.ruleId,
    shortDescription: { text: finding.ruleId },
    helpUri: finding.docsUrl,
    properties: { 'security-severity': securitySeverity(finding.severity) },
  }));

  const results = result.findings.map((finding) => {
    const codeFlows = codeFlowsFor(finding);
    // A dynamic (DAST) finding is located at a URL, not a source line — emit the URI without a region.
    const physicalLocation =
      finding.target !== undefined
        ? { artifactLocation: { uri: finding.file } }
        : { artifactLocation: { uri: finding.file }, region: toRegion(finding.range) };
    return {
      ruleId: finding.ruleId,
      level: sarifLevel(finding.severity),
      message: { text: finding.message },
      locations: [{ physicalLocation }],
      partialFingerprints: { aegisFingerprint: fingerprint(finding) },
      properties: {
        confidence: finding.confidence,
        ...(finding.owasp !== undefined ? { owasp: finding.owasp } : {}),
        ...(finding.target !== undefined
          ? { target: { method: finding.target.method, path: finding.target.path } }
          : {}),
      },
      ...(codeFlows !== undefined ? { codeFlows } : {}),
    };
  });

  const document = {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: { driver: { name: 'aegis', informationUri: 'https://aegis.dev', rules } },
        results,
      },
    ],
  };
  return JSON.stringify(document, null, 2);
}
