import { describe, expect, it } from 'vitest';
import type { RemediationSummary } from '../compliance/history';
import { buildComplianceReport } from '../compliance/report';
import type { Finding, ScanResult } from '../types';
import { toComplianceHtml } from './compliance-html';

function resultWith(findings: readonly Finding[]): ScanResult {
  return {
    findings,
    passes: [],
    summary: { BLOCKER: 0, HIGH: findings.length, MEDIUM: 0, LOW: 0, INFO: 0 },
    scannedFiles: 3,
    durationMs: 0,
    suppressedCount: 0,
  };
}

const rlsFinding: Finding = {
  ruleId: 'rls/policy-not-owner-scoped',
  severity: 'HIGH',
  confidence: 'medium',
  // Deliberately hostile characters to prove escaping.
  message: 'Policy on "docs" leaks rows <script>alert(1)</script> & more',
  file: '/repo/supabase/migrations/001.sql',
  range: { startLine: 3, startColumn: 1, endLine: 3, endColumn: 1 },
  docsUrl: 'https://example/docs',
  remediation: 'Scope with auth.uid() = user_id',
  owasp: 'A01:2021 Broken Access Control',
  explanation: {
    kind: 'authenticated-only',
    detail: 'no ownership binding',
    suggestedFix:
      'create policy "docs_select_owner" on public.docs\n  for select to authenticated\n  using (auth.uid() = user_id);',
  },
};

describe('toComplianceHtml', () => {
  const html = toComplianceHtml(buildComplianceReport(resultWith([rlsFinding]), 'soc2'));

  it('is a self-contained document with no external asset references', () => {
    expect(html.startsWith('<!DOCTYPE html>')).toBe(true);
    expect(html).toContain('<html lang="en">');
    // No network fetches from an air-gapped auditor machine: no external URLs in asset positions.
    expect(html).not.toMatch(/<(?:script|link|img)\b[^>]*\b(?:src|href)=/i);
    expect(html).not.toMatch(/https?:\/\/[^"']*\.(?:css|js|woff2?|png|svg)/i);
  });

  it('escapes hostile characters in finding text (no raw <script>)', () => {
    expect(html).not.toContain('<script>alert(1)</script>');
    expect(html).toContain('&lt;script&gt;alert(1)&lt;/script&gt;');
    expect(html).toContain('&amp; more');
  });

  it('carries the exact scope disclaimer and never claims "compliant"/"certified"', () => {
    expect(html).toContain('not a certification');
    expect(html).not.toMatch(/\bcompliant\b/i);
    expect(html).not.toMatch(/\bcertified\b/i);
  });

  it('conveys control status by text label, not colour alone (WCAG)', () => {
    expect(html).toContain('Gap(s) found');
    expect(html).toContain('No gaps detected');
  });

  it('uses accessible table semantics: a caption and scoped headers', () => {
    expect(html).toContain('<caption>');
    expect(html).toContain('scope="col"');
    expect(html).toContain('scope="row"');
  });

  it('surfaces the F1 suggested policy inside the gap detail', () => {
    expect(html).toContain('docs_select_owner');
  });

  it('renders the remediation section only when a summary is supplied', () => {
    expect(html).not.toContain('Remediation tracking');
    const remediation: RemediationSummary = {
      scans: 4,
      totalTracked: 2,
      open: 1,
      resolved: 1,
      meanTimeToRemediateDays: 3,
      oldestOpenAgeDays: 12,
      lifecycles: [
        {
          fingerprint: 'abcdef0123456789',
          firstSeen: '2026-06-01T00:00:00Z',
          lastSeen: '2026-07-01T00:00:00Z',
          status: 'open',
          ageDays: 12,
        },
        {
          fingerprint: 'fedcba9876543210',
          firstSeen: '2026-06-01T00:00:00Z',
          lastSeen: '2026-06-02T00:00:00Z',
          resolvedAt: '2026-06-04T00:00:00Z',
          status: 'resolved',
          ageDays: 3,
        },
      ],
    };
    const withRemediation = toComplianceHtml(
      buildComplianceReport(resultWith([rlsFinding]), 'soc2'),
      remediation,
    );
    expect(withRemediation).toContain('Remediation tracking');
    expect(withRemediation).toContain('mean time to remediate');
    expect(withRemediation).toContain('abcdef012345'); // fingerprint truncated to 12 chars
    // Assert the load-bearing COMPUTED values render, not just the section chrome.
    expect(withRemediation).toContain('3 days'); // MTTR, correctly pluralized
    expect(withRemediation).toContain('12 days'); // oldest open
    expect(withRemediation).toContain('2026-06-04T00:00:00Z'); // resolvedAt cell rendered
    expect(withRemediation).toContain('>open<'); // status by text label (WCAG), not colour alone
    expect(withRemediation).toContain('>resolved<');
  });
});
