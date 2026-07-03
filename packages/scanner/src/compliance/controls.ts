/**
 * The declarative bridge from Aegis findings to compliance controls — the single
 * source of truth for "which SOC 2 / ISO 27001 control is this a piece of evidence
 * for?". Mapping is keyed by **OWASP Top 10 (2021) category**, not by individual
 * rule id, because that is the axis a control actually speaks to: eleven access-control
 * rules are all evidence for one access-restriction control, and a new rule that reuses
 * an existing category is mapped automatically (DRY — rule of three, honoured once).
 *
 * A unit test (`controls.test.ts`) asserts every registered rule's OWASP category
 * resolves to at least one control in *every* framework, so CI catches a genuinely new
 * category the moment it appears — the only time this table needs a human edit.
 *
 * NON-NEGOTIABLE SCOPE: this is a *reference* mapping of application-layer technical
 * controls, and it requires an auditor's confirmation. It is not a certification, and it
 * does not cover the policy, HR, vendor, physical, or continuous-monitoring controls that
 * a GRC platform (Vanta/Drata) owns. Aegis complements those; it never replaces them.
 */

export type ComplianceFramework = 'soc2' | 'iso27001';

/** The set of frameworks a report can be generated for. */
export const SUPPORTED_FRAMEWORKS: readonly ComplianceFramework[] = ['soc2', 'iso27001'];

/** A single control Aegis can produce technical evidence for. */
export interface ControlDef {
  /** Control identifier within its framework, e.g. `CC6.1` / `A.8.3`. */
  readonly id: string;
  /** Short human-readable control title. */
  readonly title: string;
  /**
   * The OWASP Top 10 (2021) categories whose findings are evidence for this control.
   * A finding in any of these categories marks the control a gap.
   */
  readonly owasp: readonly string[];
}

/**
 * SOC 2 (2017 Trust Services Criteria) Common Criteria controls Aegis's static checks
 * touch. Titles paraphrase the TSC points of focus; confirm exact wording with your auditor.
 */
const SOC2_CONTROLS: readonly ControlDef[] = [
  {
    id: 'CC6.1',
    title: 'Logical access controls over protected information assets',
    owasp: ['A01', 'A05'],
  },
  {
    id: 'CC6.6',
    title: 'Protection against threats from outside the system boundary',
    owasp: ['A04', 'A05', 'A10'],
  },
  {
    id: 'CC6.7',
    title: 'Secure transmission, movement, and removal of information',
    owasp: ['A02'],
  },
  {
    id: 'CC6.8',
    title: 'Prevent or detect unauthorized or malicious software',
    owasp: ['A03', 'A08'],
  },
  {
    id: 'CC7.1',
    title: 'Detect configuration changes and newly introduced vulnerabilities',
    owasp: ['A03', 'A06'],
  },
];

/** ISO/IEC 27001:2022 Annex A controls Aegis's static checks touch. */
const ISO27001_CONTROLS: readonly ControlDef[] = [
  { id: 'A.8.3', title: 'Information access restriction', owasp: ['A01'] },
  { id: 'A.8.6', title: 'Capacity management', owasp: ['A04'] },
  { id: 'A.8.8', title: 'Management of technical vulnerabilities', owasp: ['A06'] },
  { id: 'A.8.9', title: 'Configuration management', owasp: ['A05'] },
  { id: 'A.8.23', title: 'Web filtering', owasp: ['A10'] },
  { id: 'A.8.24', title: 'Use of cryptography', owasp: ['A02'] },
  { id: 'A.8.28', title: 'Secure coding', owasp: ['A03', 'A08'] },
];

const CONTROLS_BY_FRAMEWORK: Record<ComplianceFramework, readonly ControlDef[]> = {
  soc2: SOC2_CONTROLS,
  iso27001: ISO27001_CONTROLS,
};

/** Human-readable framework label for report headers. */
export const FRAMEWORK_LABEL: Record<ComplianceFramework, string> = {
  soc2: 'SOC 2 (2017 Trust Services Criteria)',
  iso27001: 'ISO/IEC 27001:2022 Annex A',
};

/** The controls Aegis can speak to for `framework`, in stable declaration order. */
export function frameworkControls(framework: ComplianceFramework): readonly ControlDef[] {
  return CONTROLS_BY_FRAMEWORK[framework];
}

/**
 * Extract the OWASP Top 10 category (e.g. `A01`) from a rule's or finding's `owasp`
 * string (e.g. `A01:2021 Broken Access Control`). Returns undefined when the value is
 * absent or not an OWASP-2021 category — such a finding maps to no control (fail-safe).
 */
export function owaspCategory(owasp: string | undefined): string | undefined {
  if (owasp === undefined) {
    return undefined;
  }
  return /^(A\d{2})\b/.exec(owasp)?.[1];
}

/** Every OWASP category mapped to at least one control in `framework`. */
export function mappedCategories(framework: ComplianceFramework): ReadonlySet<string> {
  const categories = new Set<string>();
  for (const control of CONTROLS_BY_FRAMEWORK[framework]) {
    for (const category of control.owasp) {
      categories.add(category);
    }
  }
  return categories;
}
