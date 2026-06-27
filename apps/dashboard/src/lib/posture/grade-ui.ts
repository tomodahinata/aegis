import type { Grade } from '@aegiskit/observability';

export type GradeIcon = 'shield-check' | 'shield' | 'shield-alert' | 'shield-x';
export type Tone = 'good' | 'ok' | 'warn' | 'bad';

/**
 * Map a posture grade to a visual. Meaning is carried by `label` + `icon`, NEVER color alone
 * (WCAG 1.4.1) — `tone` only chooses a color *in addition* to the always-present label + icon.
 */
export interface GradeVisual {
  readonly label: string;
  readonly icon: GradeIcon;
  readonly tone: Tone;
}

export function gradeToVisual(grade: Grade): GradeVisual {
  switch (grade) {
    case 'A':
      return { label: 'Strong', icon: 'shield-check', tone: 'good' };
    case 'B':
      return { label: 'Good', icon: 'shield', tone: 'ok' };
    case 'C':
      return { label: 'Fair', icon: 'shield-alert', tone: 'warn' };
    case 'D':
      return { label: 'Weak', icon: 'shield-alert', tone: 'warn' };
    default:
      return { label: 'At risk', icon: 'shield-x', tone: 'bad' };
  }
}

export type EventSeverity = 'low' | 'medium' | 'high';

export interface SeverityVisual {
  readonly label: string;
  readonly glyph: string;
  readonly tone: Tone;
}

/** Severity badge: text label + ASCII glyph + tone (mirrors the CLI — never color alone). */
export function severityToVisual(severity: EventSeverity): SeverityVisual {
  switch (severity) {
    case 'high':
      return { label: 'High', glyph: '▲', tone: 'bad' };
    case 'medium':
      return { label: 'Medium', glyph: '▲', tone: 'warn' };
    default:
      return { label: 'Low', glyph: '•', tone: 'ok' };
  }
}
