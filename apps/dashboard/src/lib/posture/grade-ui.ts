import type { Grade } from '@aegiskit/observability';

export type GradeIcon = 'shield-check' | 'shield' | 'shield-alert' | 'shield-x';
export type Tone = 'good' | 'ok' | 'warn' | 'bad';

/** Tailwind text-color class per tone. One authoritative mapping, reused by every severity surface. */
export const TONE_TEXT_CLASS: Record<Tone, string> = {
  good: 'text-tone-good',
  ok: 'text-tone-ok',
  warn: 'text-tone-warn',
  bad: 'text-tone-bad',
};

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
  /** Sort/display rank, most severe first (high = 0). The single source of truth for severity order. */
  readonly rank: number;
}

/**
 * Severity badge: text label + DISTINCT ASCII glyph + tone (mirrors the CLI — never color alone). Each
 * severity gets its own shape (▲ / ◆ / •) so the three are distinguishable by shape alone, not just hue
 * (WCAG 1.4.1).
 */
export function severityToVisual(severity: EventSeverity): SeverityVisual {
  switch (severity) {
    case 'high':
      return { label: 'High', glyph: '▲', tone: 'bad', rank: 0 };
    case 'medium':
      return { label: 'Medium', glyph: '◆', tone: 'warn', rank: 1 };
    default:
      return { label: 'Low', glyph: '•', tone: 'ok', rank: 2 };
  }
}
