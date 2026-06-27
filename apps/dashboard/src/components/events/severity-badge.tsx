import type { SecurityEventType } from '@aegiskit/core';
import { EVENT_SEVERITY } from '@aegiskit/observability';
import { severityToVisual, type Tone } from '@/lib/posture/grade-ui';

const TONE_TEXT: Record<Tone, string> = {
  good: 'text-tone-good',
  ok: 'text-tone-ok',
  warn: 'text-tone-warn',
  bad: 'text-tone-bad',
};

/** Severity = glyph (decorative) + text label + color tone. Never color alone (WCAG 1.4.1). */
export function SeverityBadge({ type }: { type: SecurityEventType }) {
  const visual = severityToVisual(EVENT_SEVERITY[type]);
  return (
    <span
      className={`inline-flex items-center gap-1 text-sm font-medium ${TONE_TEXT[visual.tone]}`}
    >
      <span aria-hidden="true">{visual.glyph}</span>
      <span>{visual.label}</span>
    </span>
  );
}
