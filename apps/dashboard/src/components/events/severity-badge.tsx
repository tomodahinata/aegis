import type { SecurityEventType } from '@aegiskit/core';
import { EVENT_SEVERITY } from '@aegiskit/observability';
import { severityToVisual, TONE_TEXT_CLASS } from '@/lib/posture/grade-ui';

/**
 * Severity = a bordered chip carrying a distinct glyph (shape) + text label + color tone. The shape and
 * label make it readable without color (WCAG 1.4.1); the border gives a shape boundary independent of
 * hue. The glyph is `aria-hidden` (decorative); the text label is the accessible content.
 */
export function SeverityBadge({ type }: { type: SecurityEventType }) {
  const visual = severityToVisual(EVENT_SEVERITY[type]);
  return (
    <span
      className={`inline-flex items-center gap-1 rounded border border-current/40 px-1.5 py-0.5 text-xs font-medium ${TONE_TEXT_CLASS[visual.tone]}`}
    >
      <span aria-hidden="true">{visual.glyph}</span>
      <span>{visual.label}</span>
    </span>
  );
}
