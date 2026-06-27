import { EVENT_SEVERITY, type StoredEvent } from '@aegiskit/observability';
import { type EventSeverity, severityToVisual, TONE_TEXT_CLASS } from '@/lib/posture/grade-ui';

const ORDER: readonly EventSeverity[] = ['high', 'medium', 'low'];

/**
 * A scannable, at-a-glance severity breakdown (High N · Medium N · Low N) using the same chip vocabulary
 * as the table — finally surfacing the per-severity counts. Each entry pairs a distinct glyph + label
 * with its tone, so the breakdown is legible without color (WCAG 1.4.1).
 */
export function SeveritySummary({ events }: { events: readonly StoredEvent[] }) {
  const counts: Record<EventSeverity, number> = { high: 0, medium: 0, low: 0 };
  for (const event of events) {
    counts[EVENT_SEVERITY[event.type]] += 1;
  }
  return (
    <div className="flex flex-wrap items-center gap-4 text-sm">
      {ORDER.map((severity) => {
        const visual = severityToVisual(severity);
        return (
          <span
            key={severity}
            className={`inline-flex items-center gap-1 ${TONE_TEXT_CLASS[visual.tone]}`}
          >
            <span aria-hidden="true">{visual.glyph}</span>
            <span>
              {visual.label} {counts[severity]}
            </span>
          </span>
        );
      })}
      <span className="text-muted">{events.length} total</span>
    </div>
  );
}
