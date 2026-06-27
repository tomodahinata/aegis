import type { StoredEvent } from '@aegiskit/observability';
import { relativeTime } from '@/lib/format';
import { SeverityBadge } from './severity-badge';

export type EventsSort = 'recent' | 'severity';

export function EventsTable({
  events,
  caption,
  now,
  sort,
  filtered = false,
}: {
  events: readonly StoredEvent[];
  caption: string;
  now: number;
  /** Active sort, used to mark the sorted column with `aria-sort` (WCAG 4.1.2). */
  sort: EventsSort;
  /** Whether a type filter is active — distinguishes "none match" from "no events at all". */
  filtered?: boolean;
}) {
  if (events.length === 0) {
    return (
      <p className="text-muted text-sm">
        {filtered
          ? 'No events match this filter.'
          : 'No events yet — your app is quiet (or not yet wired to ship events).'}
      </p>
    );
  }
  return (
    <table className="w-full border-collapse text-sm">
      <caption className="sr-only">{caption}</caption>
      <thead>
        <tr className="border-border border-b text-left text-muted">
          <th
            scope="col"
            className="py-2 pr-4 font-medium"
            {...(sort === 'severity' ? { 'aria-sort': 'descending' as const } : {})}
          >
            Severity
          </th>
          <th scope="col" className="py-2 pr-4 font-medium">
            Type
          </th>
          <th scope="col" className="py-2 pr-4 font-medium">
            Path
          </th>
          <th scope="col" className="py-2 pr-4 font-medium">
            IP
          </th>
          <th
            scope="col"
            className="py-2 font-medium"
            {...(sort === 'recent' ? { 'aria-sort': 'descending' as const } : {})}
          >
            When
          </th>
        </tr>
      </thead>
      <tbody>
        {events.map((event) => (
          <tr key={event.id} className="border-border/60 border-b">
            {/* Row header: gives screen-reader users row context for the cells that follow (1.3.1). */}
            <th scope="row" className="py-2 pr-4 font-normal">
              <SeverityBadge type={event.type} />
            </th>
            <td className="py-2 pr-4 font-mono text-xs">{event.type}</td>
            <td className="py-2 pr-4">{event.path ?? '—'}</td>
            <td className="py-2 pr-4 font-mono text-xs">{event.ip ?? '—'}</td>
            <td className="py-2 text-muted">{relativeTime(event.receivedAt, now)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
