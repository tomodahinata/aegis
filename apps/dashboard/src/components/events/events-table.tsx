import type { StoredEvent } from '@aegiskit/observability';
import { relativeTime } from '@/lib/format';
import { SeverityBadge } from './severity-badge';

export function EventsTable({
  events,
  caption,
  now,
}: {
  events: readonly StoredEvent[];
  caption: string;
  now: number;
}) {
  if (events.length === 0) {
    return (
      <p className="text-muted text-sm">
        No events yet — your app is quiet (or not yet wired to ship events).
      </p>
    );
  }
  return (
    <table className="w-full border-collapse text-sm">
      <caption className="sr-only">{caption}</caption>
      <thead>
        <tr className="border-border border-b text-left text-muted">
          <th scope="col" className="py-2 pr-4 font-medium">
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
          <th scope="col" className="py-2 font-medium">
            When
          </th>
        </tr>
      </thead>
      <tbody>
        {events.map((event) => (
          <tr key={event.id} className="border-border/60 border-b">
            <td className="py-2 pr-4">
              <SeverityBadge type={event.type} />
            </td>
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
