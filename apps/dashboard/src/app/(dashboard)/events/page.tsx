import type { SecurityEventType } from '@aegiskit/core';
import { EventsTable } from '@/components/events/events-table';
import { getEventStore } from '@/lib/store';

export const dynamic = 'force-dynamic';

const TYPES: readonly SecurityEventType[] = [
  'rate_limit_block',
  'csrf_block',
  'origin_block',
  'csp_violation',
  'validation_error',
  'suspicious_request',
];

export default async function EventsPage({
  searchParams,
}: {
  searchParams: Promise<{ type?: string }>;
}) {
  const { type } = await searchParams;
  const selected = TYPES.find((t) => t === type);
  const now = Date.now();
  const events = await getEventStore().query({
    limit: 200,
    ...(selected ? { type: selected } : {}),
  });

  return (
    <div className="space-y-6">
      <h1 className="font-bold text-2xl">Events</h1>
      {/* GET form: server-navigated, works without JS, fully keyboard-accessible. */}
      <form method="get" className="flex flex-wrap items-center gap-2">
        <label htmlFor="type" className="text-muted text-sm">
          Filter by type
        </label>
        <select
          id="type"
          name="type"
          defaultValue={selected ?? ''}
          className="rounded border border-border bg-card px-2 py-1 text-sm"
        >
          <option value="">All types</option>
          {TYPES.map((t) => (
            <option key={t} value={t}>
              {t}
            </option>
          ))}
        </select>
        <button type="submit" className="rounded border border-border bg-card px-3 py-1 text-sm">
          Apply
        </button>
      </form>
      <EventsTable events={events} caption="Security events, newest first." now={now} />
    </div>
  );
}
