import type { SecurityEventType } from '@aegiskit/core';
import { LiveRegion } from '@/components/a11y/live-region';
import { EventsTable } from '@/components/events/events-table';
import { SeveritySummary } from '@/components/events/severity-summary';
import { bySeverityThenRecent, resolveSort, SORTS, type Sort } from '@/lib/events/event-sort';
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
  searchParams: Promise<{ type?: string; sort?: string }>;
}) {
  const { type, sort } = await searchParams;
  const selected = TYPES.find((t) => t === type);
  // Validate against the literal union, fail closed to the safe default.
  const activeSort: Sort = resolveSort(sort);
  const now = Date.now();

  const events = await getEventStore().query({
    limit: 200,
    ...(selected ? { type: selected } : {}),
  });

  // Severity sort is highest-first then newest-first; recent is the store's native newest-first order.
  const sorted = activeSort === 'severity' ? [...events].sort(bySeverityThenRecent) : events;

  const sortHref = (next: Sort): string => {
    const params = new URLSearchParams();
    if (selected) {
      params.set('type', selected);
    }
    params.set('sort', next);
    return `?${params.toString()}`;
  };

  const announcement = `Showing ${events.length} event${events.length === 1 ? '' : 's'}${
    selected ? ` · filter: ${selected}` : ''
  } · sorted by ${activeSort}`;

  return (
    <div className="space-y-6">
      <h1 className="font-bold text-2xl">Events</h1>

      <SeveritySummary events={events} />

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
        {/* Preserve the active sort when applying a filter. */}
        <input type="hidden" name="sort" value={activeSort} />
        <button type="submit" className="rounded border border-border bg-card px-3 py-1 text-sm">
          Apply
        </button>
      </form>

      {/* Sort controls as links: keyboard-accessible, server-navigated, no client state. */}
      <nav className="flex items-center gap-3 text-sm" aria-label="Sort events">
        <span className="text-muted">Sort:</span>
        {SORTS.map((option) => (
          <a
            key={option}
            href={sortHref(option)}
            {...(activeSort === option ? { 'aria-current': 'true' as const } : {})}
            className={activeSort === option ? 'font-semibold underline' : 'underline'}
          >
            {option === 'severity' ? 'Severity' : 'Recent'}
          </a>
        ))}
      </nav>

      <LiveRegion key={announcement} message={announcement} />

      <EventsTable
        events={sorted}
        caption={`Security events, sorted by ${activeSort}.`}
        now={now}
        sort={activeSort}
        filtered={selected !== undefined}
      />
    </div>
  );
}
