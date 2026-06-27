import { computePostureScore } from '@aegiskit/observability';
import { EventsTable } from '@/components/events/events-table';
import { ScoreCard } from '@/components/posture/score-card';
import { TrendSparkline } from '@/components/posture/trend-sparkline';
import { getEventStore } from '@/lib/store';

export const dynamic = 'force-dynamic';

export default async function OverviewPage() {
  const now = Date.now();
  const store = getEventStore();
  const summary = await store.summary({ since: now - 86_400_000, until: now, bucketCount: 24 });
  const posture = computePostureScore(summary);
  const recent = await store.query({ limit: 10 });

  return (
    <div className="space-y-8">
      <h1 className="font-bold text-2xl">Security posture</h1>
      <div className="grid gap-4 sm:grid-cols-2">
        <ScoreCard posture={posture} />
        <TrendSparkline buckets={summary.buckets} />
      </div>
      <section aria-labelledby="recent-heading" className="space-y-3">
        <h2 id="recent-heading" className="font-semibold text-lg">
          Recent events
        </h2>
        <EventsTable events={recent} caption="The ten most recent security events." now={now} />
      </section>
    </div>
  );
}
