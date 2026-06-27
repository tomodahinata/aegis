import { getEventStore } from '@/lib/store';

export const dynamic = 'force-dynamic';

export default async function CspPage() {
  const events = await getEventStore().query({ type: 'csp_violation', limit: 200 });
  const groups = new Map<string, Map<string, number>>();
  for (const event of events) {
    if (event.type !== 'csp_violation') {
      continue;
    }
    const uris = groups.get(event.directive) ?? new Map<string, number>();
    uris.set(event.blockedUri, (uris.get(event.blockedUri) ?? 0) + 1);
    groups.set(event.directive, uris);
  }

  return (
    <div className="space-y-6">
      <h1 className="font-bold text-2xl">CSP violations</h1>
      {groups.size === 0 ? (
        <p className="text-muted text-sm">No CSP violations reported.</p>
      ) : (
        <ul className="space-y-4">
          {[...groups.entries()].map(([directive, uris]) => (
            <li key={directive} className="rounded-lg border border-border bg-card p-4">
              <h2 className="font-mono font-semibold text-sm">{directive}</h2>
              <ul className="mt-2 space-y-1 text-muted text-sm">
                {[...uris.entries()].map(([uri, count]) => (
                  <li key={uri}>
                    <span className="tabular-nums">{count}×</span> {uri}
                  </li>
                ))}
              </ul>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
