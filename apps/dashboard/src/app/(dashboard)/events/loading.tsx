/** Streaming fallback while events load. `aria-busy` tells assistive tech the region is updating. */
export default function Loading() {
  return (
    <div className="space-y-4" role="status" aria-busy="true" aria-label="Loading events">
      <div className="h-8 w-32 animate-pulse rounded bg-card" />
      <div className="h-6 w-64 animate-pulse rounded bg-card" />
      <div className="h-40 w-full animate-pulse rounded bg-card" />
    </div>
  );
}
