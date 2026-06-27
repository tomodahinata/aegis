'use client';

/** Route error boundary — `role="alert"` so screen readers announce the failure; offers a retry. */
export default function EventsError({ reset }: { error: Error; reset: () => void }) {
  return (
    <div role="alert" className="space-y-3">
      <h1 className="font-bold text-2xl">Events</h1>
      <p className="text-tone-bad">Something went wrong loading events.</p>
      <button
        type="button"
        onClick={reset}
        className="rounded bg-primary px-3 py-2 font-medium text-primary-foreground"
      >
        Try again
      </button>
    </div>
  );
}
