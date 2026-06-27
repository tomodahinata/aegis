'use client';

import { useEffect } from 'react';

/** Route error boundary — `role="alert"` so screen readers announce the failure; offers a retry. */
export default function EventsError({ error, reset }: { error: Error; reset: () => void }) {
  // A failed event load means the operator's security feed is down — surface it to telemetry rather
  // than swallowing it. The user-facing copy stays generic; only the logged side carries detail.
  useEffect(() => {
    console.error('events route failed to render', error);
  }, [error]);

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
