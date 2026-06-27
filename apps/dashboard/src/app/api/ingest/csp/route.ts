import { createCspReportHandler } from '@aegiskit/next';
import type { StoredEvent } from '@aegiskit/observability';
import { getEventStore } from '@/lib/store';

// Unsigned by design (browsers POST CSP reports); createCspReportHandler bounds + validates them.
export const POST = createCspReportHandler({
  sink: {
    emit: (event) => {
      const stored = { ...event, id: crypto.randomUUID(), receivedAt: Date.now() } as StoredEvent;
      void getEventStore().append([stored]);
    },
  },
});
