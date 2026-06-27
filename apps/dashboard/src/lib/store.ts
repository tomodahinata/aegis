import { createMemoryEventStore, type EventStore } from '@aegiskit/observability';

// In-memory by default (zero infra). Swap for `@aegiskit/store-supabase`'s `createSupabaseEventStore`
// behind an env flag for production persistence.
let store: EventStore | undefined;

export function getEventStore(): EventStore {
  store ??= createMemoryEventStore({ capacity: 10_000 });
  return store;
}
