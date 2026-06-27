import { type EventStore, type StoredEvent, verifyBatchSignature } from '@aegiskit/observability';
import { eventBatchSchema } from './envelope';

export interface IngestInput {
  readonly rawBody: string;
  readonly timestamp: string | null;
  readonly signature: string | null;
  readonly secret: string;
  readonly store: EventStore;
  readonly now?: () => number;
}

export interface IngestResult {
  readonly status: number;
  readonly accepted: number;
}

/**
 * The core of `POST /api/ingest/events`, extracted for testing. Verifies the HMAC over the RAW
 * bytes (never a re-serialized object), validates the bounded envelope, then appends. Returns a
 * status only — never reflects input. 401 (bad/missing/stale sig) · 400 (malformed) · 204 (ok).
 */
export async function ingestEvents(input: IngestInput): Promise<IngestResult> {
  if (!input.signature || !input.timestamp) {
    return { status: 401, accepted: 0 };
  }
  const verified = await verifyBatchSignature(
    input.secret,
    input.rawBody,
    input.timestamp,
    input.signature,
    input.now ? { now: input.now } : {},
  );
  if (!verified) {
    return { status: 401, accepted: 0 };
  }

  let json: unknown;
  try {
    json = JSON.parse(input.rawBody);
  } catch {
    return { status: 400, accepted: 0 };
  }
  const parsed = eventBatchSchema.safeParse(json);
  if (!parsed.success) {
    return { status: 400, accepted: 0 };
  }

  const receivedAt = (input.now ?? Date.now)();
  const stored = parsed.data.events.map((event) => ({ ...event, receivedAt }) as StoredEvent);
  await input.store.append(stored);
  return { status: 204, accepted: stored.length };
}
