import { describe, expect, it } from 'vitest';
import { eventBatchSchema } from './envelope';

describe('eventBatchSchema', () => {
  it('accepts well-formed event variants', () => {
    expect(
      eventBatchSchema.safeParse({
        events: [{ type: 'rate_limit_block', id: 'a', at: 1, key: 'k', rule: 'ip', limit: 60 }],
      }).success,
    ).toBe(true);
    expect(
      eventBatchSchema.safeParse({ events: [{ type: 'csrf_block', id: 'b', at: 1, reason: 'x' }] })
        .success,
    ).toBe(true);
  });

  it('rejects a missing id, an unknown type, and over-long fields (memory-DoS guard)', () => {
    expect(
      eventBatchSchema.safeParse({ events: [{ type: 'csrf_block', at: 1, reason: 'x' }] }).success,
    ).toBe(false);
    expect(eventBatchSchema.safeParse({ events: [{ type: 'nope', id: 'a', at: 1 }] }).success).toBe(
      false,
    );
    expect(
      eventBatchSchema.safeParse({
        events: [{ type: 'csrf_block', id: 'a', at: 1, reason: 'x'.repeat(200) }],
      }).success,
    ).toBe(false);
  });

  it('rejects an empty batch', () => {
    expect(eventBatchSchema.safeParse({ events: [] }).success).toBe(false);
  });
});
