import { describe, expect, it, vi } from 'vitest';
import {
  createConsoleSink,
  createMultiSink,
  createNoopSink,
  cspReportSchema,
  type SecurityEvent,
  type SecuritySink,
  safeEmit,
} from './events';

const sampleEvent: SecurityEvent = {
  type: 'rate_limit_block',
  at: 1_700_000_000_000,
  ip: '203.0.113.7',
  path: '/api/ai',
  key: 'user:1',
  rule: 'ai',
  limit: 20,
};

describe('createConsoleSink', () => {
  it('writes one structured JSON line per event', () => {
    const lines: string[] = [];
    const sink = createConsoleSink({ write: (line) => lines.push(line) });
    sink.emit(sampleEvent);
    expect(lines).toHaveLength(1);
    const parsed = JSON.parse(lines[0] ?? '{}');
    expect(parsed.source).toBe('aegis');
    expect(parsed.type).toBe('rate_limit_block');
    expect(parsed.rule).toBe('ai');
  });
});

describe('createMultiSink', () => {
  it('fans out to every sink', async () => {
    const a = vi.fn();
    const b = vi.fn();
    const sink = createMultiSink({ emit: a }, { emit: b });
    await sink.emit(sampleEvent);
    expect(a).toHaveBeenCalledWith(sampleEvent);
    expect(b).toHaveBeenCalledWith(sampleEvent);
  });

  it('a throwing sink does not stop the others', async () => {
    const good = vi.fn();
    const bad: SecuritySink = {
      emit() {
        throw new Error('sink exploded');
      },
    };
    const sink = createMultiSink(bad, { emit: good });
    await expect(sink.emit(sampleEvent)).resolves.toBeUndefined();
    expect(good).toHaveBeenCalledOnce();
  });
});

describe('safeEmit', () => {
  it('never throws, even with a throwing sink', () => {
    const throwing: SecuritySink = {
      emit() {
        throw new Error('boom');
      },
    };
    expect(() => safeEmit(throwing, sampleEvent)).not.toThrow();
  });

  it('swallows async rejections', () => {
    const rejecting: SecuritySink = { emit: () => Promise.reject(new Error('async boom')) };
    expect(() => safeEmit(rejecting, sampleEvent)).not.toThrow();
  });
});

describe('createNoopSink', () => {
  it('discards events without error', () => {
    expect(() => createNoopSink().emit(sampleEvent)).not.toThrow();
  });
});

describe('cspReportSchema', () => {
  it('normalizes a legacy report-uri body', () => {
    const result = cspReportSchema.safeParse({
      'csp-report': {
        'effective-directive': 'script-src',
        'blocked-uri': 'https://evil.example/x.js',
        'document-uri': 'https://app.example.com/',
      },
    });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.directive).toBe('script-src');
      expect(result.data.blockedUri).toBe('https://evil.example/x.js');
    }
  });

  it('rejects a malformed body (untrusted input is never trusted)', () => {
    expect(cspReportSchema.safeParse({ nope: true }).success).toBe(false);
    expect(cspReportSchema.safeParse('not-an-object').success).toBe(false);
  });
});
