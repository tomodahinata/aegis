import { describe, expect, it } from 'vitest';
import { resolveScopePolicy, ScopeError } from './consent';

describe('resolveScopePolicy', () => {
  it('allows a loopback origin with no consent', () => {
    const policy = resolveScopePolicy('http://localhost:3000', undefined);
    expect(policy.remoteConsented).toBe(false);
    expect(policy.originHost).toBe('localhost');
  });

  it('throws for a remote origin without --allow-remote', () => {
    expect(() => resolveScopePolicy('https://acme.com', { allowRemote: false })).toThrow(
      ScopeError,
    );
  });

  it('throws for a remote origin with --allow-remote but no attestation', () => {
    expect(() => resolveScopePolicy('https://acme.com', { allowRemote: true })).toThrow(ScopeError);
  });

  it('throws when the attestation origin does not match the target', () => {
    expect(() =>
      resolveScopePolicy('https://acme.com', {
        allowRemote: true,
        ack: { origin: 'https://other.com', statement: 'I own other' },
      }),
    ).toThrow(/must match/);
  });

  it('succeeds when allowRemote AND a matching attestation are present', () => {
    const policy = resolveScopePolicy('https://acme.com', {
      allowRemote: true,
      ack: { origin: 'https://acme.com', statement: 'I own acme.com' },
    });
    expect(policy.remoteConsented).toBe(true);
  });

  it('rejects a link-local origin outright', () => {
    expect(() =>
      resolveScopePolicy('http://169.254.169.254', {
        allowRemote: true,
        ack: { origin: 'http://169.254.169.254', statement: 'x' },
      }),
    ).toThrow(ScopeError);
  });
});
