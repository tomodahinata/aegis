import { describe, expect, it } from 'vitest';
import { scan } from '../engine';

const RULE = 'dom/postmessage-origin-missing';
const P = '/src/widget.ts';
const has = (src: string): boolean =>
  scan({ files: [P], readFile: () => src }).findings.some((f) => f.ruleId === RULE);

describe('dom/postmessage-origin-missing', () => {
  it('flags window.addEventListener("message") that uses data without checking origin', () => {
    expect(has("window.addEventListener('message', (e) => { handle(e.data); });")).toBe(true);
  });

  it('flags window.onmessage assignment without an origin check', () => {
    expect(has('window.onmessage = (e) => { apply(e.data.cmd); };')).toBe(true);
  });

  it('does NOT flag when the handler checks event.origin', () => {
    expect(
      has(
        "window.addEventListener('message', (e) => { if (e.origin !== ORIGIN) return; handle(e.data); });",
      ),
    ).toBe(false);
  });

  it('does NOT flag a handler that does not consume the message payload', () => {
    expect(has("window.addEventListener('message', () => { refresh(); });")).toBe(false);
  });

  it('does NOT flag a worker-style self.onmessage (different threat model, fail-secure)', () => {
    expect(has('self.onmessage = (e) => { handle(e.data); };')).toBe(false);
  });

  it('does NOT flag a non-message event listener', () => {
    expect(has("window.addEventListener('resize', (e) => { handle(e.data); });")).toBe(false);
  });

  it('does NOT flag a non-inline handler (cannot inspect — fail-secure)', () => {
    expect(has("window.addEventListener('message', onMessage);")).toBe(false);
  });
});
