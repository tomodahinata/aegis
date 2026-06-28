import pc from 'picocolors';
import { afterEach, describe, expect, it } from 'vitest';
import { colorEnabled, type Palette, palette } from './colors';

const CHANNELS: readonly (keyof Palette)[] = [
  'red',
  'yellow',
  'blue',
  'gray',
  'green',
  'cyan',
  'bold',
  'dim',
];

describe('palette', () => {
  it('returns identity colorizers when disabled — every channel leaves text untouched', () => {
    const p = palette(false);
    for (const channel of CHANNELS) {
      expect(p[channel]('text')).toBe('text');
    }
  });

  it('wires every channel to picocolors when enabled', () => {
    const p = palette(true);
    expect(p.red).toBe(pc.red);
    expect(p.yellow).toBe(pc.yellow);
    expect(p.blue).toBe(pc.blue);
    expect(p.gray).toBe(pc.gray);
    expect(p.green).toBe(pc.green);
    expect(p.cyan).toBe(pc.cyan);
    expect(p.bold).toBe(pc.bold);
    expect(p.dim).toBe(pc.dim);
  });
});

describe('colorEnabled', () => {
  const originalNoColor = process.env['NO_COLOR'];
  const originalIsTty = process.stdout.isTTY;

  function setTty(value: boolean): void {
    Object.defineProperty(process.stdout, 'isTTY', { value, configurable: true });
  }

  afterEach(() => {
    if (originalNoColor === undefined) {
      delete process.env['NO_COLOR'];
    } else {
      process.env['NO_COLOR'] = originalNoColor;
    }
    Object.defineProperty(process.stdout, 'isTTY', { value: originalIsTty, configurable: true });
  });

  it('is off when the --no-color flag is set, even on a TTY', () => {
    setTty(true);
    expect(colorEnabled(true)).toBe(false);
  });

  it('honors a non-empty NO_COLOR env var (the de-facto standard)', () => {
    setTty(true);
    process.env['NO_COLOR'] = '1';
    expect(colorEnabled(false)).toBe(false);
  });

  it('ignores an empty NO_COLOR and falls through to the TTY check', () => {
    process.env['NO_COLOR'] = '';
    setTty(true);
    expect(colorEnabled(false)).toBe(true);
  });

  it('is off for a non-TTY stdout (pipes, CI logs)', () => {
    delete process.env['NO_COLOR'];
    setTty(false);
    expect(colorEnabled(false)).toBe(false);
  });
});
