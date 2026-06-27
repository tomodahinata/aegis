import pc from 'picocolors';

export type Colorize = (text: string) => string;

export interface Palette {
  readonly red: Colorize;
  readonly yellow: Colorize;
  readonly blue: Colorize;
  readonly gray: Colorize;
  readonly green: Colorize;
  readonly cyan: Colorize;
  readonly bold: Colorize;
  readonly dim: Colorize;
}

const identity: Colorize = (text) => text;

export function palette(enabled: boolean): Palette {
  if (!enabled) {
    return {
      red: identity,
      yellow: identity,
      blue: identity,
      gray: identity,
      green: identity,
      cyan: identity,
      bold: identity,
      dim: identity,
    };
  }
  return {
    red: pc.red,
    yellow: pc.yellow,
    blue: pc.blue,
    gray: pc.gray,
    green: pc.green,
    cyan: pc.cyan,
    bold: pc.bold,
    dim: pc.dim,
  };
}

/** Color is on only for a TTY, with `--no-color` and the `NO_COLOR` env var both honored. */
export function colorEnabled(noColorFlag: boolean): boolean {
  if (noColorFlag) {
    return false;
  }
  const noColorEnv = process.env['NO_COLOR'];
  if (noColorEnv !== undefined && noColorEnv !== '') {
    return false;
  }
  return process.stdout.isTTY === true;
}
