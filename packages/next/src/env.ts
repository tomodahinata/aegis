/**
 * Server-only env boundary. This module imports `server-only`, so importing it from a Client
 * Component is a BUILD error — structurally preventing the classic "server secret leaked into
 * the client bundle" bug instead of relying on discipline.
 *
 * Use `defineServerEnv` in server code (it validates server + client vars). For client
 * components that need only `NEXT_PUBLIC_*` vars, call `@aegiskit/core`'s `defineEnv` with just
 * the `client` shape from a separate, non-server-only module.
 */

import 'server-only';
import { type DefinedEnv, type DefineEnvConfig, defineEnv } from '@aegiskit/core';
import type { z } from 'zod';

type ClientShape = Record<`NEXT_PUBLIC_${string}`, z.ZodType>;

export type DefineServerEnvConfig<
  TServer extends z.ZodRawShape,
  TClient extends ClientShape,
> = Omit<DefineEnvConfig<TServer, TClient>, 'runtimeEnv' | 'isServer'> & {
  /** Defaults to `process.env`. */
  readonly runtimeEnv?: Record<string, string | undefined>;
};

/** Validate and freeze server + client env on the server. Defaults `runtimeEnv` to `process.env`. */
export function defineServerEnv<TServer extends z.ZodRawShape, TClient extends ClientShape>(
  config: DefineServerEnvConfig<TServer, TClient>,
): DefinedEnv<TServer, TClient> {
  const { runtimeEnv, ...rest } = config;
  return defineEnv<TServer, TClient>({
    ...rest,
    runtimeEnv: runtimeEnv ?? process.env,
    isServer: true,
  });
}
