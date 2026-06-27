/**
 * Typed environment-variable boundary. Validates and freezes env at module-eval (fail-fast),
 * and enforces the server/public split both at the type level and at runtime:
 *
 *  - `client` keys are constrained to `NEXT_PUBLIC_${string}` (a non-prefixed key is a compile
 *    error AND a runtime throw).
 *  - `server` keys must NOT be `NEXT_PUBLIC_`-prefixed, and are only read when running on the
 *    server — so a server secret can never be parsed into (or leak through) the client bundle.
 *
 * The `import 'server-only'` seam that makes a client import of server env a *build* failure
 * lives in the framework adapter (`@aegiskit/next/env`); this module stays runtime-agnostic.
 */

import { z } from 'zod';

type ClientShape = Record<`NEXT_PUBLIC_${string}`, z.ZodType>;

export interface DefineEnvConfig<TServer extends z.ZodRawShape, TClient extends ClientShape> {
  /** Server-only variables. Validated only on the server. Keys must NOT start with `NEXT_PUBLIC_`. */
  readonly server: TServer;
  /** Client-exposed variables. Keys MUST start with `NEXT_PUBLIC_`. */
  readonly client: TClient;
  /** The raw environment (usually `process.env`), passed explicitly for testability. */
  readonly runtimeEnv: Record<string, string | undefined>;
  /** Treat `''` as `undefined` before validation (so a blank var triggers a required-field error). Default `true`. */
  readonly emptyStringAsUndefined?: boolean;
  /** Skip validation entirely (e.g. a Docker build with no secrets present). Default `false`. */
  readonly skipValidation?: boolean;
  /** Override server detection. Defaults to `typeof window === 'undefined'`. */
  readonly isServer?: boolean;
}

export type DefinedEnv<TServer extends z.ZodRawShape, TClient extends ClientShape> = Readonly<
  z.infer<z.ZodObject<TServer>> & z.infer<z.ZodObject<TClient>>
>;

export class EnvValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'EnvValidationError';
  }
}

function blankToUndefined(
  env: Record<string, string | undefined>,
): Record<string, string | undefined> {
  const out: Record<string, string | undefined> = {};
  for (const [key, value] of Object.entries(env)) {
    out[key] = value === '' ? undefined : value;
  }
  return out;
}

function formatEnvError(scope: 'server' | 'client', error: z.ZodError): string {
  const lines = error.issues.map((issue) => {
    const path = issue.path.length > 0 ? issue.path.map(String).join('.') : '(root)';
    return `  • ${path}: ${issue.message}`;
  });
  return `Invalid ${scope} environment variables:\n${lines.join('\n')}`;
}

/** Validate, split, and freeze environment variables into one typed object. */
export function defineEnv<TServer extends z.ZodRawShape, TClient extends ClientShape>(
  config: DefineEnvConfig<TServer, TClient>,
): DefinedEnv<TServer, TClient> {
  const {
    server,
    client,
    runtimeEnv,
    emptyStringAsUndefined = true,
    skipValidation = false,
    // Edge-safe server detection without the DOM lib: the browser global `window` is absent
    // on Node and the edge runtime.
    isServer = !('window' in globalThis),
  } = config;

  for (const key of Object.keys(client)) {
    if (!key.startsWith('NEXT_PUBLIC_')) {
      throw new EnvValidationError(`Client env key "${key}" must be prefixed with NEXT_PUBLIC_.`);
    }
  }
  for (const key of Object.keys(server)) {
    if (key.startsWith('NEXT_PUBLIC_')) {
      throw new EnvValidationError(
        `Server env key "${key}" must not be prefixed with NEXT_PUBLIC_ — that prefix exposes it to the client bundle.`,
      );
    }
  }

  const source = emptyStringAsUndefined ? blankToUndefined(runtimeEnv) : runtimeEnv;

  if (skipValidation) {
    return Object.freeze({ ...source }) as unknown as DefinedEnv<TServer, TClient>;
  }

  const clientParsed = z.object(client).safeParse(source);
  if (!clientParsed.success) {
    throw new EnvValidationError(formatEnvError('client', clientParsed.error));
  }

  let serverData: Record<string, unknown> = {};
  if (isServer) {
    const serverParsed = z.object(server).safeParse(source);
    if (!serverParsed.success) {
      throw new EnvValidationError(formatEnvError('server', serverParsed.error));
    }
    serverData = serverParsed.data;
  }

  return Object.freeze({
    ...clientParsed.data,
    ...serverData,
  }) as DefinedEnv<TServer, TClient>;
}
