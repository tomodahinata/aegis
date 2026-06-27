/**
 * Out-of-band canary listener — the only way blind SSRF earns a finding. A probe injects a URL
 * pointing at this loopback server (carrying an unguessable token) into the target; if the target
 * fetches it, the server records a hit. No hit within the budget ⇒ no finding (zero false positives).
 * Bound to 127.0.0.1 on an ephemeral port, so it is unreachable off-box, and torn down reliably.
 */

import { createServer, type Server } from 'node:http';

export interface CanaryToken {
  readonly token: string;
  /** The loopback URL a probe injects into the target as a payload. */
  readonly url: string;
}

export interface CanaryRegistry {
  /** Mint a fresh, unguessable token + its callback URL. */
  issue(): CanaryToken;
  /** Resolve true if the canary received a hit for `token` within `timeoutMs`, else false. */
  awaitHit(token: string, timeoutMs: number): Promise<boolean>;
}

export interface CanaryServer extends CanaryRegistry {
  /** Loopback origin the server listens on, e.g. `http://127.0.0.1:54231`. */
  readonly origin: string;
  close(): Promise<void>;
}

interface TokenState {
  hit: boolean;
  resolve?: ((hit: boolean) => void) | undefined;
}

function mintToken(): string {
  const bytes = new Uint8Array(16);
  globalThis.crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

const CANARY_PATH = /\/__aegis_canary__\/([a-f0-9]{8,})/;

/** Start a loopback OOB canary server on an ephemeral port. */
export async function startCanaryServer(): Promise<CanaryServer> {
  const tokens = new Map<string, TokenState>();
  const server: Server = createServer((req, res) => {
    const match = CANARY_PATH.exec(req.url ?? '');
    const token = match?.[1];
    if (token !== undefined) {
      const state = tokens.get(token);
      if (state) {
        state.hit = true;
        state.resolve?.(true);
      }
      res.statusCode = 204;
      res.end();
      return;
    }
    res.statusCode = 404;
    res.end();
  });

  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (address === null || typeof address === 'string') {
    await new Promise<void>((resolve) => server.close(() => resolve()));
    throw new Error('canary server failed to bind a TCP port');
  }
  const origin = `http://127.0.0.1:${address.port}`;

  return {
    origin,
    issue(): CanaryToken {
      const token = mintToken();
      tokens.set(token, { hit: false });
      return { token, url: `${origin}/__aegis_canary__/${token}` };
    },
    awaitHit(token: string, timeoutMs: number): Promise<boolean> {
      const state = tokens.get(token);
      if (!state) {
        return Promise.resolve(false);
      }
      if (state.hit) {
        return Promise.resolve(true);
      }
      return new Promise<boolean>((resolve) => {
        const timer = setTimeout(() => {
          state.resolve = undefined;
          resolve(false);
        }, timeoutMs);
        state.resolve = (hit): void => {
          clearTimeout(timer);
          state.resolve = undefined;
          resolve(hit);
        };
      });
    },
    async close(): Promise<void> {
      for (const state of tokens.values()) {
        state.resolve?.(false);
      }
      await new Promise<void>((resolve, reject) => {
        server.close((error) => {
          // A server already torn down is the desired end state, not a failure — never let a
          // benign teardown error reject and discard an already-computed probe result.
          const code = (error as { code?: string } | undefined)?.code;
          if (error && code !== 'ERR_SERVER_NOT_RUNNING') {
            reject(error);
          } else {
            resolve();
          }
        });
      });
    },
  };
}
