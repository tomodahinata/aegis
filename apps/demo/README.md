# @aegiskit/demo

A minimal Next.js 16 App Router app showing Aegis wired end-to-end:

- `src/middleware.ts` — `secure()` applies hardened headers + nonce CSP + per-IP rate limiting on `/api`.
- `src/app/layout.tsx` — reads the nonce via `getNonce()` to allow an inline script under the strict CSP.
- `src/app/api/echo/route.ts` — `secureRoute()` enforces method, origin/CSRF, and Zod validation.
- `src/env.server.ts` — `defineServerEnv()` validates env behind the `server-only` boundary.
- `next.config.ts` — deliberately emits **no** CSP (secure() is the single emitter).

It is also a living "good fixture": running the scanner against it should report **zero** findings.

```bash
pnpm --filter @aegiskit/demo dev          # run it
node packages/cli/dist/main.js scan --cwd apps/demo   # scan it → clean
```
