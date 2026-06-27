# @aegiskit/next

Next.js (App Router) security adapters for [Aegis](https://github.com/your-org/aegis). One middleware file gives you a hardened, nonce-based CSP, security headers, rate limiting, and origin/CSRF protection.

> **Honest scope:** this closes the common, high-impact gaps automatically; it does not make your app "completely secure". Pair it with `@aegiskit/scanner` (for what a library can't auto-fix) and sound authorization design.

## Install

```bash
pnpm add @aegiskit/next @aegiskit/core
```

## 1. Middleware — the single CSP emitter

`middleware.ts` (or `proxy.ts` in Next 16 — identical):

```ts
import { secure } from '@aegiskit/next';

export default secure();

export const config = {
  matcher: ['/((?!_next/static|_next/image|favicon.ico).*)'],
};
```

> **Migration:** remove any `Content-Security-Policy` from `next.config` — `secure()` is the **only** place CSP is emitted. (A static config CSP shadowing a per-request nonce is the exact bug this prevents.)

Read the nonce in a Server Component to allow your own inline scripts:

```tsx
// app/layout.tsx
import { getNonce } from '@aegiskit/next';

export default async function RootLayout({ children }: { children: React.ReactNode }) {
  const nonce = await getNonce();
  return (
    <html>
      <body>
        {children}
        <script nonce={nonce} dangerouslySetInnerHTML={{ __html: '/* ... */' }} />
      </body>
    </html>
  );
}
```

`secure()` accepts a config: `csp`, `cspMode` (defaults to `report-only`; to drive it from an env var, pass `resolveCspMode(env.NEXT_PUBLIC_CSP_MODE)` resolved from your own typed env), `headers`, `rateLimit` (with a `RateLimiter` from `@aegiskit/core`), `origin`, `sink` (security events), and `chain` (compose your existing session/i18n middleware).

## 2. Route handlers — `secureRoute`

Custom Route Handlers get **no** CSRF protection by default. `secureRoute` adds method enforcement → origin check → rate limit → typed Zod validation:

```ts
import { secureRoute } from '@aegiskit/next';
import { RateLimiter, RATE_LIMIT_PRESETS } from '@aegiskit/core';
import { createUpstashStore } from '@aegiskit/store-upstash';
import { Redis } from '@upstash/redis';
import { z } from 'zod';

const limiter = new RateLimiter({ store: createUpstashStore({ redis: Redis.fromEnv() }) });

export const POST = secureRoute(
  {
    method: 'POST',
    body: z.object({ message: z.string().max(2000) }),
    rateLimit: { limiter, rule: RATE_LIMIT_PRESETS.ai },
  },
  async ({ body }) => {
    // `body` is fully typed: { message: string }
    return Response.json({ echo: body.message });
  },
);
```

## 3. Typed env — `@aegiskit/next/env`

Importing this module from a Client Component is a **build error** (it carries `server-only`), structurally preventing server-secret leaks:

```ts
// env.server.ts
import { defineServerEnv } from '@aegiskit/next/env';
import { z } from 'zod';

export const env = defineServerEnv({
  server: { SUPABASE_SERVICE_ROLE_KEY: z.string().min(1) },
  client: { NEXT_PUBLIC_SUPABASE_URL: z.string().url() },
});
```

## Trade-off: nonce CSP forces dynamic rendering

Reading the nonce makes a route dynamic. Apply nonce-CSP to your authenticated (already-dynamic) segment, and keep static/marketing routes on a nonce-free policy or `csp: false`.

## Composes with the platform

This is the **application** layer. It complements your platform's network-layer WAF/bot protection (e.g. Vercel Firewall/BotID) — they handle volumetric DDoS and known-bad bots; Aegis handles per-identity rate limits, CSRF on specific handlers, CSP, and typed validation.

## License

MIT
