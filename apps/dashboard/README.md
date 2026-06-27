# @aegiskit/dashboard

A self-hostable, accessible (WCAG 2.2 AA) dashboard for your Aegis-protected app: posture score, security events, and CSP violations.

It **dogfoods Aegis** — `src/middleware.ts` uses `secure()`, and the ingestion routes use `secureRoute()` / `createCspReportHandler`.

## Wire your app to it

In your app, point an HTTP sink at the dashboard's ingestion endpoint:

```ts
import { createHttpSink, createMultiSink, createConsoleSink } from '@aegiskit/core';
import { secure } from '@aegiskit/next';

const sink = createMultiSink(
  createConsoleSink(),
  createHttpSink({ endpoint: 'https://dash.example.com/api/ingest/events', secret: env.AEGIS_INGEST_SECRET }),
);
export default secure({ sink, cspReportEndpoint: '/api/aegis/csp-report' });
```

The dashboard verifies every batch's HMAC over the **raw bytes** and enforces a replay window before storing.

## Run

```bash
cp .env.example .env.local   # set AEGIS_ADMIN_PASSWORD / AEGIS_*_SECRET
pnpm --filter @aegiskit/dashboard dev
node packages/cli/dist/main.js scan --cwd apps/dashboard   # dogfood: should be clean
```

Storage defaults to an in-memory ring buffer (zero infra; single-instance). For production, swap `getEventStore()` for `@aegiskit/store-supabase`'s `createSupabaseEventStore` (ships a migration with RLS on by default).

## Accessibility (WCAG 2.2 AA)

- **Skip link** to `#main`; one `<h1>` per route; `<header>/<nav aria-label>/<main>` landmarks.
- **Keyboard**: native `<select>`/`<a>`/`<button>` everywhere; visible `:focus-visible` ring; `<main tabIndex=-1>`.
- **Not color alone (1.4.1)**: severity = glyph + text + color; grade = icon + "Grade A — Strong" + color (`gradeToVisual`/`severityToVisual`, unit-tested).
- **Charts (1.1.1)**: the sparkline is an SVG with `role="img"` + `aria-label` **and** a visually-hidden data `<table>`.
- **Contrast (1.4.3)**: token-driven `:root` / `.dark` / `.hc` (high-contrast) themes; selectable.
- **Motion (2.3.3)**: `prefers-reduced-motion` disables animations/transitions.
- **Forms (3.3)**: login field has `<label>`, `aria-invalid`/`aria-describedby`, `role="alert"` errors, `autocomplete="current-password"`, paste allowed.
- **Auth (3.3.8)**: a single password field; no cognitive test.

## Security notes

- Ingestion (`/api/ingest/events`) verifies the HMAC over RAW bytes (no `secureRoute` body schema), enforces a replay window, bounds every field, rate-limits, and returns 204/4xx — never reflecting input.
- CSP reports (`/api/ingest/csp`) are unsigned (browsers send them) but bounded + validated + rate-limited.
- Admin session is a signed `__Host-` cookie (HttpOnly, Secure, SameSite=Lax). Supabase Auth is the documented upgrade path.
