/**
 * Map a Next.js App-Router route handler file to its URL path, and fill dynamic segments with a safe
 * placeholder so the route can actually be requested. `app/api/users/[id]/route.ts → /api/users/[id]`,
 * then `fillParams('/api/users/[id]') → /api/users/1`.
 */

const ROUTE_FILE = /(?:^|\/)app\/(?:(.+)\/)?route\.(?:ts|tsx|js|jsx|mjs)$/;

/** The route pattern for a `route.ts` file, or `undefined` if it is not an App-Router route. */
export function deriveRoutePath(filePath: string): string | undefined {
  const normalized = filePath.replace(/\\/g, '/');
  const match = ROUTE_FILE.exec(normalized);
  if (!match) {
    return undefined;
  }
  const inner = match[1];
  if (inner === undefined) {
    return '/';
  }
  // Drop route groups `(marketing)` — they don't appear in the URL.
  const segments = inner.split('/').filter((s) => !(s.startsWith('(') && s.endsWith(')')));
  return segments.length === 0 ? '/' : `/${segments.join('/')}`;
}

const DYNAMIC_SEGMENT = /\[\[?\.{0,3}[^\]]+\]\]?/g;

/** Replace dynamic segments (`[id]`, `[...slug]`, `[[...slug]]`) with a placeholder value. */
export function fillParams(routePath: string, value = '1'): string {
  return routePath.replace(DYNAMIC_SEGMENT, value);
}
