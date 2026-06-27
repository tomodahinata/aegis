// Array-split CSP policy: the `'unsafe-inline'` fragment names no directive of its own,
// so a directive-name filter would miss it. The file is still a CSP context.
const policy = ["script-src 'self'", "'unsafe-inline'"].join(' ');

export function middleware() {
  const headers = new Headers();
  headers.set('Content-Security-Policy', policy);
  return new Response(null, { headers });
}
