import { LogoutButton } from './logout-button';

export const dynamic = 'force-dynamic';

export default function SettingsPage() {
  return (
    <div className="space-y-6">
      <h1 className="font-bold text-2xl">Settings</h1>
      <section className="rounded-lg border border-border bg-card p-4 text-sm">
        <h2 className="font-semibold">Ingestion</h2>
        <p className="mt-1 text-muted">
          Events are HMAC-verified at <code>/api/ingest/events</code> using{' '}
          <code>AEGIS_INGEST_SECRET</code>. Rotate it in your environment and redeploy. Browser CSP
          reports POST to <code>/api/ingest/csp</code>.
        </p>
      </section>
      <section className="rounded-lg border border-border bg-card p-4 text-sm">
        <h2 className="font-semibold">Session</h2>
        <p className="mt-1 text-muted">Sign out to clear the admin session cookie.</p>
        <LogoutButton />
      </section>
    </div>
  );
}
