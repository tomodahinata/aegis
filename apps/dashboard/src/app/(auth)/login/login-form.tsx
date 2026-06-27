'use client';

import { useRouter } from 'next/navigation';
import { type FormEvent, useId, useState } from 'react';

export function LoginForm() {
  const router = useRouter();
  const fieldId = useId();
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setPending(true);
    setError(null);
    const password = new FormData(event.currentTarget).get('password');
    const response = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ password }),
    });
    setPending(false);
    if (response.ok) {
      router.push('/');
      router.refresh();
    } else {
      setError('Incorrect password.');
    }
  }

  return (
    <form onSubmit={onSubmit} className="mt-6 space-y-4" noValidate>
      <div>
        <label htmlFor={`${fieldId}-pw`} className="block font-medium text-sm">
          Admin password
        </label>
        <input
          id={`${fieldId}-pw`}
          name="password"
          type="password"
          autoComplete="current-password"
          required
          aria-invalid={error ? true : undefined}
          aria-describedby={error ? `${fieldId}-err` : undefined}
          className="mt-1 w-full rounded border border-border bg-card px-3 py-2"
        />
      </div>
      {error ? (
        <p id={`${fieldId}-err`} role="alert" className="text-sm text-tone-bad">
          {error}
        </p>
      ) : null}
      <button
        type="submit"
        disabled={pending}
        className="w-full rounded bg-primary px-3 py-2 font-medium text-white disabled:opacity-60"
      >
        {pending ? 'Signing in…' : 'Sign in'}
      </button>
    </form>
  );
}
