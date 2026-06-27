import { LoginForm } from './login-form';

export default function LoginPage() {
  return (
    <main
      id="main"
      tabIndex={-1}
      className="mx-auto flex min-h-dvh max-w-sm flex-col justify-center px-4"
    >
      <h1 className="font-bold text-2xl">Aegis dashboard</h1>
      <p className="mt-1 text-muted text-sm">Sign in to view your security posture.</p>
      <LoginForm />
    </main>
  );
}
