import './globals.css';
import { getNonce } from '@aegiskit/next';
import type { Metadata } from 'next';
import type { ReactNode } from 'react';
import { SkipLink } from '@/components/a11y/skip-link';
import { ThemeProvider } from '@/components/theme/theme-provider';

export const metadata: Metadata = {
  title: 'Aegis — Security Dashboard',
  description: 'Runtime security posture and events for your Aegis-protected app.',
};

export default async function RootLayout({ children }: { children: ReactNode }) {
  // The nonce flows from secure() in middleware; next-themes uses it for its inline theme script.
  const nonce = await getNonce();
  return (
    <html lang="en" suppressHydrationWarning>
      <body>
        <ThemeProvider {...(nonce !== undefined ? { nonce } : {})}>
          <SkipLink />
          {children}
        </ThemeProvider>
      </body>
    </html>
  );
}
