import { getNonce } from '@aegiskit/next';
import type { ReactNode } from 'react';

export default async function RootLayout({ children }: { children: ReactNode }) {
  const nonce = await getNonce();
  return (
    <html lang="en">
      <body>
        {children}
        {/* biome-ignore lint/security/noDangerouslySetInnerHtml: demonstrating a nonce-protected inline script under the strict CSP. */}
        <script nonce={nonce} dangerouslySetInnerHTML={{ __html: 'window.__aegisDemo = true;' }} />
      </body>
    </html>
  );
}
