import { defineServerEnv } from '@aegiskit/next/env';
import { z } from 'zod';

// Importing this module from a Client Component is a BUILD error (it carries `server-only`),
// so a server secret can never be bundled to the browser.
export const env = defineServerEnv({
  server: { SUPABASE_SERVICE_ROLE_KEY: z.string().min(1).optional() },
  client: { NEXT_PUBLIC_APP_URL: z.string().min(1).optional() },
});
