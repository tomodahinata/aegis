import { defineServerEnv } from '@aegiskit/next/env';
import { z } from 'zod';

// The ONLY process.env reader in the app. Validated + frozen at boot, behind the server-only seam.
export const env = defineServerEnv({
  server: {
    AEGIS_ADMIN_PASSWORD: z.string().min(12),
    AEGIS_SESSION_SECRET: z.string().min(32),
    AEGIS_INGEST_SECRET: z.string().min(32),
    AEGIS_SESSION_TTL_S: z.coerce.number().int().positive().default(86_400),
    AEGIS_RETENTION_MAX: z.coerce.number().int().positive().default(10_000),
  },
  client: {
    NEXT_PUBLIC_CSP_MODE: z.enum(['enforce', 'report-only', 'off']).default('report-only'),
  },
});
