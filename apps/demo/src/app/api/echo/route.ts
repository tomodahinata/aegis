import { secureRoute } from '@aegiskit/next';
import { z } from 'zod';

// Method enforcement → origin/CSRF check → Zod validation, all before the handler runs.
// `body` is fully typed from the schema.
export const POST = secureRoute(
  { method: 'POST', body: z.object({ message: z.string().max(500) }) },
  ({ body }) => Response.json({ echo: body.message }),
);
