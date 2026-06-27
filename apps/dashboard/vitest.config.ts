import { fileURLToPath } from 'node:url';
import { defineProject } from 'vitest/config';

/**
 * Dashboard test project: jsdom (React components render to a DOM), the `@` path alias, and the
 * `development` condition so `@aegiskit/*` resolves to source. Only `*.test.tsx` runs here; pure-logic
 * `*.test.ts` continue under the root `unit` (Node) project.
 */
export default defineProject({
  resolve: {
    alias: { '@': fileURLToPath(new URL('./src', import.meta.url)) },
    conditions: ['development'],
  },
  test: {
    name: 'dashboard',
    environment: 'jsdom',
    include: ['src/**/*.test.tsx'],
    setupFiles: ['./vitest.setup.ts'],
    clearMocks: true,
  },
});
