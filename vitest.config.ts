import { defineConfig } from 'vitest/config';

/**
 * Single root config. Cross-package imports (`@aegiskit/*`) resolve to each package's
 * `src/index.ts` via its package.json `exports` (the dev condition), so tests run
 * against TypeScript source with no build step.
 */
export default defineConfig({
  // Resolve `@aegiskit/*` to each package's `src` (the `development` export condition).
  resolve: { conditions: ['development'] },
  test: {
    include: ['packages/*/src/**/*.test.ts', 'apps/*/src/**/*.test.ts'],
    environment: 'node',
    passWithNoTests: true,
    clearMocks: true,
  },
});
