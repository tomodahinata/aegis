import { defineConfig } from 'vitest/config';

/**
 * Multi-project root config. Most tests run in a Node environment against TypeScript source — cross-
 * package `@aegiskit/*` imports resolve to each package's `src/index.ts` via the `development` export
 * condition, so there is no build step. The dashboard has its own project (jsdom + the `@` alias) for
 * React component / accessibility tests; see `apps/dashboard/vitest.config.ts`.
 */
export default defineConfig({
  test: {
    passWithNoTests: true,
    projects: [
      {
        resolve: { conditions: ['development'] },
        test: {
          name: 'unit',
          include: [
            'packages/*/src/**/*.test.ts',
            'packages/*/bench/**/*.test.ts',
            'apps/*/src/**/*.test.ts',
          ],
          environment: 'node',
          clearMocks: true,
        },
      },
      './apps/dashboard/vitest.config.ts',
    ],
  },
});
