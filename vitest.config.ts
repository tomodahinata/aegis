import { defineConfig } from 'vitest/config';

/**
 * Multi-project root config. Most tests run in a Node environment against TypeScript source — cross-
 * package `@aegiskit/*` imports resolve to each package's `src/index.ts` via the `development` export
 * condition, so there is no build step. The dashboard has its own project (jsdom + the `@` alias) for
 * React component / accessibility tests; see `apps/dashboard/vitest.config.ts`.
 */

// v8 coverage instrumentation inflates wall-clock time several-fold, which would flake the handful of
// timing smoke-checks (e.g. the SQL predicate DoS guard). We surface the coverage run to tests via
// `VITEST_COVERAGE` so those checks can relax their budget under instrumentation while staying strict
// for the plain `pnpm test` path that devs and the pre-push hook run.
const coverageRun = process.argv.includes('--coverage');

export default defineConfig({
  test: {
    passWithNoTests: true,
    // Coverage aggregates across both projects (Node unit + jsdom dashboard). The gate is a *ratchet*:
    // thresholds below sit at the measured floor and only ever increase as tests land, so a regression
    // fails CI while progress toward 100% stays non-blocking.
    coverage: {
      provider: 'v8',
      reporter: ['text-summary', 'json-summary', 'html', 'lcov'],
      reportsDirectory: './coverage',
      // Honest coverage: measure every shipped source file, not just the ones tests happen to import.
      all: true,
      include: ['packages/*/src/**/*.ts', 'apps/dashboard/src/**/*.{ts,tsx}'],
      exclude: [
        '**/*.test.{ts,tsx}',
        '**/*.d.ts',
        '**/types.ts', // type-only modules carry no runtime to exercise
        'packages/*/bench/**',
        'packages/scanner/fixtures/**',
        'apps/demo/**', // example app, already changesets-ignored
      ],
      // Per-package ratchet floors, set to the integer floor of measured coverage. They are a one-way
      // gate: a regression below the floor fails CI; raise (never lower) a number as tests land, until
      // every package reaches 100. Any metric already at 100 is pinned — perfection cannot regress.
      thresholds: {
        'packages/core/src/**': { statements: 93, branches: 91, functions: 90, lines: 93 },
        'packages/next/src/**': { statements: 95, branches: 88, functions: 100, lines: 95 },
        'packages/scanner/src/**': { statements: 94, branches: 87, functions: 97, lines: 94 },
        'packages/dast/src/**': { statements: 90, branches: 78, functions: 88, lines: 91 },
        'packages/cli/src/**': { statements: 74, branches: 57, functions: 84, lines: 73 },
        'packages/observability/src/**': { statements: 98, branches: 84, functions: 91, lines: 98 },
        'packages/store-supabase/src/**': {
          statements: 85,
          branches: 74,
          functions: 100,
          lines: 85,
        },
        'packages/store-upstash/src/**': {
          statements: 100,
          branches: 100,
          functions: 100,
          lines: 100,
        },
        'packages/eslint-config/src/**': {
          statements: 100,
          branches: 100,
          functions: 100,
          lines: 100,
        },
        'apps/dashboard/src/**': { statements: 37, branches: 44, functions: 34, lines: 36 },
      },
    },
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
          env: { VITEST_COVERAGE: coverageRun ? '1' : '' },
        },
      },
      './apps/dashboard/vitest.config.ts',
    ],
  },
});
