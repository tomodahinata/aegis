import { cleanup } from '@testing-library/react';
import { afterEach } from 'vitest';

// Unmount React trees between tests (RTL auto-cleanup only registers with global test APIs, which we
// keep off in favor of explicit imports).
afterEach(() => {
  cleanup();
});
