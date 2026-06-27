import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { discoverFiles } from './discover';

const SRC = dirname(fileURLToPath(import.meta.url));

describe('discoverFiles', () => {
  it('finds source files and excludes test files', () => {
    const files = discoverFiles(SRC);
    expect(files.some((file) => file.endsWith('main.ts'))).toBe(true);
    expect(files.every((file) => !/\.test\.ts$/.test(file))).toBe(true);
  });
});
