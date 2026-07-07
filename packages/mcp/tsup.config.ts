import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['src/main.ts', 'src/index.ts'],
  format: ['esm'],
  dts: true,
  clean: true,
  treeshake: true,
  target: 'es2022',
  outDir: 'dist',
  external: ['@aegiskit/cli', '@aegiskit/scanner', '@modelcontextprotocol/sdk', 'zod'],
});
