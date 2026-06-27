import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['src/index.ts', 'src/env.ts'],
  format: ['esm'],
  dts: true,
  clean: true,
  treeshake: true,
  target: 'es2022',
  outDir: 'dist',
  external: ['next', 'react', 'react-dom', 'server-only'],
});
