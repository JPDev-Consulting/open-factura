// tsup.config.ts
import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['src/index.ts'],
  format: ['cjs','esm'],
  dts: true,
  clean: true,
  outDir: 'dist',
  outExtension: ({ format }) => ({
    // for format==='cjs' → use .cjs; for esm → .mjs
    js: format === 'cjs' ? '.cjs' : '.mjs'
  }),
});

