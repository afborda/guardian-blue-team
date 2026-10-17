import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['src/index.ts', 'src/scripts/weekly-audit-now.ts'],
  format: ['esm'],
  dts: true,
  clean: true,
  noExternal: [],
  external: ['onnxruntime-node'],
});
