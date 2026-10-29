import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['src/**/*.test.ts'],
    // Les runners CI (surtout macOS) sont nettement plus lents qu'un poste de dev.
    testTimeout: 30_000,
  },
});
