import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['src/**/*.test.ts'],
    // Les runners CI (surtout macOS) sont nettement plus lents qu'un poste de dev.
    testTimeout: 30_000,
    coverage: {
      provider: 'v8',
      include: ['src/**/*.ts'],
      exclude: ['src/**/*.test.ts'],
      reporter: ['text', 'json-summary'],
      // Seuils légèrement sous la couverture actuelle (96 % lignes). Seul `defaultLimits()` de recovery.ts
      // (Argon2id « sensitive », plusieurs minutes et 1 Gio) n'est pas exercé : tous les tests passent des limites réduites.
      thresholds: {
        statements: 95,
        branches: 90,
        functions: 90,
        lines: 95,
      },
    },
  },
});
