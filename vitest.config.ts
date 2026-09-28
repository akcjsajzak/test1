import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    environment: 'node',
    testTimeout: 20000,
    hookTimeout: 60000,
    // Browser-driven e2e tests are safer in isolated forks.
    pool: 'forks',
    reporters: 'default',
  },
});
