import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: './e2e',
  fullyParallel: false,
  retries: 0,
  reporter: 'list',
  outputDir: './test-results',
  globalSetup: './e2e/global-setup.ts',
  timeout: 90_000,
  expect: { timeout: 8_000 },
  use: {
    ...devices['Desktop Chrome'],
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    video: 'off',
  },
  projects: [
    { name: 'chromium-production', testMatch: 'dashboard.spec.ts' },
    { name: 'chromium-session-expiry', testMatch: 'session-expiry.spec.ts' },
  ],
});
