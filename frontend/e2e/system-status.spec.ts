import { expect, test, type Page } from '@playwright/test';

type BrowserUrls = {
  standard?: { url: string; email: string; password: string };
  diagnosticsDegraded?: { url: string; email: string; password: string };
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function fixtureFrom(value: unknown): BrowserUrls['standard'] | undefined {
  if (!isRecord(value) || typeof value.url !== 'string' || typeof value.email !== 'string' || typeof value.password !== 'string') {
    return undefined;
  }
  return { url: value.url, email: value.email, password: value.password };
}

function browserUrlsFrom(value: unknown): BrowserUrls {
  if (!isRecord(value)) return {};
  return {
    standard: fixtureFrom(value.standard),
    diagnosticsDegraded: fixtureFrom(value.diagnosticsDegraded),
  };
}

const parsedUrls: unknown = JSON.parse(process.env.CHINESCAN_BROWSER_TEST_URLS ?? '{}');
const urls = browserUrlsFrom(parsedUrls);
const screenshots = process.env.CHINESCAN_BROWSER_STATUS_SCREENSHOTS ?? '';

async function signIn(page: Page, fixture: NonNullable<BrowserUrls['standard']>) {
  await page.goto(fixture.url);
  await expect(page.getByRole('heading', { name: 'Welcome back' })).toBeVisible();
  await page.getByLabel('Email').fill(fixture.email);
  await page.getByLabel('Password').fill(fixture.password);
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(page.getByRole('heading', { name: 'Overview' })).toBeVisible();
  await page.getByRole('navigation', { name: 'Main navigation' }).getByRole('button', { name: 'System status' }).click();
  await expect(page.getByRole('heading', { name: 'System status' })).toBeVisible();
}

test('system status is healthy, goes offline, then recovers', async ({ page }) => {
  const fixture = urls.standard;
  expect(fixture).toBeDefined();
  if (!fixture) throw new Error('Healthy browser fixture is unavailable.');
  await signIn(page, fixture);
  await expect(page.getByText('Connected to local service')).toBeVisible();
  const configurationCheck = page.getByRole('listitem').filter({ hasText: 'Configuration' });
  await expect(configurationCheck.getByText('[PASS]')).toBeVisible();
  await page.screenshot({ path: `${screenshots}/system-status-healthy.png`, fullPage: true });

  await page.route('**/api/health', (route) => route.abort('failed'));
  await page.route('**/api/ready', (route) => route.abort('failed'));
  await page.route('**/api/diagnostics', (route) => route.abort('failed'));
  await page.getByRole('button', { name: 'Check system status now' }).click();
  await expect(page.getByRole('region', { name: 'Connectivity' }).getByText('Service offline', { exact: true })).toBeVisible();
  await page.screenshot({ path: `${screenshots}/system-status-offline.png`, fullPage: true });
  await page.unroute('**/api/health');
  await page.unroute('**/api/ready');
  await page.unroute('**/api/diagnostics');
  await page.getByRole('button', { name: 'Check system status now' }).click();
  await expect(page.getByText('Connected to local service')).toBeVisible({ timeout: 10_000 });
});

test('system status reports degraded readiness for missing optional storage', async ({ page }) => {
  const fixture = urls.diagnosticsDegraded;
  expect(fixture).toBeDefined();
  if (!fixture) throw new Error('Degraded browser fixture is unavailable.');
  await signIn(page, fixture);
  await expect(page.getByText('Connected to local service')).toBeVisible();
  await expect(page.getByText('[WARN]').first()).toBeVisible();
  await expect(page.getByText(/Managed malware storage is not configured/)).toBeVisible();
  await page.screenshot({ path: `${screenshots}/system-status-degraded.png`, fullPage: true });
});

test('unauthenticated status view redirects to operator login', async ({ page }) => {
  const fixture = urls.standard;
  expect(fixture).toBeDefined();
  if (!fixture) throw new Error('Healthy browser fixture is unavailable.');
  await page.goto(fixture.url);
  await expect(page.getByRole('heading', { name: 'Welcome back' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'System checks' })).toHaveCount(0);
});
