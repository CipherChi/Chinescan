import { expect, test } from '@playwright/test';

const urls = JSON.parse(process.env.CHINESCAN_BROWSER_TEST_URLS ?? '{}') as {
  expiry?: { url: string; email: string; password: string };
};

test('expired session during a protected action returns to sign-in and revokes API access', async ({ page }) => {
  await page.goto(urls.expiry?.url ?? '/');
  await page.getByLabel('Email').fill(urls.expiry?.email ?? '');
  await page.getByLabel('Password').fill(urls.expiry?.password ?? '');
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(page.getByRole('heading', { name: 'Overview' })).toBeVisible();

  const scanRequest = page.waitForRequest((request) => new URL(request.url()).pathname === '/api/scans');
  await page.getByRole('navigation', { name: 'Main navigation' }).getByRole('button', { name: /^Scans/ }).click();
  await scanRequest;
  await expect.poll(async () => {
    const response = await page.request.get(`${urls.expiry?.url}/api/auth/session`);
    if (response.status() !== 200) return false;
    return (await response.json()).authenticated;
  }, { timeout: 25_000 }).toBe(false);
  await expect(page.getByRole('heading', { name: 'Welcome back' })).toBeVisible();
  const apiResponse = await page.request.get(`${urls.expiry?.url}/api/overview`);
  expect(apiResponse.status()).toBe(401);
});
