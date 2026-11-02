import { expect, test } from '@playwright/test';
import { mkdirSync } from 'node:fs';
import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

type Fixture = { url: string; email: string; password: string };
function fixtures(): Record<string, Fixture> {
  return JSON.parse(process.env.CHINESCAN_BROWSER_TEST_URLS ?? '{}') as Record<string, Fixture>;
}

async function signIn(page: import('@playwright/test').Page, fixture: Fixture): Promise<void> {
  await page.goto(fixture.url);
  await page.getByLabel('Email').fill(fixture.email);
  await page.getByLabel('Password').fill(fixture.password);
  await page.getByRole('button', { name: /sign in/i }).click();
  await expect(page.getByRole('navigation', { name: 'Main navigation' })).toBeVisible();
}

async function capture(page: import('@playwright/test').Page, filename: string): Promise<void> {
  const directory = process.env.CHINESCAN_BROWSER_PHASE6C_SCREENSHOTS;
  if (!directory) throw new Error('Phase 6C screenshot directory is missing.');
  mkdirSync(directory, { recursive: true });
  await page.screenshot({ path: resolve(directory, filename), fullPage: true });
}

test('public GitHub import creates, assesses, scans and safely removes a project', async ({ page }) => {
  const fixture = fixtures().githubEnabled;
  const repositoryUrl = process.env.CHINESCAN_BROWSER_GITHUB_URL;
  const dataDirectory = process.env.CHINESCAN_BROWSER_GITHUB_DATA_DIR;
  expect(repositoryUrl).toBeTruthy();
  expect(dataDirectory).toBeTruthy();
  expect(existsSync(fileURLToPath(repositoryUrl!))).toBe(true);
  let importJobId = '';
  page.on('response', async (response) => {
    if (response.url().endsWith('/api/github/imports') && response.request().method() === 'POST') {
      const payload: unknown = await response.json();
      if (payload !== null && typeof payload === 'object' && 'job_id' in payload && typeof payload.job_id === 'string') importJobId = payload.job_id;
    }
  });
  await signIn(page, fixture);
  await page.getByRole('button', { name: 'Projects', exact: true }).click();
  await page.getByRole('button', { name: 'Import from GitHub' }).click();
  await page.getByLabel('Public GitHub repository URL').fill(repositoryUrl!);
  await page.getByRole('button', { name: 'Preview' }).click();
  await expect(page.getByRole('heading', { name: 'Review import' })).toBeVisible();
  await capture(page, 'github-preview.png');
  await page.getByRole('button', { name: 'Import', exact: true }).click();
  await expect(page.getByRole('region', { name: 'Import progress' })).toBeVisible();
  await capture(page, 'github-progress.png');
  await expect(page.getByRole('heading', { name: 'Import complete' })).toBeVisible({ timeout: 30_000 });
  await capture(page, 'github-success.png');
  await page.getByRole('dialog').getByRole('button', { name: 'Close' }).click();
  await expect(page.getByRole('row').filter({ hasText: 'repository' })).toBeVisible();
  expect(importJobId).not.toBe('');
  const clone = resolve(dataDirectory!, 'gh', importJobId);
  expect(existsSync(resolve(clone, 'sample.py'))).toBe(true);

  await page.getByRole('row').filter({ hasText: 'repository' }).getByRole('button', { name: 'Open project' }).click();
  await page.getByRole('button', { name: 'Assess code' }).click();
  await expect(page.getByRole('heading', { name: 'Assessment history' })).toBeVisible();
  await page.getByRole('button', { name: 'Scan for malware' }).click();
  const malwareDialog = page.getByRole('dialog', { name: 'Before scanning this project' });
  await expect(malwareDialog.getByText('For GitHub projects, do the import itself inside the VM.')).toBeVisible();
  await page.getByRole('button', { name: 'Cancel' }).click();
  await page.getByRole('button', { name: 'Remove project' }).click();
  const removeDialog = page.getByRole('dialog', { name: /Remove repository\?/ });
  await removeDialog.getByLabel('Type repository to confirm').fill('repository');
  const removalResponsePromise = page.waitForResponse((response) =>
    /^\/api\/projects\/[^/]+$/.test(new URL(response.url()).pathname) && response.request().method() === 'DELETE',
  );
  await removeDialog.getByRole('button', { name: 'Remove project and clone' }).click();
  const removalResponse = await removalResponsePromise;
  expect(removalResponse.status(), await removalResponse.text()).toBe(200);
  await expect(page.getByRole('region', { name: 'Projects' })).toBeVisible();
  await expect(page.getByRole('row').filter({ hasText: 'repository' })).toHaveCount(0);
  await expect.poll(() => existsSync(clone), { timeout: 10_000 }).toBe(false);
});

test('GitHub import is disabled until the operator enables it', async ({ page }) => {
  const fixture = fixtures().githubDisabled;
  await signIn(page, fixture);
  await page.getByRole('button', { name: 'Projects', exact: true }).click();
  await page.getByRole('button', { name: 'Import from GitHub' }).click();
  await expect(page.getByRole('heading', { name: 'GitHub import is disabled' })).toBeVisible();
  await expect(page.getByText(/github_import_enabled = true/)).toBeVisible();
  await capture(page, 'github-disabled.png');
});
