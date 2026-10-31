import { expect, test } from '@playwright/test';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync } from 'node:fs';
import { readdir, readFile } from 'node:fs/promises';
import { resolve } from 'node:path';

type Fixture = { url: string; email: string; password: string };
function fixtures(): Record<string, Fixture> {
  return JSON.parse(process.env.CHINESCAN_BROWSER_TEST_URLS ?? '{}') as Record<string, Fixture>;
}
async function signIn(page: import('@playwright/test').Page, fixture: Fixture) {
  await page.goto(fixture.url);
  await page.getByLabel('Email').fill(fixture.email);
  await page.getByLabel('Password').fill(fixture.password);
  await page.getByRole('button', { name: /sign in/i }).click();
  await expect(page.getByRole('navigation', { name: 'Main navigation' })).toBeVisible();
}
async function capture(page: import('@playwright/test').Page, filename: string) {
  const directory = process.env.CHINESCAN_BROWSER_SCREENSHOT_DIR;
  if (!directory) throw new Error('Project E2E screenshot directory was not configured.');
  mkdirSync(directory, { recursive: true });
  await page.screenshot({ path: resolve(directory, filename), fullPage: true });
}

async function folderHash(directory: string): Promise<string> {
  const hash = createHash('sha256');
  async function visit(current: string, relative: string) {
    for (const entry of (await readdir(current, { withFileTypes: true })).sort((a, b) => a.name.localeCompare(b.name))) {
      const entryPath = resolve(current, entry.name);
      const entryRelative = relative ? `${relative}/${entry.name}` : entry.name;
      if (entry.isDirectory()) {
        hash.update(`directory:${entryRelative}\0`);
        await visit(entryPath, entryRelative);
      } else if (entry.isFile()) {
        hash.update(`file:${entryRelative}\0`);
        hash.update(await readFile(entryPath));
      } else {
        hash.update(`other:${entryRelative}\0`);
      }
    }
  }
  await visit(directory, '');
  return hash.digest('hex');
}

test('add project, assess code, create linked case and remove record without touching files', async ({ page }) => {
  const fixture = fixtures().standard;
  const projectFolder = process.env.CHINESCAN_BROWSER_PROJECT_FIXTURE;
  expect(projectFolder).toBeTruthy();
  const originalFolderHash = await folderHash(projectFolder!);
  await signIn(page, fixture);
  await page.getByRole('button', { name: 'Projects', exact: true }).click();
  await page.getByRole('button', { name: 'Add project' }).click();
  await expect(page.getByRole('dialog', { name: 'Add a local project' })).toBeVisible();
  await capture(page, 'picker.png');
  const rootButton = page.getByRole('button', { name: 'Approved folder 1' }).first();
  await rootButton.click();
  await page.getByRole('button', { name: 'Select this folder' }).last().click();
  await page.getByLabel('Project name').fill('E2E code project');
  await page.getByRole('button', { name: 'Add project' }).last().click();
  await expect(page.getByRole('heading', { name: 'E2E code project' })).toBeVisible();
  await capture(page, 'project-page.png');
  await page.getByRole('button', { name: 'Assess code' }).click();
  const partial = page.getByText('Partial result');
  await expect(partial).toBeVisible({ timeout: 60_000 });
  await capture(page, 'partial-banner.png');
  await expect(page.getByRole('heading', { name: /Persisted findings/ })).toBeVisible();
  const caseLink = page.getByRole('button', { name: 'Create or link case' }).first();
  await expect(caseLink).toBeVisible();
  await caseLink.click();
  await expect(page.getByRole('heading', { name: 'Create a case' })).toBeVisible();
  await page.getByLabel('Case title').fill('E2E linked project case');
  await page.getByRole('button', { name: 'Create case' }).click();
  await expect(page.getByText('Case created and saved.', { exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Projects', exact: true }).click();
  await page.getByRole('row').filter({ hasText: 'E2E code project' }).getByRole('button', { name: 'Open project' }).click();
  await expect(page.getByText('E2E linked project case')).toBeVisible();
  await page.getByRole('button', { name: 'Remove project' }).click();
  await page.getByLabel(/Type E2E code project to confirm/).fill('E2E code project');
  await page.getByRole('button', { name: 'Remove project record' }).click();
  await expect(page.getByRole('row').filter({ hasText: 'E2E code project' })).toHaveCount(0);
  expect(existsSync(resolve(projectFolder!, 'app.py'))).toBe(true);
  expect(existsSync(resolve(projectFolder!, 'worker.py'))).toBe(true);
  expect(await folderHash(projectFolder!)).toBe(originalFolderHash);
});

test('project picker explains the valid empty allowed-roots state', async ({ page }) => {
  await signIn(page, fixtures().emptyRoots);
  await page.getByRole('button', { name: 'Projects', exact: true }).click();
  await page.getByRole('button', { name: 'Add project' }).click();
  await expect(page.getByRole('heading', { name: 'No allowed roots' })).toBeVisible();
  await expect(page.getByText("allowed_roots = ['C:\\src']")).toBeVisible();
});

test('project log suggestions and analysis work twice and removal preserves files', async ({ page }) => {
  const fixture = fixtures().standard;
  const projectFolder = process.env.CHINESCAN_BROWSER_PROJECT_FIXTURE;
  expect(projectFolder).toBeTruthy();
  const originalFolderHash = await folderHash(projectFolder!);
  await signIn(page, fixture);

  for (let run = 1; run <= 2; run += 1) {
    await page.getByRole('button', { name: 'Projects', exact: true }).click();
    await page.getByRole('button', { name: 'Add project' }).click();
    await page.getByRole('button', { name: 'Approved folder 1' }).first().click();
    await page.getByRole('button', { name: 'Select this folder' }).last().click();
    await page.getByLabel('Project name').fill(`E2E log project ${run}`);
    await page.getByRole('button', { name: 'Add project' }).last().click();
    await expect(page.getByRole('heading', { name: `E2E log project ${run}` })).toBeVisible();
    await capture(page, `project-log-locations-${run}.png`);

    await page.getByRole('button', { name: 'Suggest locations' }).click();
    const suggestions = page.getByRole('region', { name: 'Log location suggestions' });
    await expect(suggestions.getByText('logs', { exact: true })).toBeVisible();
    await capture(page, `project-log-suggestions-${run}.png`);
    await suggestions.getByRole('button', { name: 'Confirm' }).first().click();
    await expect(page.getByRole('checkbox', { name: 'logs' })).toBeVisible();
    await page.getByRole('button', { name: 'Analyze logs' }).click();
    await expect(page.getByText('Repeated authentication failures')).toBeVisible({ timeout: 60_000 });
    await capture(page, `project-log-alerts-${run}.png`);

    await page.once('dialog', (dialog) => dialog.accept());
    await page.once('dialog', (dialog) => dialog.accept('logs'));
    await page.getByRole('button', { name: 'Remove', exact: true }).click();
    await expect(page.getByText('No log locations linked yet.')).toBeVisible();
    expect(await folderHash(projectFolder!)).toBe(originalFolderHash);
  }
});
