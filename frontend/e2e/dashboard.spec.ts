import { expect, test, type Download, type Page, type Response } from '@playwright/test';

const urls = JSON.parse(process.env.CHINESCAN_BROWSER_TEST_URLS ?? '{}') as {
  standard?: { url: string; username: string; password: string };
};
const username = urls.standard?.username ?? '';
const password = urls.standard?.password ?? '';
const scanId = 'browser-scan-fixture';

async function signIn(page: Page) {
  await page.goto(urls.standard?.url ?? '/');
  await expect(page.getByRole('heading', { name: 'Welcome back' })).toBeVisible();
  await page.getByLabel('Operator name').fill(username);
  await page.getByLabel('Password').fill(password);
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(page.getByRole('heading', { name: 'Overview' })).toBeVisible();
}

test('production dashboard workflows, redaction, downloads, keyboard, and logout', async ({ page }) => {
  const consoleErrors: string[] = [];
  const unexpectedResponses: Array<{ url: string; status: number }> = [];
  const failedApiResponses: Array<{ path: string; status: number }> = [];
  page.on('console', (message) => {
    if (message.type() === 'error' && !/^Failed to load resource: the server responded with a status of (401|404) /.test(message.text())) {
      consoleErrors.push(message.text());
    }
  });
  page.on('pageerror', (error) => consoleErrors.push(error.message));
  page.on('response', (response: Response) => {
    if (response.url().includes('/api/') && response.status() >= 400) {
      failedApiResponses.push({ path: new URL(response.url()).pathname, status: response.status() });
    }
    if (response.url().includes('/api/') && response.status() >= 500) {
      unexpectedResponses.push({ url: response.url(), status: response.status() });
    }
  });

  await page.goto(urls.standard?.url ?? '/');
  await expect(page.getByRole('heading', { name: 'Welcome back' })).toBeVisible();
  const unauthenticated = await page.request.get(`${urls.standard?.url}/api/overview`);
  expect(unauthenticated.status()).toBe(401);
  const protectedShell = await page.request.get(`${urls.standard?.url}/api/scans`);
  expect(protectedShell.status()).toBe(401);

  await page.getByLabel('Operator name').fill(username);
  await page.getByLabel('Password').fill('invalid-synthetic-password');
  const invalidLoginResponse = page.waitForResponse((response) => response.url().endsWith('/api/auth/login') && response.status() === 401);
  await page.getByRole('button', { name: 'Sign in' }).click();
  await invalidLoginResponse;
  await expect(page.locator('.login-error')).toContainText('Invalid username or password.');
  await page.getByLabel('Password').fill(password);
  const successfulLogin = page.waitForResponse((response) =>
    response.url().endsWith('/api/auth/login') && response.status() === 200,
  );
  await page.getByRole('button', { name: 'Sign in' }).click();
  await successfulLogin;
  await expect(page.getByRole('heading', { name: 'Overview' })).toBeVisible();

  await expect(page.getByText('Synthetic fixture data')).toHaveCount(0);
  await expect(page.getByText('STORED SCANS')).toBeVisible();
  await expect(page.getByText('STORED SCANS').locator('..')).toContainText('1');
  await expect(page.getByText('STORED FINDINGS').locator('..')).toContainText('2');
  await expect(page.getByRole('cell', { name: 'synthetic-python' })).toBeVisible();
  await expect(page.getByText('synthetic-target-that-must-not-leak')).toHaveCount(0);

  await page.getByRole('navigation', { name: 'Main navigation' }).getByRole('button', { name: /^Scans/ }).click();
  await expect(page.getByText(scanId)).toBeVisible();
  await page.getByText(scanId).click();
  await expect(page.getByRole('complementary', { name: 'scan details' })).toBeVisible();
  await expect(page.getByText('Create case from this scan')).toBeVisible();
  await page.getByRole('button', { name: 'Create case from this scan' }).click();

  await expect(page.getByRole('heading', { name: 'Cases' }).first()).toBeVisible();
  const scanInput = page.getByLabel('Persisted scan ID');
  await scanInput.fill('');
  await page.getByRole('button', { name: 'Create case' }).click();
  expect(await scanInput.evaluate((element: HTMLInputElement) => element.checkValidity())).toBe(false);
  await page.getByLabel('Persisted scan ID').fill('missing-synthetic-scan');
  await page.getByRole('button', { name: 'Create case' }).click();
  await expect(page.getByRole('alert')).toContainText('not found');
  await page.getByLabel('Persisted scan ID').fill(scanId);
  await page.getByLabel('Case title').fill('Synthetic browser investigation');
  await page.getByLabel('Description').fill('Synthetic fixture investigation description');
  await page.getByRole('button', { name: 'Create case' }).click();
  await expect(page.getByText('Case created and saved.', { exact: true })).toBeVisible();
  await page.getByRole('button', { name: /Synthetic browser investigation/ }).click();

  const casePanel = page.getByRole('region', { name: 'Case detail' });
  await expect(casePanel.getByText('browser-scan-fixture', { exact: true })).toBeVisible();
  await casePanel.getByLabel('Change status').selectOption('in_progress');
  const statusResponsePromise = page.waitForResponse((response) => response.url().includes('/api/cases/') && response.url().endsWith('/status') && response.status() === 200);
  await casePanel.getByRole('button', { name: 'Update' }).click();
  const statusResponse = await statusResponsePromise;
  expect((await statusResponse.json()).case.status).toBe('in_progress');
  await expect(page.getByText('Case status updated.', { exact: true })).toBeVisible();
  await expect(casePanel.getByLabel('Change status')).toHaveValue('in_progress');

  await casePanel.getByLabel('Record type').selectOption('event');
  await casePanel.getByLabel('Record ID').fill('browser-event-fixture');
  await casePanel.getByRole('button', { name: 'Link record' }).click();
  await expect(page.getByText('Record link saved.', { exact: true })).toBeVisible();
  const firstActivityCount = await casePanel.locator('ol > li').count();
  await casePanel.getByLabel('Record type').selectOption('event');
  await casePanel.getByLabel('Record ID').fill('browser-event-fixture');
  await casePanel.getByRole('button', { name: 'Link record' }).click();
  await expect(page.getByText('Record link saved.', { exact: true })).toBeVisible();
  expect(await casePanel.locator('ol > li').count()).toBe(firstActivityCount);
  await expect(casePanel.getByText('Synthetic high severity fixture')).toBeVisible();

  const htmlNote = '<img src=x onerror="window.__noteExecuted=true"> password=synthetic-note-secret';
  await casePanel.getByLabel('Append analyst note').fill(htmlNote);
  await casePanel.getByRole('button', { name: 'Add note' }).click();
  await expect(page.getByText('Note appended.', { exact: true })).toBeVisible();
  await expect(casePanel.locator('article.case-note')).toContainText('<img src=x');
  expect(await page.evaluate(() => (window as Window & { __noteExecuted?: boolean }).__noteExecuted)).toBeUndefined();
  await expect(casePanel.locator('article.case-note img')).toHaveCount(0);
  await expect(casePanel.getByText('created', { exact: false }).first()).toBeVisible();
  await expect(casePanel.getByText('status changed', { exact: false }).first()).toBeVisible();
  await expect(casePanel.getByText('Linked event record browser-event-fixture.')).toBeVisible();
  await expect(casePanel.getByText('Added analyst note')).toBeVisible();
  const timelineAfterNote = await casePanel.locator('ol > li').count();
  expect(timelineAfterNote).toBe(firstActivityCount + 1);

  await page.reload();
  await expect(page.getByRole('heading', { name: 'Overview' })).toBeVisible();
  await page.getByRole('navigation', { name: 'Main navigation' }).getByRole('button', { name: 'Cases', exact: true }).click();
  await page.getByRole('button', { name: /Synthetic browser investigation/ }).click();
  const reloadedCase = page.getByRole('region', { name: 'Case detail' });
  await expect(reloadedCase.locator('article.case-note')).toContainText('<img src=x');
  await expect(reloadedCase.getByLabel('Change status')).toHaveValue('in_progress');
  await expect(reloadedCase.getByText('browser-finding-high')).toBeVisible();
  await expect(reloadedCase.locator('ol > li')).toHaveCount(timelineAfterNote);

  const downloads: Record<string, Download> = {};
  for (const format of ['json', 'markdown', 'html']) {
    const reportLink = reloadedCase.locator('.report-actions').first().getByRole('link', { name: format.toUpperCase(), exact: true });
    const href = await reportLink.getAttribute('href');
    expect(href).toBeTruthy();
    const reportResponse = await page.request.get(`${urls.standard?.url}${href}`);
    expect(reportResponse.headers()['content-disposition']).toContain('attachment;');
    const [download] = await Promise.all([
      page.waitForEvent('download'),
      reportLink.click(),
    ]);
    downloads[format] = download;
    expect(download.suggestedFilename()).toBe(`case-report.${format}`);
    const path = await download.path();
    expect(path).toBeTruthy();
    const { readFile } = await import('node:fs/promises');
    const report = await readFile(path!, 'utf8');
    expect(report).toContain('Synthetic browser investigation');
    expect(report).not.toContain('synthetic-note-secret');
    if (format === 'json') expect(report).toContain('browser-finding-high');
    if (format === 'markdown') expect(report).toContain('Synthetic fixture investigation description');
    if (format === 'html') {
      expect(report).toContain('&lt;img');
      expect(download.suggestedFilename()).toMatch(/\.html$/);
    }
  }
  expect(Object.keys(downloads)).toHaveLength(3);

  await page.getByRole('button', { name: 'Sign out' }).click();
  await expect(page.getByRole('heading', { name: 'Welcome back' })).toBeVisible();
  for (const endpoint of ['/api/overview', '/api/scans', '/api/cases/synthetic', '/api/findings']) {
    const response = await page.request.get(`${urls.standard?.url}${endpoint}`);
    expect(response.status()).toBe(401);
  }
  await page.setViewportSize({ width: 390, height: 844 });
  await expect(page.getByRole('heading', { name: 'Welcome back' })).toBeVisible();
  await page.keyboard.press('Tab');
  await expect(page.locator(':focus')).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBeTruthy();
  expect(consoleErrors).toEqual([]);
  expect(unexpectedResponses).toEqual([]);
  expect(failedApiResponses).toEqual([
    { path: '/api/auth/session', status: 401 },
    { path: '/api/auth/login', status: 401 },
    { path: '/api/cases', status: 404 },
  ]);
});

test('approved project assessment persists findings and creates a case across refresh', async ({ page }) => {
  await signIn(page);
  await page.getByRole('button', { name: /Code assessments/ }).click();
  await page.getByLabel('Approved project').selectOption('browser-fixture');
  await page.getByRole('button', { name: 'Start assessment' }).click();
  const jobRow = page.getByRole('row').filter({ hasText: 'Browser fixture' });
  await expect(jobRow).toContainText('succeeded', { timeout: 15_000 });
  await jobRow.getByRole('button', { name: /Open scan findings/ }).click();
  await expect(page.getByRole('heading', { name: 'Scan details' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Persisted findings' })).toBeVisible();
  await page.getByRole('button', { name: /Create case from this scan/ }).click();
  await expect(page.getByLabel('Persisted scan ID')).not.toHaveValue('');
  await page.getByLabel('Case title').fill('Browser accepted local assessment');
  await page.getByRole('button', { name: 'Create case' }).click();
  await expect(page.getByText('Case created and saved.')).toBeVisible();
  await page.reload();
  await expect(page.getByRole('heading', { name: 'Overview' })).toBeVisible();
  await page.getByRole('button', { name: /Code assessments/ }).click();
  await expect(page.getByRole('row').filter({ hasText: 'Browser fixture' })).toContainText('succeeded');
  await page.getByRole('button', { name: 'Cases', exact: true }).click();
  await expect(page.getByRole('button', { name: /Browser accepted local assessment/ })).toBeVisible();
});

test('finding detail shows fixture data as text and preserves keyboard navigation', async ({ page }) => {
  await signIn(page);
  await page.keyboard.press('Tab');
  await expect(page.locator(':focus')).toBeVisible();
  await page.getByRole('navigation', { name: 'Main navigation' }).getByRole('button', { name: 'Findings', exact: true }).click();
  await expect(page.getByText('Synthetic high severity fixture')).toBeVisible();
  await page.getByText('Synthetic high severity fixture').click();
  await expect(page.getByRole('complementary', { name: 'finding details' })).toBeVisible();
  await expect(page.getByText('synthetic password=fixture-secret-value')).toHaveCount(0);
  await expect(page.locator('svg[onload], img[onerror]')).toHaveCount(0);
});
