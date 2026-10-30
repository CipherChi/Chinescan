import { expect, test } from '@playwright/test';
import { spawnSync } from 'node:child_process';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const urls = JSON.parse(process.env.CHINESCAN_BROWSER_TEST_URLS ?? '{}') as {
  standard?: { url: string };
  signup?: { url: string; email: string; password: string; credentialFile: string };
};
const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../..');

test('signup route explains that the single operator is already configured', async ({ page }) => {
  await page.goto(new URL('/signup', urls.standard?.url ?? 'http://127.0.0.1:5173').toString());
  await expect(page.getByRole('heading', { name: 'Operator account already exists' })).toBeVisible();
  await expect(page.getByText(/supports one local operator account/i)).toBeVisible();
});

test('operator can sign up, reset password locally, and access the authenticated dashboard', async ({ page }) => {
  const fixture = urls.signup;
  await page.goto(fixture?.url ?? '/');
  await page.getByRole('button', { name: 'Create operator account' }).click();
  await expect(page.getByRole('heading', { name: 'Create operator account' })).toBeVisible();
  await page.getByLabel('Email').fill(fixture?.email ?? '');
  await page.getByLabel('Password', { exact: true }).fill(fixture?.password ?? '');
  await page.getByLabel('Confirm password').fill(fixture?.password ?? '');
  await page.getByRole('button', { name: 'Create account' }).click();
  await expect(page.getByRole('heading', { name: 'Overview' })).toBeVisible();
  await page.getByRole('button', { name: 'Sign out' }).click();
  await page.getByRole('button', { name: 'Forgot password?' }).click();
  await page.getByLabel('Email').fill(fixture?.email ?? '');
  await page.getByRole('button', { name: 'Continue' }).click();
  await expect(page.getByRole('heading', { name: 'Continue recovery locally' })).toBeVisible();

  const tokenResult = spawnSync(
    'uv',
    [
      'run', 'chinescan', 'web', 'reset-password', '--email', fixture?.email ?? '', '--issue-link',
      '--credential-file', fixture?.credentialFile ?? '',
    ],
    { cwd: repoRoot, encoding: 'utf8' },
  );
  if (tokenResult.error || tokenResult.status !== 0) {
    throw new Error('Local synthetic reset-token fixture failed.');
  }
  const resetUrl = tokenResult.stdout.trim().split(/\r?\n/).at(-1) ?? '';
  const token = new URL(resetUrl).searchParams.get('token') ?? '';
  await page.getByRole('button', { name: 'Enter reset token' }).click();
  await page.getByLabel('Email').fill(fixture?.email ?? '');
  await page.getByLabel('Reset token').fill(token);
  await page.getByLabel('New password').fill('browser-new-synthetic-password-987');
  await page.getByLabel('Confirm password').fill('browser-new-synthetic-password-987');
  await page.getByRole('button', { name: 'Reset password' }).click();
  await expect(page.getByText('Password reset. You can now sign in with the new password.')).toBeVisible();
  await page.getByRole('button', { name: 'Back to sign in' }).click();
  await page.getByLabel('Email').fill(fixture?.email ?? '');
  await page.getByLabel('Password').fill('browser-new-synthetic-password-987');
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(page.getByRole('heading', { name: 'Overview' })).toBeVisible();
});
