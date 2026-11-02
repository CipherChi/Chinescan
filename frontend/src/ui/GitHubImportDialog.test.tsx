import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { setCsrfToken } from '../api';
import type { GitHubImportCapabilities, GitHubImportJob, GitHubImportPreview } from '../types';
import { GitHubImportDialog } from './GitHubImportDialog';

function makeCapabilities(overrides: Partial<GitHubImportCapabilities> = {}): GitHubImportCapabilities {
  return { enabled: true, git_available: true, max_bytes: 524288000, max_files: 50000, max_projects: 20, timeout_seconds: 120, ...overrides };
}

function makePreview(overrides: Partial<GitHubImportPreview> = {}): GitHubImportPreview {
  return { preview_id: 'preview-fixture', url: 'https://github.com/example/repo', ref: null, fetch_depth: 1, submodules: false, lfs: false, max_bytes: 524288000, max_files: 50000, max_projects: 20, timeout_seconds: 120, blob_limit_bytes: 16777216, expires_in_seconds: 600, git_metadata_allowance_bytes: 8388608, ...overrides };
}

function makeJob(overrides: Partial<GitHubImportJob> = {}): GitHubImportJob {
  return { job_id: 'job-fixture', status: 'queued', phase: 'queued', error_code: null, message: null, commit_sha: null, fetched_at: null, file_count: null, total_bytes: null, project_id: null, ...overrides };
}

function response(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } });
}

async function flushPromises(): Promise<void> {
  await act(async () => { await Promise.resolve(); await Promise.resolve(); });
}

function apiFetch(
  capabilities: GitHubImportCapabilities,
  jobReplies: GitHubImportJob[] = [],
  importFailure?: GitHubImportJob,
) {
  let jobIndex = 0;
  return vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
    const path = String(input);
    if (path === '/api/github/status') return response(capabilities);
    if (path === '/api/projects') return response([]);
    if (path === '/api/github/previews') return response(makePreview());
    if (path === '/api/github/imports' && init?.method === 'POST') return response(importFailure ?? makeJob());
    if (path === '/api/github/imports/job-fixture/cancel') return response(makeJob({ status: 'cancelled' }));
    if (path === '/api/github/imports/job-fixture') return response(jobReplies[Math.min(jobIndex++, jobReplies.length - 1)] ?? makeJob());
    return response({ detail: { code: 'unknown', message: 'Unexpected test request.' } }, 404);
  });
}

describe('GitHub import dialog', () => {
  afterEach(() => { vi.restoreAllMocks(); vi.useRealTimers(); setCsrfToken(''); });

  it('shows disabled instructions without enabling the setting', async () => {
    apiFetch(makeCapabilities({ enabled: false }));
    render(<GitHubImportDialog onClose={vi.fn()} onUnauthorized={vi.fn()} onFinished={vi.fn()} />);
    expect(await screen.findByRole('heading', { name: 'GitHub import is disabled' })).toBeInTheDocument();
    expect(screen.getByText(/github_import_enabled = true/)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Preview' })).not.toBeInTheDocument();
  });

  it('shows the dedicated path-too-long state and safe remediation', async () => {
    apiFetch(makeCapabilities(), [], makeJob({
      status: 'failed',
      phase: 'failed',
      error_code: 'path_too_long',
      message: 'The import location path is too long; use a shorter managed import directory.',
    }));
    render(<GitHubImportDialog onClose={vi.fn()} onUnauthorized={vi.fn()} onFinished={vi.fn()} />);
    fireEvent.change(await screen.findByLabelText('Public GitHub repository URL'), { target: { value: 'https://github.com/example/repo' } });
    fireEvent.click(screen.getByRole('button', { name: 'Preview' }));
    await screen.findByRole('heading', { name: 'Review import' });
    fireEvent.click(screen.getByRole('button', { name: /^Import$/ }));
    expect(await screen.findByRole('heading', { name: 'Import location path is too long' })).toBeInTheDocument();
    expect(screen.getByText(/use a shorter managed import directory/)).toBeInTheDocument();
  });

  it('previews before import, polls to success, announces completion and refreshes projects', async () => {
    vi.useFakeTimers();
    apiFetch(makeCapabilities(), [makeJob({ status: 'running', phase: 'fetching' }), makeJob({ status: 'succeeded', phase: 'succeeded', project_id: 'project-fixture', commit_sha: 'a'.repeat(40) })]);
    const onFinished = vi.fn();
    render(<GitHubImportDialog onClose={vi.fn()} onUnauthorized={vi.fn()} onFinished={onFinished} />);
    await flushPromises();
    fireEvent.change(screen.getByLabelText('Public GitHub repository URL'), { target: { value: 'https://github.com/example/repo' } });
    fireEvent.click(screen.getByRole('button', { name: 'Preview' }));
    await flushPromises();
    expect(screen.getByRole('heading', { name: 'Review import' })).toBeInTheDocument();
    expect(screen.getByText(/submodules and Git LFS disabled/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: /^Import$/ }));
    await flushPromises();
    expect(screen.getByText('Phase: queued')).toBeInTheDocument();
    await act(async () => { await vi.advanceTimersByTimeAsync(800); });
    expect(screen.getByText('Phase: fetching')).toBeInTheDocument();
    await act(async () => { await vi.advanceTimersByTimeAsync(1600); });
    expect(screen.getByText(/Project created. Commit/)).toBeInTheDocument();
    expect(screen.getByRole('status')).toHaveTextContent(/import completed/i);
    expect(onFinished).toHaveBeenCalledTimes(1);
  });

  it('requests cancellation and traps focus in the dialog', async () => {
    apiFetch(makeCapabilities());
    render(<GitHubImportDialog onClose={vi.fn()} onUnauthorized={vi.fn()} onFinished={vi.fn()} />);
    const dialog = await screen.findByRole('dialog', { name: 'Import from GitHub' });
    const url = await within(dialog).findByLabelText('Public GitHub repository URL');
    url.focus();
    fireEvent.keyDown(document, { key: 'Tab', shiftKey: true });
    expect(document.activeElement).toBe(within(dialog).getByRole('button', { name: 'Close' }));
    fireEvent.change(url, { target: { value: 'https://github.com/example/repo' } });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Preview' }));
    await waitFor(() => expect(screen.getByRole('heading', { name: 'Review import' })).toBeInTheDocument());
    fireEvent.click(screen.getByRole('button', { name: /^Import$/ }));
    await screen.findByText('Phase: queued');
    fireEvent.click(screen.getByRole('button', { name: 'Cancel import' }));
    await waitFor(() => expect(screen.getByRole('heading', { name: 'Import cancelled' })).toBeInTheDocument());
  });
});
