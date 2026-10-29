import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { App } from './App';

function json(body: unknown, status = 200) {
  return Promise.resolve(new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  }));
}

describe('dashboard authentication and overview', () => {
  beforeEach(() => { vi.restoreAllMocks(); });

  it('shows sign in after an unauthorized session check and loads stored metrics after login', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const path = String(input);
      if (path === '/api/auth/session') return json({ detail: 'Authentication required.' }, 401);
      if (path === '/api/auth/login') return json({ username: 'analyst', csrf_token: 'csrf-value' });
      if (path === '/api/overview') return json({
        scan_count: 3,
        finding_count: 7,
        findings_by_severity: { critical: 1, high: 2, medium: 2, low: 1, info: 1 },
        recent_scans: [],
      });
      if (path.startsWith('/api/findings?')) return json({ items: [], total: 0, limit: 20, offset: 0 });
      throw new Error(`Unexpected API call: ${path} ${init?.method ?? 'GET'}`);
    });

    render(<App/>);
    expect(await screen.findByRole('heading', { name: 'Welcome back' })).toBeInTheDocument();
    expect(screen.queryByRole('link', { name: /create account|register|sign up/i })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /create account|register|sign up/i })).not.toBeInTheDocument();
    expect(screen.queryByText('STORED SCANS')).not.toBeInTheDocument();
    fireEvent.change(screen.getByLabelText('Operator name'), { target: { value: 'analyst' } });
    fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'safe local password' } });
    fireEvent.click(screen.getByRole('button', { name: /sign in/i }));

    expect(await screen.findByRole('heading', { name: 'Overview' })).toBeInTheDocument();
    expect(await screen.findByText('3', { selector: 'strong' })).toBeInTheDocument();
    expect(await screen.findByText('7', { selector: 'strong' })).toBeInTheDocument();
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith('/api/overview', expect.anything()));
  });

  it('renders an honest empty state when persisted scans are absent', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const path = String(input);
      if (path === '/api/auth/session') return json({ username: 'analyst', csrf_token: 'csrf-value' });
      if (path === '/api/overview') return json({
        scan_count: 0, finding_count: 0,
        findings_by_severity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
        recent_scans: [],
      });
      if (path.startsWith('/api/findings?')) return json({ items: [], total: 0, limit: 20, offset: 0 });
      throw new Error(`Unexpected API call: ${path}`);
    });
    render(<App/>);
    expect(await screen.findByText('No scans yet')).toBeInTheDocument();
    fireEvent.click(within(screen.getByRole('navigation', { name: 'Main navigation' })).getByRole('button', { name: /findings/i }));
    expect(await screen.findByText('No persisted finding records')).toBeInTheDocument();
  });
});
