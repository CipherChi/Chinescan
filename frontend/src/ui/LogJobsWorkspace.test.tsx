import { render, screen } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { setCsrfToken } from '../api';
import { LogJobsWorkspace } from './LogJobsWorkspace';

const unauthorized = vi.fn();
function response(body: unknown, status = 200) { return Promise.resolve(new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })); }

describe('log jobs workspace registry status', () => {
  beforeEach(() => { vi.restoreAllMocks(); unauthorized.mockReset(); setCsrfToken('csrf-test'); });

  it.each([
    ['missing', 'Registry file not found', 'Registry file not found.'],
    ['unreadable', 'Registry file is unreadable', 'Registry file could not be read.'],
    ['invalid', 'Registry file is invalid', 'Registry TOML or source entries are invalid.'],
    ['empty', 'Registry is valid but has no sources', 'Registry is valid but contains no sources.'],
    ['ok', 'No approved log sources', 'Registry loaded successfully.'],
  ])('shows the %s registry state', async (status, heading, reason) => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const path = String(input);
      if (path === '/api/log/sources') return response([]);
      if (path === '/api/log/sources/status') return response({ status, reason });
      if (path.startsWith('/api/log/jobs')) return response({ items: [], total: 0, limit: 50, offset: 0 });
      if (path.startsWith('/api/cases?')) return response({ items: [], total: 0, limit: 20, offset: 0 });
      throw new Error(`Unexpected call: ${path}`);
    });
    render(<LogJobsWorkspace onUnauthorized={unauthorized}/>);
    expect(await screen.findByRole('heading', { name: heading })).toBeInTheDocument();
    expect(screen.getByText(reason)).toBeInTheDocument();
  });
});
