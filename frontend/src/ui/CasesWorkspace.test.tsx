import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { setCsrfToken } from '../api';
import type { CaseData } from '../types';
import { CasesWorkspace } from './CasesWorkspace';

const record: CaseData = {
  case: { case_id: 'case-1', title: 'Local triage', description: 'Review scan', status: 'open', severity: 'high', created_at: '2026-10-26T10:00:00Z', updated_at: '2026-10-26T10:00:00Z', scan_ids: ['scan-1'], notes: [] },
  links: [], records: [{ record_type: 'scan', record_id: 'scan-1', source: 'builtin', title: '', severity: null }],
  timeline: [{ item_id: 'activity-1', category: 'case_activity', description: 'Case created from scan scan-1.', event_occurred_at: null, case_activity_at: '2026-10-26T10:00:00Z' }],
  warnings: [], counts_by_severity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
};
const unauthorized = vi.fn();
function response(body: unknown, status = 200) { return Promise.resolve(new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })); }

describe('case workspace', () => {
  beforeEach(() => { vi.restoreAllMocks(); unauthorized.mockReset(); setCsrfToken('csrf-test'); });

  it('renders a real case, creates, links, appends notes, changes status, and exposes report downloads', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const path = String(input);
      if (path.startsWith('/api/cases?')) return response({ items: [{ ...record.case, note_count: 0, linked_record_count: 1 }], total: 1, limit: 20, offset: 0 });
      if (path === '/api/cases/case-1') return response(record);
      if (path === '/api/cases') return response(record, 201);
      if (path.includes('/notes') || path.includes('/status') || path.includes('/links')) return response(record);
      throw new Error(`Unexpected call: ${path} ${init?.method}`);
    });
    render(<CasesWorkspace onUnauthorized={unauthorized}/>);
    expect(await screen.findByRole('button', { name: /local triage/i })).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: /local triage/i }));
    expect(await screen.findByText('Case created from scan scan-1.')).toBeInTheDocument();
    expect(screen.getAllByRole('link', { name: 'HTML' })[0]).toHaveAttribute('download');
    fireEvent.change(screen.getByLabelText('Persisted scan ID'), { target: { value: 'scan-1' } });
    fireEvent.click(screen.getByRole('button', { name: 'Create case' }));
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith('/api/cases', expect.objectContaining({ method: 'POST' })));
    expect(await screen.findByRole('status')).toHaveTextContent('Case created and saved.');
    fireEvent.change(screen.getByLabelText('Append analyst note'), { target: { value: '<b>typed note</b>' } });
    fireEvent.click(screen.getByRole('button', { name: 'Add note' }));
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith('/api/cases/case-1/notes', expect.anything()));
    fireEvent.change(screen.getByLabelText('Change status'), { target: { value: 'in_progress' } });
    fireEvent.click(screen.getByRole('button', { name: 'Update' }));
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith('/api/cases/case-1/status', expect.anything()));
    const statusCall = fetchMock.mock.calls.find(([path]) => String(path) === '/api/cases/case-1/status');
    expect(String(statusCall?.[1]?.body)).toContain('in_progress');
    fireEvent.change(screen.getByLabelText('Record ID'), { target: { value: 'finding-1' } });
    fireEvent.click(screen.getByRole('button', { name: 'Link record' }));
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith('/api/cases/case-1/links', expect.anything()));
  });

  it('shows loading, empty, failed-request, and native validation states', async () => {
    let finish!: (value: Response) => void;
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => new Promise((resolve) => { finish = resolve; }));
    render(<CasesWorkspace onUnauthorized={unauthorized}/>);
    expect(screen.getByRole('status')).toHaveTextContent('Loading cases');
    finish(new Response(JSON.stringify({ items: [], total: 0, limit: 20, offset: 0 }), { status: 200 }));
    expect(await screen.findByText('No cases yet')).toBeInTheDocument();
    expect(screen.getByLabelText('Persisted scan ID')).toBeRequired();
    vi.restoreAllMocks();
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({ detail: 'Storage failed.' }), { status: 500 }));
    render(<CasesWorkspace onUnauthorized={unauthorized}/>);
    expect(await screen.findByRole('alert')).toHaveTextContent('Storage failed.');
  });

  it('returns to permission-denied state when session expires during a mutation', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const path = String(input);
      if (path.startsWith('/api/cases?')) return response({ items: [{ ...record.case, note_count: 0, linked_record_count: 1 }], total: 1, limit: 20, offset: 0 });
      if (path === '/api/cases/case-1') return response(record);
      if (path.includes('/notes')) return response({ detail: 'Authentication required.' }, 401);
      throw new Error(path);
    });
    render(<CasesWorkspace onUnauthorized={unauthorized}/>);
    fireEvent.click(await screen.findByRole('button', { name: /local triage/i }));
    fireEvent.change(await screen.findByLabelText('Append analyst note'), { target: { value: 'note' } });
    fireEvent.click(screen.getByRole('button', { name: 'Add note' }));
    await waitFor(() => expect(unauthorized).toHaveBeenCalledOnce());
  });
});
