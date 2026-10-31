import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { setCsrfToken } from '../api';
import { ProjectsWorkspace } from './ProjectsWorkspace';

const roots = [{ directory_id: 'root-id', name: 'approved', selectable: true }];
const page = { directory_id: 'root-id', name: 'approved', selectable: true, breadcrumbs: [roots[0]], items: [{ directory_id: 'child-id', name: 'source', selectable: true }], next_cursor: 'next', truncated: false };
function reply(value: unknown, status = 200) { return Promise.resolve(new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } })); }

describe('projects workspace', () => {
  beforeEach(() => { vi.restoreAllMocks(); setCsrfToken('csrf'); });

  it('shows the no-roots guidance and opens an accessible folder picker', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => String(input).startsWith('/api/fs/roots') ? reply({ items: [] }) : reply([]));
    render(<ProjectsWorkspace onUnauthorized={vi.fn()} onOpenScan={vi.fn()} onCreateCase={vi.fn()} />);
    fireEvent.click(await screen.findByRole('button', { name: 'Add project' }));
    expect(await screen.findByRole('heading', { name: 'No allowed roots' })).toBeInTheDocument();
    expect(screen.getByText("allowed_roots = ['C:\\src']")).toBeInTheDocument();
    const dialog = screen.getByRole('dialog', { name: 'Add a local project' });
    expect(dialog).toBeInTheDocument();
    const close = within(dialog).getByRole('button', { name: 'Close folder picker' });
    await waitFor(() => expect(document.activeElement).toBe(close));
    fireEvent.keyDown(document, { key: 'Tab', shiftKey: true });
    expect(document.activeElement).toBe(close);
    fireEvent.keyDown(document, { key: 'Escape' });
    expect(screen.queryByRole('dialog', { name: 'Add a local project' })).not.toBeInTheDocument();
  });

  it('browses folders, paginates, and creates a project from a selected directory', async () => {
    let listCount = 0;
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const path = String(input);
      if (path === '/api/projects' && init?.method === 'POST') return reply({ project_id: 'p1', name: 'Example', kind: 'local', configured_by: 'ui', origin_label: 'This device', created_at: '', last_scan: null, last_scan_refs: [] }, 201);
      if (path === '/api/projects') return reply([]);
      if (path.startsWith('/api/projects/p1')) return reply({ project_id: 'p1', name: 'Example', kind: 'local', configured_by: 'ui', origin_label: 'This device', created_at: '', last_scan: null, last_scan_refs: [], recent_jobs: [], findings_count: 0, findings: [], linked_cases: [], recent_scans: [] });
      if (path.startsWith('/api/fs/roots')) return reply({ items: roots });
      if (path.startsWith('/api/fs/list')) {
        listCount += 1;
        return reply(listCount === 1 ? page : { ...page, items: [{ directory_id: 'second-child', name: 'tests', selectable: true }], next_cursor: null });
      }
      return reply({});
    });
    render(<ProjectsWorkspace onUnauthorized={vi.fn()} onOpenScan={vi.fn()} onCreateCase={vi.fn()} />);
    fireEvent.click(await screen.findByRole('button', { name: 'Add project' }));
    fireEvent.click(await screen.findByRole('button', { name: 'approved' }));
    fireEvent.click(await screen.findByRole('button', { name: 'Load more' }));
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith(expect.stringContaining('cursor=next'), expect.anything()));
    fireEvent.click(screen.getAllByRole('button', { name: 'Select this folder' })[1]);
    fireEvent.change(screen.getByLabelText('Project name'), { target: { value: 'Example' } });
    fireEvent.click(screen.getAllByRole('button', { name: 'Add project' }).at(-1)!);
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith('/api/projects', expect.objectContaining({ method: 'POST' })));
  });

  it('shows persisted partial counts and requires typed removal confirmation', async () => {
    const project = { project_id: 'p1', name: 'Example', kind: 'local', configured_by: 'ui', origin_label: 'This device', created_at: '', last_scan: 'scan1', last_scan_refs: ['scan1'] };
    const detail = { ...project, recent_jobs: [], findings_count: 0, findings: [], linked_cases: [], recent_scans: [{ scan_id: 'scan1', status: 'partial', finding_count: 1, skipped_counts: { max_files: 2 } }] };
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const path = String(input);
      if (path === '/api/projects') return reply([project]);
      if (path === '/api/projects/p1' && init?.method !== 'DELETE') return reply(detail);
      if (path === '/api/projects/p1' && init?.method === 'DELETE') return reply({ status: 'removed' });
      return reply({});
    });
    render(<ProjectsWorkspace onUnauthorized={vi.fn()} onOpenScan={vi.fn()} onCreateCase={vi.fn()} />);
    fireEvent.click(await screen.findByRole('button', { name: 'Open project' }));
    expect(await screen.findByRole('status')).toHaveTextContent('max_files: 2');
    expect(screen.getByText('No log locations linked yet.')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Remove project' }));
    expect(screen.getByRole('dialog', { name: 'Remove Example?' })).toHaveTextContent('Files in the folder are never touched.');
    const button = within(screen.getByRole('dialog')).getByRole('button', { name: 'Remove project record' });
    expect(button).toBeDisabled();
    fireEvent.change(screen.getByLabelText(/Type Example to confirm/), { target: { value: 'Example' } });
    expect(button).toBeEnabled();
  });

  it('shows bounded suggestions and marks EVTX as unsupported', async () => {
    const project = { project_id: 'p1', name: 'Example', kind: 'local', configured_by: 'ui', origin_label: 'This device', created_at: '', last_scan: null, last_scan_refs: [] };
    const detail = { ...project, recent_jobs: [], findings_count: 0, findings: [], linked_cases: [], recent_scans: [], log_locations: [], log_alerts: [], log_events: [], log_timeline: [] };
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const path = String(input);
      if (path === '/api/projects') return reply([project]);
      if (path === '/api/projects/p1' && init?.method !== 'POST') return reply(detail);
      if (path === '/api/log/jobs?limit=50&offset=0') return reply({ items: [], total: 0, limit: 50, offset: 0 });
      if (path === '/api/projects/p1/log-suggestions') return reply({ partial: true, visited: 5000, items: [{ suggestion_id: 'suggestion-123456789', label: 'archive.evtx', unsupported: true }] });
      return reply({});
    });
    render(<ProjectsWorkspace onUnauthorized={vi.fn()} onOpenScan={vi.fn()} onCreateCase={vi.fn()} />);
    fireEvent.click(await screen.findByRole('button', { name: 'Open project' }));
    fireEvent.click(await screen.findByRole('button', { name: 'Suggest locations' }));
    expect(await screen.findByRole('status')).toHaveTextContent(/partial/i);
    expect(screen.getByText('Unsupported format')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Confirm' })).not.toBeInTheDocument();
  });
});
