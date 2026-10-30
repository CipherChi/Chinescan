import type { CaseData, CaseSummary, CodeJob, CodeProject, Finding, Overview, Page, Scan, LogSource, LogSourceRegistryStatus, LogJob, LogAlert, LogEvent, LogTimeline, MalwareAnalysis, MalwareCapability, MalwareJob, MalwareSample } from './types';

let csrfToken = '';
export function setCsrfToken(token: string) { csrfToken = token; }

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const headers = new Headers(init?.headers);
  if (init?.body) headers.set('Content-Type', 'application/json');
  if (init?.method && init.method !== 'GET' && csrfToken) headers.set('X-CSRF-Token', csrfToken);
  const response = await fetch(path, { ...init, headers, credentials: 'same-origin' });
  if (response.status === 401) {
    if (path === '/api/auth/login') {
      const detail = await response.json().catch(() => ({}));
      throw new Error(typeof detail.detail === 'string' ? detail.detail : 'Invalid email or password.');
    }
    throw new UnauthorizedError();
  }
  if (!response.ok) {
    const detail = await response.json().catch(() => ({}));
    const message = typeof detail.detail === 'string' ? detail.detail : 'The request could not be completed.';
    throw new Error(message);
  }
  return response.json() as Promise<T>;
}

export class UnauthorizedError extends Error {}
export const api = {
  session: () => request<{ authenticated: boolean; email_masked: string | null; signup_available: boolean }>('/api/auth/session'),
  csrf: () => request<{ csrf_token: string }>('/api/auth/csrf'),
  login: (email: string, password: string) => request<{ email: string; csrf_token: string }>('/api/auth/login', {
    method: 'POST', body: JSON.stringify({ email, password }),
  }),
  signup: (email: string, password: string) => request<{ email: string; csrf_token: string }>('/api/auth/signup', {
    method: 'POST', body: JSON.stringify({ email, password }),
  }),
  forgotPassword: (email: string) => request<{ status: string }>('/api/auth/forgot-password', { method: 'POST', body: JSON.stringify({ email }) }),
  resetPassword: (email: string, token: string, password: string) => request<{ status: string }>('/api/auth/reset-password', { method: 'POST', body: JSON.stringify({ email, token, password }) }),
  logout: () => request<{ status: string }>('/api/auth/logout', { method: 'POST' }),
  overview: () => request<Overview>('/api/overview'),
  scans: (offset: number, status: string) => {
    const query = new URLSearchParams({ limit: '20', offset: String(offset), sort: 'started_at', order: 'desc' });
    if (status) query.set('status', status);
    return request<Page<Scan>>(`/api/scans?${query}`);
  },
  scan: (id: string) => request<Scan & { finding_ids: string[] }>(`/api/scans/${encodeURIComponent(id)}`),
  findings: (offset: number, severity: string) => {
    const query = new URLSearchParams({ limit: '20', offset: String(offset), sort: 'severity', order: 'desc' });
    if (severity) query.set('severity', severity);
    return request<Page<Finding>>(`/api/findings?${query}`);
  },
  finding: (id: string) => request<Finding>(`/api/findings/${encodeURIComponent(id)}`),
  codeProjects: () => request<CodeProject[]>('/api/code/projects'),
  codeJobs: () => request<Page<CodeJob>>('/api/code/jobs?limit=50&offset=0'),
  codeJob: (id: string) => request<CodeJob>(`/api/code/jobs/${encodeURIComponent(id)}`),
  startCodeJob: (project_id: string) => request<CodeJob>('/api/code/jobs', { method: 'POST', body: JSON.stringify({ project_id }) }),
  malwareCapability: () => request<MalwareCapability>('/api/malware/capability'),
  malwareSamples: () => request<MalwareSample[]>('/api/malware/samples'),
  malwareJobs: () => request<Page<MalwareJob>>('/api/malware/jobs?limit=50&offset=0'),
  startMalwareRegistryJob: (registry_id: string) => request<MalwareJob>('/api/malware/jobs', { method: 'POST', body: JSON.stringify({ registry_id, profile: 'builtin_static' }) }),
  startManagedMalwareJob: (sample_id: string) => request<MalwareJob>('/api/malware/jobs', { method: 'POST', body: JSON.stringify({ sample_id, profile: 'builtin_static' }) }),
  malwareJob: (id: string) => request<MalwareJob>(`/api/malware/jobs/${encodeURIComponent(id)}`),
  malwareAnalysis: (id: string) => request<MalwareAnalysis>(`/api/malware/analyses/${encodeURIComponent(id)}`),
  logSources: () => request<LogSource[]>('/api/log/sources'),
  logSourcesStatus: () => request<LogSourceRegistryStatus>('/api/log/sources/status'),
  logJobs: () => request<Page<LogJob>>('/api/log/jobs?limit=50&offset=0'),
  startLogJob: (source_id: string) => request<LogJob>('/api/log/jobs', { method: 'POST', body: JSON.stringify({ source_id }) }),
  logAlerts: (scan: string, offset = 0, severity = '') => { const query = new URLSearchParams({ limit: '20', offset: String(offset) }); if (severity) query.set('severity', severity); return request<Page<LogAlert>>(`/api/log/analyses/${encodeURIComponent(scan)}/alerts?${query}`); },
  logAlert: (scan: string, id: string) => request<LogAlert>(`/api/log/analyses/${encodeURIComponent(scan)}/alerts/${encodeURIComponent(id)}`),
  logEvents: (scan: string, offset = 0, source = '') => { const query = new URLSearchParams({ limit: '20', offset: String(offset) }); if (source) query.set('source', source); return request<Page<LogEvent>>(`/api/log/analyses/${encodeURIComponent(scan)}/events?${query}`); },
  logEvent: (scan: string, id: string) => request<LogEvent>(`/api/log/analyses/${encodeURIComponent(scan)}/events/${encodeURIComponent(id)}`),
  logTimeline: (scan: string, offset = 0) => request<Page<LogTimeline>>(`/api/log/analyses/${encodeURIComponent(scan)}/timeline?limit=20&offset=${offset}`),
  cases: (offset = 0, status = '', severity = '') => {
    const query = new URLSearchParams({ limit: '20', offset: String(offset), sort: 'updated_at', order: 'desc' });
    if (status) query.set('status', status); if (severity) query.set('severity', severity);
    return request<Page<CaseSummary>>(`/api/cases?${query}`);
  },
  case: (id: string) => request<CaseData>(`/api/cases/${encodeURIComponent(id)}`),
  createCase: (scan_id: string, title: string, description: string, severity: string) => request<CaseData>('/api/cases', { method: 'POST', body: JSON.stringify({ scan_id, title: title || null, description, severity }) }),
  addCaseNote: (id: string, body: string) => request<CaseData>(`/api/cases/${encodeURIComponent(id)}/notes`, { method: 'POST', body: JSON.stringify({ body }) }),
  updateCaseStatus: (id: string, status: string) => request<CaseData>(`/api/cases/${encodeURIComponent(id)}/status`, { method: 'POST', body: JSON.stringify({ status }) }),
  linkCaseRecord: (id: string, record_type: string, record_id: string) => request<CaseData>(`/api/cases/${encodeURIComponent(id)}/links`, { method: 'POST', body: JSON.stringify({ record_type, record_id }) }),
};
