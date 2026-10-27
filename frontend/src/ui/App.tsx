import { useCallback, useEffect, useState } from 'react';
import { api, setCsrfToken, UnauthorizedError } from '../api';
import type { Finding, Overview, Page, Scan } from '../types';
import { CasesWorkspace } from './CasesWorkspace';
import { CodeJobsWorkspace } from './CodeJobsWorkspace';
import { LogJobsWorkspace } from './LogJobsWorkspace';

type Section = 'overview' | 'scans' | 'findings' | 'cases' | 'jobs' | 'logs';
type Detail = { kind: 'scan'; id: string } | { kind: 'finding'; id: string } | null;

function messageOf(error: unknown) {
  return error instanceof Error ? error.message : 'Something went wrong. Please try again.';
}
function dateOf(value: string | null) {
  if (!value) return 'In progress';
  return new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(value));
}

export function App() {
  const [ready, setReady] = useState(false);
  const [username, setUsername] = useState('');
  const [error, setError] = useState('');
  const [section, setSection] = useState<Section>('overview');
  const [overview, setOverview] = useState<Overview | null>(null);
  const [scanPage, setScanPage] = useState<Page<Scan> | null>(null);
  const [findingPage, setFindingPage] = useState<Page<Finding> | null>(null);
  const [page, setPage] = useState(0);
  const [filter, setFilter] = useState('');
  const [detail, setDetail] = useState<Detail>(null);
  const [detailData, setDetailData] = useState<Scan | Finding | null>(null);
  const [busy, setBusy] = useState(false);
  const [caseScanId, setCaseScanId] = useState('');

  const signOut = useCallback(() => {
    setCsrfToken(''); setUsername(''); setOverview(null); setScanPage(null); setFindingPage(null);
    setDetail(null); setDetailData(null);
  }, []);

  useEffect(() => {
    api.session().then((session) => {
      setUsername(session.username); setCsrfToken(session.csrf_token);
    }).catch((reason: unknown) => {
      if (!(reason instanceof UnauthorizedError)) setError(messageOf(reason));
    }).finally(() => setReady(true));
  }, []);

  const loadSection = useCallback(async (selected: Section, offset = 0, filterValue = '') => {
    if (!username) return;
    setBusy(true); setError('');
    try {
      if (selected === 'overview') setOverview(await api.overview());
      if (selected === 'scans') setScanPage(await api.scans(offset, filterValue));
      if (selected === 'findings') setFindingPage(await api.findings(offset, filterValue));
    } catch (reason) {
      if (reason instanceof UnauthorizedError) signOut();
      else setError(messageOf(reason));
    } finally { setBusy(false); }
  }, [username, signOut]);

  useEffect(() => { if (username) void loadSection(section, page * 20, filter); }, [username, section, page, filter, loadSection]);

  useEffect(() => {
    if (!detail) { setDetailData(null); return; }
    const load = detail.kind === 'scan' ? api.scan(detail.id) : api.finding(detail.id);
    load.then(setDetailData).catch((reason: unknown) => {
      if (reason instanceof UnauthorizedError) signOut(); else setError(messageOf(reason));
    });
  }, [detail, signOut]);

  async function submitLogin(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault(); setBusy(true); setError('');
    const form = new FormData(event.currentTarget);
    try {
      const session = await api.login(String(form.get('username')), String(form.get('password')));
      setCsrfToken(session.csrf_token); setUsername(session.username);
    } catch (reason) { setError(messageOf(reason)); }
    finally { setBusy(false); }
  }

  async function logout() {
    setBusy(true); setError('');
    try { await api.logout(); signOut(); }
    catch (reason) { if (reason instanceof UnauthorizedError) signOut(); else setError(messageOf(reason)); }
    finally { setBusy(false); }
  }

  if (!ready) return <CenteredState title="Connecting to Chinetscan" detail="Checking your local session…" />;
  if (!username) return <Login error={error} busy={busy} onSubmit={submitLogin} onRetry={() => window.location.reload()} />;

  const title = section === 'overview' ? 'Overview' : section === 'scans' ? 'Scan history' : section === 'findings' ? 'Findings' : section === 'cases' ? 'Cases' : section === 'jobs' ? 'Code assessments' : 'Log analysis';
  const nav = (id: Section, label: string, glyph: string) => <button className={`nav-link ${section === id ? 'active' : ''}`} key={id} onClick={() => { setSection(id); setPage(0); setFilter(''); setDetail(null); }}><span className="nav-glyph" aria-hidden="true">{glyph}</span>{label}{id === 'scans' && overview ? <span className="nav-count">{overview.scan_count}</span> : null}</button>;

  return <div className="app-shell">
    <aside className="sidebar">
      <div className="brand"><div className="brand-mark" aria-hidden="true"><span>c</span><i /></div><div><strong>Chinetscan</strong><small>LOCAL ANALYST CONSOLE</small></div></div>
      <div className="nav-caption">WORKSPACE</div>
      <nav aria-label="Main navigation">{nav('overview', 'Overview', '⌂')}{nav('jobs', 'Code assessments', '⌘')}{nav('logs', 'Log analysis', '≋')}{nav('scans', 'Scans', '⌕')}{nav('findings', 'Findings', '◈')}{nav('cases', 'Cases', '▤')}</nav>
      <div className="sidebar-bottom"><div className="local-indicator"><span />LOCAL INSTANCE</div><p>Assessment data stays on this device.</p><div className="profile"><div className="avatar">{username.slice(0, 1).toUpperCase()}</div><div className="profile-name"><strong>{username}</strong><small>Local operator</small></div><button className="icon-button" onClick={logout} disabled={busy} aria-label="Sign out" title="Sign out">↗</button></div></div>
    </aside>
    <main className="main-content">
      <header className="topbar"><div className="breadcrumbs"><span>Workspace</span><b>/</b><strong>{title}</strong></div><div className="topbar-right"><span className="secure-pill"><span>●</span> Loopback secured</span><div className="top-avatar">{username.slice(0, 1).toUpperCase()}</div></div></header>
      <section className="page-content">
        <div className="page-heading"><div><div className="eyebrow">ANALYST WORKSPACE</div><h1>{title}</h1><p>{section === 'overview' ? 'A clear view of your locally stored assessment activity.' : section === 'scans' ? 'Review completed and partial local assessments.' : section === 'findings' ? 'Triage findings from supported local assessments.' : section === 'cases' ? 'Investigate persisted scans with notes, links, timelines, and reports.' : section === 'jobs' ? 'Start and review bounded assessments of operator approved local projects.' : 'Analyze operator-approved local exports with bounded parsing and local detections.'}</p></div>{section !== 'overview' && section !== 'cases' && section !== 'jobs' && section !== 'logs' && <div className="list-controls"><label className="filter-control"><span aria-hidden="true">⌕</span><select aria-label={section === 'scans' ? 'Filter scan status' : 'Filter finding severity'} value={filter} onChange={(event) => { setPage(0); setFilter(event.target.value); }}><option value="">All {section === 'scans' ? 'statuses' : 'severities'}</option>{section === 'scans' ? <><option value="complete">Complete</option><option value="partial">Partial</option></> : <>{['critical','high','medium','low','info'].map((value) => <option key={value} value={value}>{value[0].toUpperCase() + value.slice(1)}</option>)}</>}</select></label></div>}</div>
        {error && <div className="alert-error" role="alert"><span>!</span><div><strong>We couldn’t load this view</strong><p>{error}</p></div><button onClick={() => void loadSection(section, page * 20, filter)}>Retry</button></div>}
        {busy && <div className="loading-line" aria-label="Loading"><span /></div>}
        {section === 'overview' && <OverviewPanel data={overview} onScans={() => setSection('scans')} onFindings={() => setSection('findings')} onOpen={(id) => setDetail({ kind: 'scan', id })} />}
        {section === 'scans' && <ScanTable data={scanPage} page={page} onPage={setPage} onOpen={(id) => setDetail({ kind: 'scan', id })} />}
        {section === 'findings' && <FindingTable data={findingPage} page={page} onPage={setPage} onOpen={(id) => setDetail({ kind: 'finding', id })} />}
        {section === 'jobs' && <CodeJobsWorkspace onUnauthorized={signOut} onOpenScan={(id) => { setSection('scans'); setDetail({ kind: 'scan', id }); }} onCreateCase={(id) => { setCaseScanId(id); setSection('cases'); }} />}
        {section === 'logs' && <LogJobsWorkspace onUnauthorized={signOut} />}
        {section === 'cases' && <CasesWorkspace onUnauthorized={signOut} initialScanId={caseScanId}/>}
      </section>
    </main>
    {detail && <DetailPanel detail={detailData} kind={detail.kind} onClose={() => setDetail(null)} onOpenFinding={(id) => setDetail({ kind: 'finding', id })} onCreateCase={(id) => { setCaseScanId(id); setDetail(null); setSection('cases'); }} />}
  </div>;
}

function Login({ error, busy, onSubmit, onRetry }: { error: string; busy: boolean; onSubmit: (event: React.FormEvent<HTMLFormElement>) => void; onRetry: () => void }) {
  return <div className="login-page"><div className="login-orb orb-one"/><div className="login-orb orb-two"/><section className="login-card"><div className="login-brand"><div className="brand-mark"><span>c</span><i /></div><span>Chinetscan</span></div><div className="login-label">LOCAL SECURITY WORKSPACE</div><h1>Welcome back</h1><p>Sign in to access your local assessment data.</p><form onSubmit={onSubmit}><label htmlFor="username">Operator name</label><input id="username" name="username" autoComplete="username" required maxLength={100}/><label htmlFor="password">Password</label><input id="password" name="password" type="password" autoComplete="current-password" required maxLength={1024}/>{error && <div className="login-error" role="alert">{error}<button type="button" onClick={onRetry}>Retry session check</button></div>}<button className="primary-button" disabled={busy}>{busy ? 'Signing in…' : 'Sign in'}<span aria-hidden="true">→</span></button></form><div className="login-foot"><span>◉</span> Available from this device only</div></section><footer className="login-footer">Chinetscan <span>•</span> Local analyst console</footer></div>;
}

function CenteredState({ title, detail }: { title: string; detail: string }) { return <div className="center-state"><div className="spinner"/><h1>{title}</h1><p>{detail}</p></div>; }

function OverviewPanel({ data, onScans, onFindings, onOpen }: { data: Overview | null; onScans: () => void; onFindings: () => void; onOpen: (id: string) => void }) {
  if (!data) return <div className="skeleton-card"/>;
  const severities: Array<keyof Overview['findings_by_severity']> = ['critical', 'high', 'medium', 'low', 'info'];
  return <><div className="welcome-strip"><div className="welcome-symbol">✳</div><div><strong>Your local workspace is ready</strong><p>Data shown here is read from your configured Chinetscan database.</p></div><span className="connected"><i/> Connected</span></div><div className="metric-grid"><Metric label="STORED SCANS" value={data.scan_count} icon="⌕" tone="blue" onClick={onScans}/><Metric label="STORED FINDINGS" value={data.finding_count} icon="◈" tone="violet" onClick={onFindings}/><Metric label="CRITICAL FINDINGS" value={data.findings_by_severity.critical} icon="↑" tone="red" onClick={onFindings}/></div><div className="overview-grid"><section className="panel recent-panel"><div className="panel-heading"><div><h2>Recent scans</h2><p>Your latest locally stored assessments</p></div><button className="text-button" onClick={onScans}>View all <span>→</span></button></div>{data.recent_scans.length ? <div className="table-scroll"><table><thead><tr><th>SCAN</th><th>TYPE</th><th>STARTED</th><th>FINDINGS</th><th>STATUS</th></tr></thead><tbody>{data.recent_scans.map((scan) => <tr key={scan.scan_id} onClick={() => onOpen(scan.scan_id)} tabIndex={0} onKeyDown={(event) => { if (event.key === 'Enter') onOpen(scan.scan_id); }}><td><span className="scan-icon">⌕</span><span className="mono">{scan.scan_id.slice(0, 8)}</span></td><td>{scan.project_types[0] ?? scan.scanner}</td><td>{dateOf(scan.started_at)}</td><td>{scan.finding_count}</td><td><Status status={scan.status}/></td></tr>)}</tbody></table></div> : <Empty title="No scans yet" text="Stored local assessments will appear here."/>}</section><section className="panel severity-panel"><div className="panel-heading"><div><h2>Findings by severity</h2><p>Counts from persisted findings</p></div></div><div className="severity-list">{severities.map((severity) => <div className="severity-row" key={severity}><SeverityPill severity={severity}/><div className="severity-track"><i className={`severity-fill ${severity}`} style={{ width: `${data.finding_count ? Math.max(4, data.findings_by_severity[severity] / data.finding_count * 100) : 0}%` }}/></div><strong>{data.findings_by_severity[severity]}</strong></div>)}</div><button className="secondary-button" onClick={onFindings}>Explore findings <span>→</span></button></section></div><div className="scope-note"><span>ⓘ</span><p><strong>Local-only workspace</strong> · No background jobs or network assessments are started from this dashboard.</p></div></>;
}

function Metric({ label, value, icon, tone, onClick }: { label: string; value: number; icon: string; tone: string; onClick: () => void }) { return <button className="metric-card" onClick={onClick}><div className={`metric-icon ${tone}`}>{icon}</div><span>{label}</span><strong>{value.toLocaleString()}</strong><small>From stored records <b>→</b></small></button>; }

function ScanTable({ data, page, onPage, onOpen }: { data: Page<Scan> | null; page: number; onPage: (page: number) => void; onOpen: (id: string) => void }) {
  if (!data) return <div className="skeleton-card"/>;
  return <section className="panel table-panel"><div className="panel-heading"><div><h2>Assessment records</h2><p>{data.total} stored scans</p></div><span className="data-chip">Local database</span></div>{data.items.length ? <><div className="table-scroll"><table><thead><tr><th>SCAN ID</th><th>ASSESSMENT</th><th>STARTED</th><th>FINDINGS</th><th>STATUS</th></tr></thead><tbody>{data.items.map((scan) => <tr key={scan.scan_id} onClick={() => onOpen(scan.scan_id)} tabIndex={0} onKeyDown={(event) => { if (event.key === 'Enter') onOpen(scan.scan_id); }}><td className="mono">{scan.scan_id}</td><td>{scan.project_types.join(', ') || scan.scanner}</td><td>{dateOf(scan.started_at)}</td><td>{scan.finding_count}</td><td><Status status={scan.status}/></td></tr>)}</tbody></table></div><Pagination total={data.total} page={page} onPage={onPage}/></> : <Empty title="No scan records" text="Run an assessment from the local CLI to see it here."/>}</section>;
}

function FindingTable({ data, page, onPage, onOpen }: { data: Page<Finding> | null; page: number; onPage: (page: number) => void; onOpen: (id: string) => void }) {
  if (!data) return <div className="skeleton-card"/>;
  return <section className="panel table-panel"><div className="panel-heading"><div><h2>Finding records</h2><p>{data.total} stored findings</p></div><span className="data-chip">Evidence-safe view</span></div>{data.items.length ? <><div className="table-scroll"><table><thead><tr><th>FINDING</th><th>SEVERITY</th><th>CATEGORY</th><th>SCANNER</th><th>RULE</th></tr></thead><tbody>{data.items.map((item) => <tr key={item.finding_id} onClick={() => onOpen(item.finding_id)} tabIndex={0} onKeyDown={(event) => { if (event.key === 'Enter') onOpen(item.finding_id); }}><td><span className="finding-dot"/><strong>{item.title}</strong><small className="sub-id">{item.finding_id.slice(0, 12)}</small></td><td><SeverityPill severity={item.severity}/></td><td>{item.category}</td><td>{item.scanner}</td><td className="mono">{item.rule_id}</td></tr>)}</tbody></table></div><Pagination total={data.total} page={page} onPage={onPage}/></> : <Empty title="No findings to review" text="Findings from supported local assessments will appear here."/>}</section>;
}

function DetailPanel({ detail, kind, onClose, onCreateCase, onOpenFinding }: { detail: Scan | Finding | null; kind: 'scan' | 'finding'; onClose: () => void; onCreateCase: (id: string) => void; onOpenFinding: (id: string) => void }) {
  return <div className="detail-backdrop" onMouseDown={(event) => { if (event.target === event.currentTarget) onClose(); }}><aside className="detail-panel" aria-label={`${kind} details`}><div className="detail-header"><div><div className="eyebrow">RECORD DETAILS</div><h2>{kind === 'scan' ? 'Scan details' : 'Finding details'}</h2></div><button className="close-button" onClick={onClose} aria-label="Close details">×</button></div>{!detail ? <div className="detail-loading"><div className="spinner"/>Loading record…</div> : kind === 'scan' ? <ScanDetail scan={detail as Scan} onCreateCase={() => onCreateCase((detail as Scan).scan_id)} onOpenFinding={onOpenFinding}/> : <FindingDetail finding={detail as Finding}/>}</aside></div>;
}

function ScanDetail({ scan, onCreateCase, onOpenFinding }: { scan: Scan; onCreateCase: () => void; onOpenFinding: (id: string) => void }) { return <div className="detail-body"><div className="detail-id">SCAN ID<span className="mono">{scan.scan_id}</span></div><dl><DetailValue label="Status"><Status status={scan.status}/></DetailValue><DetailValue label="Scanner">{scan.scanner}</DetailValue><DetailValue label="Started">{dateOf(scan.started_at)}</DetailValue><DetailValue label="Finished">{dateOf(scan.finished_at)}</DetailValue><DetailValue label="Project type">{scan.project_types.join(', ') || 'Not recorded'}</DetailValue><DetailValue label="Findings">{scan.finding_count}</DetailValue></dl>{scan.finding_ids?.length ? <section className="evidence-section"><h3>Persisted findings</h3>{scan.finding_ids.map((id) => <button className="text-button" key={id} onClick={() => onOpenFinding(id)}>{id.slice(0, 12)} →</button>)}</section> : null}<button className="primary-button" onClick={onCreateCase}>Create case from this scan</button><div className="evidence-note">Target paths and raw scan payloads are hidden in this dashboard view.</div></div>; }
function FindingDetail({ finding }: { finding: Finding }) { return <div className="detail-body"><div className="detail-id">FINDING ID<span className="mono">{finding.finding_id}</span></div><h3 className="finding-title">{finding.title}</h3><SeverityPill severity={finding.severity}/><dl><DetailValue label="Category">{finding.category}</DetailValue><DetailValue label="Confidence">{finding.confidence}</DetailValue><DetailValue label="Scanner">{finding.scanner}</DetailValue><DetailValue label="Rule">{finding.rule_id}</DetailValue>{finding.location && <DetailValue label="Location"><span className="mono evidence-text">{finding.location}</span></DetailValue>}</dl>{finding.description && <section className="evidence-section"><h3>Description</h3><p className="evidence-text">{finding.description}</p></section>}{finding.tags?.length ? <section className="evidence-section"><h3>Tags</h3><div className="tag-list">{finding.tags.map((tag) => <span key={tag}>{tag}</span>)}</div></section> : null}<div className="evidence-note">Evidence is displayed as text. Raw persisted payloads are not sent to the browser.</div></div>; }
function DetailValue({ label, children }: { label: string; children: React.ReactNode }) { return <div className="detail-value"><dt>{label}</dt><dd>{children}</dd></div>; }
function Status({ status }: { status: string }) { const tone = status === 'complete' ? 'green' : status === 'partial' ? 'amber' : 'neutral'; return <span className={`status ${tone}`}><i/>{status}</span>; }
function SeverityPill({ severity }: { severity: string }) { return <span className={`severity-pill ${severity}`}><i/>{severity}</span>; }
function Pagination({ total, page, onPage }: { total: number; page: number; onPage: (page: number) => void }) { const max = Math.max(0, Math.ceil(total / 20) - 1); return <div className="pagination"><span>Showing {total ? page * 20 + 1 : 0}–{Math.min((page + 1) * 20, total)} of {total}</span><div><button onClick={() => onPage(Math.max(0, page - 1))} disabled={page === 0} aria-label="Previous page">←</button><span>Page {page + 1} of {max + 1}</span><button onClick={() => onPage(Math.min(max, page + 1))} disabled={page >= max} aria-label="Next page">→</button></div></div>; }
function Empty({ title, text }: { title: string; text: string }) { return <div className="empty-state"><div className="empty-mark">⌕</div><h3>{title}</h3><p>{text}</p></div>; }
