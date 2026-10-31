import { useCallback, useEffect, useRef, useState } from 'react';
import { api, UnauthorizedError } from '../api';
import type { FsDirectory, FsPage, ProjectDetail, ProjectSummary } from '../types';

type Props = { onUnauthorized: () => void; onOpenScan: (id: string) => void; onCreateCase: (id: string) => void };
const pickerExample = "allowed_roots = ['C:\\src']";

export function ProjectsWorkspace({ onUnauthorized, onOpenScan, onCreateCase }: Props) {
  const [projects, setProjects] = useState<ProjectSummary[]>([]);
  const [detail, setDetail] = useState<ProjectDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [pickerOpen, setPickerOpen] = useState(false);
  const [removeOpen, setRemoveOpen] = useState(false);
  const [removing, setRemoving] = useState(false);
  const [confirmation, setConfirmation] = useState('');
  const dialogRef = useRef<HTMLDivElement>(null);

  const load = useCallback(async () => {
    try {
      const next = await api.projects();
      setProjects(next);
      if (detail) {
        const current = next.find((item) => item.project_id === detail.project_id);
        if (current) setDetail(await api.project(current.project_id));
        else setDetail(null);
      }
    } catch (reason) {
      if (reason instanceof UnauthorizedError) onUnauthorized();
      else setError(reason instanceof Error ? reason.message : 'Unable to load projects.');
    } finally { setLoading(false); }
  }, [detail, onUnauthorized]);

  useEffect(() => { void load(); }, []); // load is deliberately initialized once
  useEffect(() => {
    if (!detail?.recent_jobs.some((job) => job.status === 'queued' || job.status === 'running')) return;
    const timer = window.setTimeout(() => { void load(); }, 1200);
    return () => window.clearTimeout(timer);
  }, [detail, load]);
  useEffect(() => {
    if (!pickerOpen && !removeOpen) return;
    const dialog = dialogRef.current;
    if (!dialog) return;
    const focusable = () => Array.from(dialog.querySelectorAll<HTMLElement>(
      'button:not([disabled]), input:not([disabled]), select:not([disabled]), [tabindex="0"]',
    ));
    focusable()[0]?.focus();
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') { setPickerOpen(false); setRemoveOpen(false); }
      if (event.key !== 'Tab') return;
      const elements = focusable();
      if (!elements.length) return;
      const first = elements[0]; const last = elements[elements.length - 1];
      if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
      else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
    };
    document.addEventListener('keydown', onKeyDown);
    return () => document.removeEventListener('keydown', onKeyDown);
  }, [pickerOpen, removeOpen]);

  async function openProject(project: ProjectSummary) {
    try { setDetail(await api.project(project.project_id)); setError(''); }
    catch (reason) { if (reason instanceof UnauthorizedError) onUnauthorized(); else setError(reason instanceof Error ? reason.message : 'Unable to load project.'); }
  }
  async function startAssessment() {
    if (!detail) return;
    try {
      await api.startProjectCodeJob(detail.project_id);
      await openProject({ ...detail, origin_label: detail.origin_label });
    } catch (reason) { if (reason instanceof UnauthorizedError) onUnauthorized(); else setError(reason instanceof Error ? reason.message : 'Unable to start assessment.'); }
  }
  async function removeProject() {
    if (!detail || confirmation !== detail.name) return;
    setRemoving(true); setError('');
    try {
      await api.removeProject(detail.project_id, confirmation);
      setRemoveOpen(false); setConfirmation(''); setDetail(null); await load();
    } catch (reason) { if (reason instanceof UnauthorizedError) onUnauthorized(); else setError(reason instanceof Error ? reason.message : 'Unable to remove project.'); }
    finally { setRemoving(false); }
  }

  if (detail) return <section className="projects-workspace" aria-label="Project detail">
    <div className="panel project-detail-panel">
      <div className="panel-heading"><div><button className="text-button" onClick={() => setDetail(null)}>← All projects</button><h2>{detail.name}</h2><p>{detail.kind} · configured by {detail.configured_by} · {detail.origin_label}</p></div>
        <div className="project-actions"><button className="primary-button" onClick={() => void startAssessment()}>Assess code</button>{detail.configured_by === 'ui' && <button className="secondary-button" onClick={() => { setConfirmation(''); setRemoveOpen(true); }}>Remove project</button>}</div>
      </div>
      {error && <div className="alert-error" role="alert" aria-live="assertive">{error}</div>}
      <ProjectLogs projectId={detail.project_id} locations={detail.log_locations ?? []} onUnauthorized={onUnauthorized} onChanged={() => void openProject(detail)} />
      <section aria-label="Project log alerts"><h3>Project log alerts</h3>{detail.log_alerts?.length ? <ul>{detail.log_alerts.map((alert) => <li key={alert.alert_id}><strong>{alert.title}</strong> · {alert.severity}</li>)}</ul> : <p className="empty-copy">No log alerts yet.</p>}</section>
      <section aria-label="Project log events"><h3>Project log events</h3>{detail.log_events?.length ? <ul>{detail.log_events.map((event) => <li key={event.event_id}>{event.occurred_at} · {event.summary} {event.sha256} {event.file_hashes?.join(' ')}</li>)}</ul> : <p className="empty-copy">No log events yet.</p>}</section>
      <section aria-label="Project log timeline"><h3>Project log timeline</h3>{detail.log_timeline?.length ? <ol>{detail.log_timeline.map((entry) => <li key={entry.entry_id}>{entry.occurred_at} · {entry.description}</li>)}</ol> : <p className="empty-copy">No timeline entries yet.</p>}</section>
      <section aria-label="Recent jobs"><h3>Recent jobs</h3>{detail.recent_jobs.length ? <ul className="project-job-list">{detail.recent_jobs.map((job) => <li key={job.job_id}><span>{job.status}</span><span>{job.warning ?? job.error ?? job.scan_id ?? job.job_id.slice(0, 8)}</span>{job.scan_id && <button className="text-button" onClick={() => onOpenScan(job.scan_id!)}>Open findings</button>}</li>)}</ul> : <p className="empty-copy">No assessments yet.</p>}</section>
      <section aria-label="Persisted findings"><h3>Persisted findings ({detail.findings_count})</h3>{detail.findings.length ? <ul className="project-finding-list">{detail.findings.map((finding) => <li key={finding.finding_id}><strong>{finding.title}</strong><span>{finding.severity} · {finding.location ?? 'Project file'}</span></li>)}</ul> : <p className="empty-copy">No findings have been persisted for this project.</p>}</section>
      <section aria-label="Linked cases"><h3>Linked cases</h3>{detail.linked_cases.length ? <ul>{detail.linked_cases.map((item) => <li key={item.case_id}>{item.title} · {item.status}</li>)}</ul> : <p className="empty-copy">No linked cases.</p>}</section>
      <section aria-label="Assessment history"><h3>Assessment history</h3>{detail.recent_scans.map((scan) => <div key={scan.scan_id} className="project-scan-row">
        {scan.status === 'partial' && <div className="partial-result" role="status" aria-live="polite"><strong>Partial result</strong><span>Skipped counts: {Object.entries(scan.skipped_counts).map(([key, count]) => `${key}: ${count}`).join(', ') || 'see coverage details'}.</span></div>}
        <span>{scan.status} · {scan.finding_count} findings · {scan.scan_id}</span><button className="text-button" onClick={() => onCreateCase(scan.scan_id)}>Create or link case</button>
      </div>)}</section>
    </div>
    {removeOpen && <div className="project-dialog-backdrop"><div className="project-dialog" role="dialog" aria-modal="true" aria-labelledby="remove-project-title" ref={dialogRef}>
      <h2 id="remove-project-title">Remove {detail.name}?</h2><p>The project record and its association will be removed. <strong>Files in the folder are never touched.</strong> Existing scans, findings and cases remain in history and are marked as project removed.</p>
      <label htmlFor="remove-project-confirm">Type <strong>{detail.name}</strong> to confirm</label><input id="remove-project-confirm" value={confirmation} onChange={(event) => setConfirmation(event.target.value)} autoComplete="off" />
      <div className="project-actions"><button className="secondary-button" onClick={() => setRemoveOpen(false)}>Cancel</button><button className="danger-button" disabled={confirmation !== detail.name || removing} onClick={() => void removeProject()}>{removing ? 'Removing…' : 'Remove project record'}</button></div>
      {error && <p role="alert" aria-live="assertive">{error}</p>}
    </div></div>}
  </section>;

  return <section className="projects-workspace" aria-label="Projects">
    <div className="panel table-panel"><div className="panel-heading"><div><h2>Projects</h2><p>Assess code from approved folders on this device.</p></div><button className="primary-button" onClick={() => { setError(''); setPickerOpen(true); }}>Add project</button></div>
      {error && <div className="alert-error" role="alert" aria-live="assertive">{error}</div>}
      {loading ? <div className="skeleton-card" aria-label="Loading projects"/> : projects.length ? <div className="table-scroll"><table><thead><tr><th>PROJECT</th><th>KIND</th><th>CONFIGURED BY</th><th>LAST SCAN</th><th>ACTIONS</th></tr></thead><tbody>{projects.map((project) => <tr key={project.project_id}><td><strong>{project.name}</strong></td><td>{project.kind}</td><td><span className={`project-origin ${project.configured_by}`}>{project.configured_by === 'file' ? 'Configured by file' : 'Added here'}</span></td><td>{project.last_scan ?? '—'}</td><td><button className="text-button" onClick={() => void openProject(project)}>Open project</button></td></tr>)}</tbody></table></div> : <div className="empty-state"><h3>No projects yet</h3><p>Add an approved local folder to begin code assessments.</p></div>}
    </div>
    {pickerOpen && <FolderPicker dialogRef={dialogRef} onClose={() => setPickerOpen(false)} onUnauthorized={onUnauthorized} onCreated={async (project) => { setPickerOpen(false); await load(); await openProject(project); }} />}
  </section>;
}

function ProjectLogs({ projectId, locations, onUnauthorized, onChanged }: { projectId: string; locations: Array<{ location_id: string; name: string; scope: 'project' | 'external' }>; onUnauthorized: () => void; onChanged: () => void }) {
  const [suggestions, setSuggestions] = useState<{ items: Array<{ suggestion_id: string; label: string; unsupported: boolean }>; partial: boolean } | null>(null);
  const [selected, setSelected] = useState<string[]>(locations.map((item) => item.location_id));
  const [running, setRunning] = useState(false);
  const [error, setError] = useState('');
  const [browserOpen, setBrowserOpen] = useState(false);
  const [folder, setFolder] = useState<{ directory_id: string; name: string } | null>(null);
  const [children, setChildren] = useState<Array<{ directory_id: string; name: string }>>([]);
  const [locationName, setLocationName] = useState('');
  const [scopeMode, setScopeMode] = useState<'project' | 'external'>('project');
  const [externalRoots, setExternalRoots] = useState<Array<{ directory_id: string; name: string }>>([]);
  const [projectJobs, setProjectJobs] = useState<Array<{ job_id: string; status: string; error: string | null; error_count: number; skipped_counts?: Record<string, number> }>>([]);
  const dialog = useRef<HTMLDivElement>(null);
  const hadActiveJob = useRef(false);
  const locationKey = locations.map((item) => item.location_id).join('|');
  useEffect(() => { setSelected(locations.map((item) => item.location_id)); }, [locationKey]);
  useEffect(() => {
    let active = true;
    async function loadJobs() {
      try {
        const page = await api.logJobs();
        if (active) {
          const next = page.items.filter((job) => job.project_id === projectId).slice(0, 10);
          const hasActive = next.some((job) => job.status === 'queued' || job.status === 'running');
          if (hadActiveJob.current && !hasActive) onChanged();
          hadActiveJob.current = hasActive;
          setProjectJobs(next);
        }
      } catch (reason) { if (reason instanceof UnauthorizedError) onUnauthorized(); }
    }
    void loadJobs();
    const timer = window.setInterval(() => void loadJobs(), 1800);
    return () => { active = false; window.clearInterval(timer); };
  }, [projectId, onUnauthorized]);
  useEffect(() => {
    if (!browserOpen || !dialog.current) return;
    const node = dialog.current;
    const focusable = () => Array.from(node.querySelectorAll<HTMLElement>('button:not([disabled]), input:not([disabled])'));
    focusable()[0]?.focus();
    const trap = (event: KeyboardEvent) => {
      if (event.key === 'Escape') { setBrowserOpen(false); return; }
      if (event.key !== 'Tab') return;
      const items = focusable();
      if (!items.length) return;
      if (event.shiftKey && document.activeElement === items[0]) { event.preventDefault(); items.at(-1)?.focus(); }
      else if (!event.shiftKey && document.activeElement === items.at(-1)) { event.preventDefault(); items[0].focus(); }
    };
    document.addEventListener('keydown', trap);
    return () => document.removeEventListener('keydown', trap);
  }, [browserOpen]);

  async function suggest() {
    try { setSuggestions(await api.projectLogSuggestions(projectId)); setError(''); }
    catch (reason) { if (reason instanceof UnauthorizedError) onUnauthorized(); else setError(reason instanceof Error ? reason.message : 'Suggestions could not be loaded.'); }
  }
  async function openFolder(id?: string) {
    try {
      const root = id ? null : await api.projectBrowse(projectId);
      const result = await api.projectBrowse(projectId, id ?? root?.directory_id);
      setFolder(null);
      setChildren((result.items ?? []).map((item) => ({ directory_id: item.directory_id, name: item.name })));
    } catch (reason) { if (reason instanceof UnauthorizedError) onUnauthorized(); else setError(reason instanceof Error ? reason.message : 'Folder could not be loaded.'); }
  }
  async function openExternal() {
    setScopeMode('external');
    try {
      const result = await api.fsRoots('log_location');
      setExternalRoots(result.items);
      setFolder(null);
      setChildren([]);
    } catch (reason) { if (reason instanceof UnauthorizedError) onUnauthorized(); else setError(reason instanceof Error ? reason.message : 'Approved folders could not be loaded.'); }
  }
  async function browseExternal(id: string) {
    try {
      const result = await api.fsList('log_location', id);
      setFolder({ directory_id: result.directory_id, name: result.name });
      setChildren(result.items.map((item) => ({ directory_id: item.directory_id, name: item.name })));
    } catch (reason) { if (reason instanceof UnauthorizedError) onUnauthorized(); else setError(reason instanceof Error ? reason.message : 'Folder could not be loaded.'); }
  }
  async function addFolder() {
    if (!folder || !locationName.trim()) return;
    try { await api.addProjectLogLocation(projectId, locationName.trim(), folder.directory_id, scopeMode); setBrowserOpen(false); onChanged(); }
    catch (reason) { if (reason instanceof UnauthorizedError) onUnauthorized(); else setError(reason instanceof Error ? reason.message : 'Location could not be added.'); }
  }
  async function run() {
    setRunning(true); setError('');
    try { const job = await api.startProjectLogJob(projectId, selected); setProjectJobs((items) => [job, ...items].slice(0, 10)); }
    catch (reason) { if (reason instanceof UnauthorizedError) onUnauthorized(); else setError(reason instanceof Error ? reason.message : 'Log analysis could not start.'); }
    finally { setRunning(false); }
  }
  return <section aria-label="Log locations">
    <div className="panel-heading"><div><h3>Log locations</h3><p>Linked folders are read-only; analysis writes only to ChineScan storage.</p></div><div className="project-actions"><button className="secondary-button" onClick={() => { setBrowserOpen(true); void openFolder(); }}>Add location</button><button className="secondary-button" onClick={() => void suggest()}>Suggest locations</button></div></div>
    {error && <p role="alert" aria-live="assertive" className="alert-error">{error}</p>}
    {!locations.length && <p className="empty-copy">No log locations linked yet.</p>}
    <ul>{locations.map((item) => <li key={item.location_id}>{item.name} <span className="project-origin">{item.scope}</span> <button className="text-button" onClick={async () => { if (!window.confirm(`Remove this association? Files are never touched; scans and findings are kept. Type ${item.name} in the next prompt to confirm.`)) return; if (window.prompt(`Type ${item.name} to confirm removal.`) !== item.name) return; try { await api.removeProjectLogLocation(projectId, item.location_id, item.name); onChanged(); } catch (reason) { setError(reason instanceof Error ? reason.message : 'Location could not be removed.'); } }}>Remove</button></li>)}</ul>
    {suggestions && <section aria-label="Log location suggestions"><h4>Suggestions</h4>{suggestions.partial && <p role="status" aria-live="polite">Suggestions are partial because the directory visit limit was reached.</p>}<ul>{suggestions.items.map((item) => <li key={item.suggestion_id}>{item.label} {item.unsupported ? <span className="project-origin">Unsupported format</span> : <button className="text-button" onClick={async () => { try { await api.confirmProjectLogSuggestion(projectId, item.suggestion_id, item.label); onChanged(); } catch (reason) { setError(reason instanceof Error ? reason.message : 'Suggestion could not be confirmed.'); } }}>Confirm</button>}</li>)}</ul></section>}
    {!!locations.length && <><fieldset><legend>Locations to analyze</legend>{locations.map((item) => <label key={item.location_id}><input type="checkbox" checked={selected.includes(item.location_id)} onChange={(event) => setSelected(event.target.checked ? [...selected, item.location_id] : selected.filter((id) => id !== item.location_id))} /> {item.name}</label>)}</fieldset><button className="primary-button" disabled={!selected.length || running} onClick={() => void run()}>{running ? 'Starting…' : 'Analyze logs'}</button></>}
    <section aria-label="Recent project log jobs"><h4>Recent log jobs</h4>{projectJobs.length ? <ul>{projectJobs.map((job) => <li key={job.job_id}>{job.status}{job.status === 'partial' && ` · skipped ${Object.entries(job.skipped_counts ?? {}).map(([key, count]) => `${key}: ${count}`).join(', ') || job.error_count}`}{job.error && ` · ${job.error}`}</li>)}</ul> : <p className="empty-copy">No project log jobs yet.</p>}</section>
    {browserOpen && <div className="project-dialog-backdrop"><div className="project-dialog folder-picker" role="dialog" aria-modal="true" aria-labelledby="project-log-folder-title" ref={dialog}><h2 id="project-log-folder-title">Add a log folder</h2><fieldset><legend>Folder scope</legend><label><input type="radio" name="log-scope" checked={scopeMode === 'project'} onChange={() => { setScopeMode('project'); setFolder(null); setChildren([]); void openFolder(); }} /> Inside this project</label><label><input type="radio" name="log-scope" checked={scopeMode === 'external'} onChange={() => void openExternal()} /> Outside this project (approved roots)</label></fieldset>{scopeMode === 'external' && <ul aria-label="Approved external roots">{externalRoots.map((item) => <li key={item.directory_id}><button className="text-button" onClick={() => void browseExternal(item.directory_id)}>{item.name}</button><button className="secondary-button" onClick={() => setFolder(item)}>Select</button></li>)}</ul>}{folder && <p role="status">Selected: {folder.name}</p>}<ul aria-label="Folder contents">{children.map((item) => <li key={item.directory_id}><button className="text-button" onClick={() => scopeMode === 'project' ? void openFolder(item.directory_id) : void browseExternal(item.directory_id)}>{item.name}</button><button className="secondary-button" onClick={() => setFolder(item)}>Select</button></li>)}</ul><label htmlFor="project-log-name">Location name</label><input id="project-log-name" value={locationName} onChange={(event) => setLocationName(event.target.value)} maxLength={120} /><div className="project-actions"><button className="secondary-button" onClick={() => setBrowserOpen(false)}>Cancel</button><button className="primary-button" disabled={!folder || !locationName.trim()} onClick={() => void addFolder()}>Add</button></div></div></div>}
  </section>;
}

function FolderPicker({ dialogRef, onClose, onUnauthorized, onCreated }: { dialogRef: React.RefObject<HTMLDivElement | null>; onClose: () => void; onUnauthorized: () => void; onCreated: (project: ProjectSummary) => void }) {
  const [roots, setRoots] = useState<FsDirectory[]>([]);
  const [page, setPage] = useState<FsPage | null>(null);
  const [cursor, setCursor] = useState<string | null>(null);
  const [items, setItems] = useState<FsDirectory[]>([]);
  const [selected, setSelected] = useState<FsDirectory | null>(null);
  const [name, setName] = useState('');
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    api.fsRoots('project_directory').then((result) => setRoots(result.items)).catch((reason: unknown) => {
      if (reason instanceof UnauthorizedError) onUnauthorized();
      else setError(reason instanceof Error ? reason.message : 'Folder list could not be loaded.');
    }).finally(() => setLoading(false));
  }, [onUnauthorized]);

  async function browse(directory: FsDirectory, append = false) {
    setLoading(true); setError('');
    try {
      const result = await api.fsList('project_directory', directory.directory_id, append ? cursor : null);
      setPage(result); setSelected({ directory_id: result.directory_id, name: result.name, selectable: result.selectable });
      setItems(append ? [...items, ...result.items] : result.items); setCursor(result.next_cursor);
    } catch (reason) {
      if (reason instanceof UnauthorizedError) onUnauthorized();
      else setError(reason instanceof Error ? reason.message : 'Folder list could not be loaded.');
    } finally { setLoading(false); }
  }
  async function add() {
    if (!selected || !name.trim()) return;
    setSaving(true); setError('');
    try { onCreated(await api.addProject(name.trim(), selected.directory_id)); }
    catch (reason) { if (reason instanceof UnauthorizedError) onUnauthorized(); else setError(reason instanceof Error ? reason.message : 'Project could not be added.'); }
    finally { setSaving(false); }
  }

  return <div className="project-dialog-backdrop"><div className="project-dialog folder-picker" role="dialog" aria-modal="true" aria-labelledby="folder-picker-title" ref={dialogRef}>
    <div className="dialog-heading"><div><h2 id="folder-picker-title">Add a local project</h2><p>Choose a folder inside an approved root. Files are only read for assessment.</p></div><button aria-label="Close folder picker" className="close-button" onClick={onClose}>×</button></div>
    {error && <div role="alert" aria-live="assertive" className="alert-error">{error}</div>}
    {loading && !roots.length && <p role="status" aria-live="polite">Loading approved folders…</p>}
    {!loading && !roots.length && <div className="empty-state"><h3>No allowed roots</h3><p>Add an approved folder to <code>config.toml</code>, then restart ChineScan. Example:</p><pre>{pickerExample}</pre></div>}
    {roots.length > 0 && <div className="folder-browser">
      <section aria-label="Approved roots"><h3>Approved roots</h3><ul>{roots.map((root) => <li key={root.directory_id}>
        <button className="text-button" onClick={() => void browse(root)}>{root.name}</button>
        {root.selectable && <button className="secondary-button" onClick={() => { setSelected(root); setPage(null); setItems([]); }}>Select this folder</button>}
      </li>)}</ul></section>
      {page && <section aria-label="Folder contents"><nav aria-label="Folder breadcrumbs" className="folder-breadcrumbs">{page.breadcrumbs.map((crumb, index) => <button key={`${crumb.directory_id}-${index}`} className="text-button" onClick={() => void browse(crumb)}>{crumb.name}</button>)}</nav>
        <button className="secondary-button" onClick={() => setSelected({ directory_id: page.directory_id, name: page.name, selectable: page.selectable })}>Select this folder</button>
        {page.truncated && <p role="status">Folder listing reached its directory-entry cap; results may be incomplete.</p>}
        {items.length ? <ul className="folder-list">{items.map((item) => <li key={item.directory_id}><button className="text-button" onClick={() => void browse(item)} aria-label={`Open ${item.name}`}>📁 {item.name}</button><button className="secondary-button" disabled={!item.selectable} onClick={() => setSelected(item)}>Select this folder</button></li>)}</ul> : <p className="empty-copy">No subfolders in this folder.</p>}
        {cursor && <button className="secondary-button" disabled={loading} onClick={() => void browse({ directory_id: page.directory_id, name: page.name, selectable: true }, true)}>Load more</button>}
      </section>}
      {selected && <div className="selected-project-folder" role="status">Selected folder: {selected.name}</div>}
      <label htmlFor="new-project-name">Project name</label><input id="new-project-name" value={name} onChange={(event) => setName(event.target.value)} maxLength={120} required />
      <div className="project-actions"><button className="secondary-button" onClick={onClose}>Cancel</button><button className="primary-button" disabled={!selected || !name.trim() || saving} onClick={() => void add()}>{saving ? 'Adding…' : 'Add project'}</button></div>
    </div>}
  </div></div>;
}
