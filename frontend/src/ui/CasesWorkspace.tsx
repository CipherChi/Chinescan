import { useCallback, useEffect, useRef, useState } from 'react';
import { api, UnauthorizedError } from '../api';
import type { CaseData, CaseSummary, Page, Severity } from '../types';

const severities: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
const statuses = ['open', 'in_progress', 'resolved', 'closed'];

export function CasesWorkspace({ onUnauthorized, initialScanId = '' }: { onUnauthorized: () => void; initialScanId?: string }) {
  const [page, setPage] = useState<Page<CaseSummary> | null>(null);
  const [selected, setSelected] = useState<CaseData | null>(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState('');
  const [casePage, setCasePage] = useState(0);
  const [statusChoice, setStatusChoice] = useState('open');
  const actionInFlight = useRef(false);

  const load = useCallback(async (offset = casePage * 20) => {
    setBusy(true); setError('');
    try { setPage(await api.cases(offset)); }
    catch (e) { if (e instanceof UnauthorizedError) onUnauthorized(); else setError(message(e)); }
    finally { setBusy(false); }
  }, [casePage, onUnauthorized]);
  useEffect(() => { void load(); }, [load]);

  async function perform(action: () => Promise<CaseData>, success: string, afterSuccess?: () => void) {
    if (actionInFlight.current) return;
    actionInFlight.current = true;
    setBusy(true); setError(''); setNotice('');
    try {
      const result = await action(); setSelected(result); setStatusChoice(result.case.status); setNotice(success);
      afterSuccess?.();
      try { setPage(await api.cases(casePage * 20)); }
      catch (refreshError) {
        if (refreshError instanceof UnauthorizedError) onUnauthorized();
        else setError(`Saved successfully, but the case list could not refresh: ${message(refreshError)}`);
      }
    } catch (e) { if (e instanceof UnauthorizedError) onUnauthorized(); else setError(message(e)); }
    finally { actionInFlight.current = false; setBusy(false); }
  }

  return <section className="case-workspace">
    <div className="case-create panel"><div className="panel-heading"><div><h2>Create a case</h2><p>Start from a scan saved in the local database.</p></div></div>
      <form className="case-form" onSubmit={(event) => { event.preventDefault(); const formElement = event.currentTarget; const form = new FormData(formElement); void perform(() => api.createCase(String(form.get('scan_id')), String(form.get('title')), String(form.get('description')), String(form.get('severity'))), 'Case created and saved.', () => formElement.reset()); }}>
        <label>Persisted scan ID<input name="scan_id" required maxLength={255} aria-label="Persisted scan ID" defaultValue={initialScanId} /></label>
        <label>Case title<input name="title" maxLength={200} aria-label="Case title" /></label>
        <label>Severity<select name="severity" defaultValue="medium" aria-label="Case severity">{severities.map((s) => <option key={s} value={s}>{capitalize(s)}</option>)}</select></label>
        <label className="case-description">Description<textarea name="description" maxLength={8000} rows={2} aria-label="Case description" /></label>
        <button className="primary-button" disabled={busy}>Create case</button>
      </form>
    </div>
    {error && <div role="alert" className="alert-error"><strong>Action failed</strong><p>{error}</p><button onClick={() => void load()}>Retry</button></div>}
    {notice && <p role="status" className="case-notice">{notice}</p>}
    <div className="cases-grid"><section className="panel"><div className="panel-heading"><div><h2>Cases</h2><p>{page?.total ?? 0} persisted investigations</p></div></div>
      {busy && <p role="status">Loading cases…</p>}{page && !page.items.length && <div className="empty-state"><h3>No cases yet</h3><p>Create one from a persisted scan above.</p></div>}
      {page?.items.map((item) => <button className="case-row" key={item.case_id} onClick={() => { if (selected?.case.case_id === item.case_id) return; setBusy(true); setError(''); api.case(item.case_id).then((value) => { setSelected(value); setStatusChoice(value.case.status); }).catch((e: unknown) => { if (e instanceof UnauthorizedError) onUnauthorized(); else setError(message(e)); }).finally(() => setBusy(false)); }}><strong>{item.title}</strong><span>{item.case_id.slice(0, 8)} · {item.status.replace('_', ' ')}</span><SeverityBadge severity={item.severity}/></button>)}
      {page && <div className="case-pagination"><span>Showing {page.total ? page.offset + 1 : 0}–{Math.min(page.offset + page.limit, page.total)} of {page.total}</span><button disabled={!page.offset || busy} onClick={() => setCasePage(Math.max(0, casePage - 1))}>Previous</button><span>Page {casePage + 1} of {Math.max(1, Math.ceil(page.total / page.limit))}</span><button disabled={page.offset + page.limit >= page.total || busy} onClick={() => setCasePage(casePage + 1)}>Next</button></div>}
    </section>
    <section className="panel case-detail" aria-label="Case detail">{!selected ? <div className="empty-state"><h3>Select a case</h3><p>Case notes, linked records, and timeline will appear here.</p></div> : <>
      <div className="panel-heading"><div><h2>{selected.case.title}</h2><p className="mono">{selected.case.case_id}</p></div><SeverityBadge severity={selected.case.severity}/></div>
      <p>{selected.case.description || 'No description.'}</p><p><strong>Status:</strong> {selected.case.status.replace('_', ' ')}</p>
      <form className="inline-form" onSubmit={(event) => { event.preventDefault(); void perform(() => api.updateCaseStatus(selected.case.case_id, statusChoice), 'Case status updated.'); }}><label htmlFor="case-status">Change status</label><select id="case-status" name="status" value={statusChoice} onChange={(event) => setStatusChoice(event.target.value)}>{statuses.map((s) => <option key={s} value={s}>{s.replace('_', ' ')}</option>)}</select><button disabled={busy}>Update</button></form>
      <form className="inline-form" onSubmit={(event) => { event.preventDefault(); const formElement = event.currentTarget; const form = new FormData(formElement); void perform(() => api.linkCaseRecord(selected.case.case_id, String(form.get('record_type')), String(form.get('record_id'))), 'Record link saved.', () => formElement.reset()); }}><label>Link persisted record</label><select name="record_type" aria-label="Record type"><option value="finding">Finding</option><option value="scan">Scan</option><option value="alert">Alert</option><option value="event">Event</option><option value="timeline_entry">Timeline entry</option><option value="indicator">Indicator</option><option value="target">Target</option><option value="authorization_record">Authorization record</option></select><input name="record_id" required maxLength={255} aria-label="Record ID"/><button disabled={busy}>Link record</button></form>
      <form className="note-form" onSubmit={(event) => { event.preventDefault(); const formElement = event.currentTarget; const form = new FormData(formElement); void perform(() => api.addCaseNote(selected.case.case_id, String(form.get('body'))), 'Note appended.', () => formElement.reset()); }}><label htmlFor="case-note">Append analyst note</label><textarea id="case-note" name="body" required maxLength={8000} rows={3}/><button className="secondary-button" disabled={busy}>Add note</button></form>
      <h3>Linked records</h3>{selected.records.length ? <ul>{selected.records.map((r) => <li key={`${r.record_type}:${r.record_id}`}><strong>{r.record_type}</strong> <span className="mono">{r.record_id}</span> {r.severity && <SeverityBadge severity={r.severity}/>} {r.title}</li>)}</ul> : <p>No persisted records linked.</p>}
      <h3>Analyst notes</h3>{selected.case.notes.map((n) => <article className="case-note" key={n.note_id}><time>{new Date(n.created_at).toLocaleString()}</time><p>{n.body}</p>{n.author_label && <small>Local author label, unverified: {n.author_label}</small>}</article>)}{!selected.case.notes.length && <p>No analyst notes.</p>}
      <h3>Timeline</h3>{selected.timeline.length ? <ol>{selected.timeline.map((item) => <li key={item.item_id}><time>{new Date(item.event_occurred_at || item.case_activity_at || '').toLocaleString()}</time> <strong>{item.category.replace('_', ' ')}</strong><p>{item.description}</p></li>)}</ol> : <p>No timeline entries.</p>}
      <div className="report-actions"><strong>Download case report</strong>{(['json', 'markdown', 'html'] as const).map((fmt) => <a key={fmt} href={`/api/cases/${encodeURIComponent(selected.case.case_id)}/report/${fmt}`} download> {fmt.toUpperCase()} </a>)}</div>
      {selected.case.scan_ids.map((id) => <div className="report-actions" key={id}><span>Scan report</span>{(['json', 'markdown', 'html', 'csv', 'sarif'] as const).map((fmt) => <a key={fmt} href={`/api/scans/${encodeURIComponent(id)}/report/${fmt}`} download>{fmt.toUpperCase()}</a>)}</div>)}
    </>}</section></div>
  </section>;
}

function message(e: unknown) { return e instanceof Error ? e.message : 'The operation failed. Please try again.'; }
function capitalize(value: string) { return value[0].toUpperCase() + value.slice(1); }
function SeverityBadge({ severity }: { severity: string }) { return <span className={`severity-pill ${severity}`}><i aria-hidden="true"/>{capitalize(severity)} severity</span>; }
