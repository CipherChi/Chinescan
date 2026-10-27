export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type Scan = {
  scan_id: string;
  started_at: string;
  finished_at: string | null;
  status: string;
  scanner: string;
  project_types: string[];
  finding_count: number;
  finding_ids?: string[];
};
export type Finding = {
  finding_id: string;
  title: string;
  severity: Severity;
  category: string;
  confidence: string;
  scanner: string;
  rule_id: string;
  description?: string;
  location?: string | null;
  tags?: string[];
};
export type Page<T> = { items: T[]; total: number; limit: number; offset: number };
export type Overview = {
  scan_count: number;
  finding_count: number;
  findings_by_severity: Record<Severity, number>;
  recent_scans: Scan[];
};
export type CaseRecord = { record_type: string; record_id: string; source: string; title: string; severity: Severity | null };
export type CaseNote = { note_id: string; body: string; created_at: string; author_label: string | null };
export type CaseTimelineItem = { item_id: string; category: string; description: string; event_occurred_at: string | null; case_activity_at: string | null };
export type CaseData = {
  case: { case_id: string; title: string; description: string; status: string; severity: Severity; created_at: string; updated_at: string; scan_ids: string[]; notes: CaseNote[] };
  links: Array<{ record_type: string; record_id: string; source: string; linked_at: string | null }>;
  records: CaseRecord[]; timeline: CaseTimelineItem[]; warnings: string[];
  counts_by_severity: Record<Severity, number>;
};
export type CaseSummary = Pick<CaseData['case'], 'case_id' | 'title' | 'description' | 'status' | 'severity' | 'created_at' | 'updated_at'> & { note_count: number; linked_record_count: number };
export type CodeProject = { project_id: string; display_name: string };
export type CodeJob = { job_id: string; project_id: string; project_name: string; status: 'queued' | 'running' | 'succeeded' | 'failed' | 'interrupted'; created_at: string; started_at: string | null; finished_at: string | null; scan_id: string | null; error: string | null };
export type LogSource = { source_id: string; display_name: string };
export type LogJob = { job_id: string; source_id: string; source_name: string; status: 'queued' | 'running' | 'succeeded' | 'partial' | 'failed' | 'interrupted'; created_at: string; started_at: string | null; finished_at: string | null; scan_id: string | null; event_count: number; alert_count: number; error_count: number; error: string | null; diagnostics: string[] };
export type LogEvent = { event_id: string; occurred_at: string; kind: string; summary: string; source: string; source_ip: string | null; destination_ip: string | null; user: string | null; host: string | null; process: string | null; url: string | null; event_outcome: string | null; mitre_attack_techniques: string[] };
export type LogAlert = { alert_id: string; title: string; description: string; severity: Severity; confidence: string; rule_id: string; event_ids: string[]; indicator_ids: string[]; mitre_attack_techniques: string[] };
export type LogTimeline = { entry_id: string; occurred_at: string; description: string; event_id: string | null; scan_id: string | null };
