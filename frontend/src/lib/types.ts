export type Severity = "informational" | "low" | "medium" | "high" | "critical";
export type Confidence = "low" | "medium" | "high";
export type IncidentStatus = "new" | "open" | "investigating" | "contained" | "resolved" | "closed";
export type Verdict = "true_positive" | "benign_positive" | "false_positive" | "undetermined";
export type AlertStatus = "new" | "acknowledged" | "escalated" | "closed";
export type Role = "viewer" | "analyst" | "lead" | "admin";

export interface Page<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
}

export interface Me {
  id: string;
  email: string;
  display_name: string;
  role: Role;
  org_id: string;
  org_name: string;
  is_demo: boolean;
  must_change_password?: boolean;
  alert_email_severity?: "critical" | "high" | "medium" | "low" | null;
  csrf_token?: string | null;
}

export interface UserRef {
  id: string;
  display_name: string;
  email: string;
  role: Role;
}

export interface Incident {
  id: string;
  number: number;
  reference: string;
  title: string;
  summary: string;
  severity: Severity;
  status: IncidentStatus;
  verdict: Verdict | null;
  closure_reason: string | null;
  source: string;
  tags: string[];
  assignee: UserRef | null;
  is_synthetic: boolean;
  created_at: string;
  updated_at: string;
  acknowledged_at: string | null;
  contained_at: string | null;
  resolved_at: string | null;
  closed_at: string | null;
  version: number;
  alert_count: number;
  event_count: number;
}

export interface Alert {
  id: string;
  rule_id: string;
  rule_name: string | null;
  title: string;
  description: string;
  severity: Severity;
  confidence: Confidence;
  status: AlertStatus;
  disposition: Verdict | null;
  disposition_reason: string | null;
  occurrence_count: number;
  first_seen: string;
  last_seen: string;
  entities: Record<string, string>;
  evidence_summary: Record<string, unknown>;
  incident_id: string | null;
  incident_number: number | null;
  assignee_id: string | null;
  created_at: string;
  updated_at: string;
}

export interface EventRecord {
  id: string;
  event_time: string;
  ingested_at: string;
  event_type: string;
  outcome: string | null;
  host: string | null;
  user_name: string | null;
  src_ip: string | null;
  dst_ip: string | null;
  dst_port: number | null;
  domain: string | null;
  url: string | null;
  process_name: string | null;
  command_line: string | null;
  parent_process: string | null;
  file_hash: string | null;
  target_user: string | null;
  group_name: string | null;
  email_sender: string | null;
  email_subject: string | null;
  bytes_out: number | null;
  message: string | null;
  is_synthetic: boolean;
  scenario_id: string | null;
  data_source_id: string;
  data_source_name: string | null;
  raw: Record<string, unknown> | null;
}

export interface RuleMeta {
  id: string;
  name: string;
  description: string;
  severity: Severity;
  confidence: Confidence;
  rationale: string;
  required_telemetry: string[];
  false_positives: string[];
  attack_techniques: string[];
  version: number;
  enabled?: boolean | null;
}

export interface DetectionTest {
  run_at: string;
  passed: boolean;
  precision: number | null;
  recall: number | null;
  true_positives: number;
  false_positives: number;
  true_negatives: number;
  false_negatives: number;
  latency_ms: number;
  cases: { name: string; label: string; outcome: string; known_limitation: string | null }[];
}

export interface RuleRow extends RuleMeta {
  alert_count: number;
  last_alert_at: string | null;
  fixture_count: number;
  latest_test: DetectionTest | null;
  techniques: { id: string; name: string; tactic: string | null }[];
}

export interface Note {
  id: string;
  note_type: "analyst" | "assessment" | "system";
  body: string;
  created_at: string;
  author: UserRef | null;
}

export interface EvidenceItem {
  id: string;
  evidence_type: string;
  title: string;
  description: string | null;
  source_ref: string | null;
  provenance: Record<string, unknown>;
  content: Record<string, unknown>;
  sha256: string;
  created_at: string;
}

export interface TimelineItem {
  at: string;
  kind: "event" | "alert" | "note" | "status" | "action" | "evidence" | "audit";
  title: string;
  detail?: string | null;
  ref_id?: string | null;
  severity?: Severity | null;
  actor?: string | null;
}

export interface AuditEntry {
  id: string;
  actor_label: string;
  action: string;
  target_type: string | null;
  target_id: string | null;
  details: Record<string, unknown>;
  ip: string | null;
  request_id: string | null;
  created_at: string;
}

export interface ResponseAction {
  id: string;
  incident_id: string;
  incident_number: number | null;
  playbook_run_id: string | null;
  action_type: string;
  parameters: Record<string, unknown>;
  requested_by: string | null;
  requested_by_name: string | null;
  status: "pending_approval" | "approved" | "rejected" | "executed" | "failed" | "cancelled";
  requires_approval: boolean;
  simulated: boolean;
  result: Record<string, unknown>;
  error: string | null;
  rollback_plan: string | null;
  created_at: string;
  updated_at: string;
  executed_at: string | null;
  approval: { decision: string; reason: string; decided_by: string | null; decided_at: string } | null;
}

export interface Playbook {
  id: string;
  name: string;
  description: string;
  category: string;
  requires_approval: boolean;
  min_role: Role;
  simulated: boolean;
  rollback_plan: string | null;
}

export interface PlaybookStep {
  kind: "action" | "task";
  title: string;
  action: string | null;
  instructions: string | null;
}

export interface CustomPlaybook {
  id: string;
  name: string;
  description: string;
  steps: PlaybookStep[];
  trigger_rules: string[];
  created_by: string | null;
  updated_at: string;
  suggested: boolean;
}

export type RunStepStatus = "pending" | "done" | "skipped" | "awaiting_approval" | "failed";

export interface RunStep extends PlaybookStep {
  status: RunStepStatus;
  note: string | null;
  by: string | null;
  at: string | null;
  playbook_run_id: string | null;
}

export interface CustomPlaybookRun {
  id: string;
  playbook_id: string;
  incident_id: string;
  name: string;
  status: "in_progress" | "completed";
  started_by: string | null;
  started_at: string | null;
  completed_at: string | null;
  steps: RunStep[];
}

export interface Indicator {
  id: string;
  ioc_type: string;
  value: string;
  analyst_verdict: "unknown" | "benign" | "suspicious" | "malicious";
  analyst_note: string | null;
  first_seen: string;
  last_looked_up: string | null;
  lookup_count: number;
}

export interface Enrichment {
  id?: string;
  provider: string;
  provider_label?: string;
  terms_url?: string;
  status: string;
  reported_verdict: string;
  score?: number | null;
  confidence?: string | null;
  summary?: Record<string, unknown>;
  error?: string | null;
  fetched_at?: string;
  expires_at?: string | null;
  cached?: boolean;
}

export interface LocalSightings {
  event_count: number;
  first_seen: string | null;
  last_seen: string | null;
  hosts: { host: string; count: number }[];
  sample_events: { id: string; event_time: string; event_type: string; host: string | null }[];
  incidents_with_matching_evidence: { id: string; number: number; title: string; status: string; severity: Severity }[];
}

export interface DataSource {
  id: string;
  name: string;
  source_type: string;
  description: string | null;
  is_enabled: boolean;
  is_synthetic: boolean;
  event_count: number;
  last_event_at: string | null;
  has_ingest_key: boolean;
  ingest_key_prefix: string | null;
  created_at: string;
}
