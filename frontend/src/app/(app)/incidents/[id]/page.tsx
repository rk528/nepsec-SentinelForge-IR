"use client";

import * as Tabs from "@radix-ui/react-tabs";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowUpRight, Check, FileText, Pencil, Play, Search, ShieldQuestion, X } from "lucide-react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { useMemo, useState } from "react";

import { EventList, EvidenceList, Timeline } from "@/components/investigation";
import {
  AlertStatusBadge,
  ConfidenceMeter,
  IncidentStatusBadge,
  IntelVerdictBadge,
  SeverityBadge,
  SimulatedBadge,
  SyntheticBadge,
  Tag,
  VERDICT_OPTIONS,
  VerdictBadge,
} from "@/components/ui/badges";
import { ConfirmDialog, Dialog, useToast } from "@/components/ui/overlays";
import { Button, ButtonLink, EmptyState, ErrorState, Field, Input, PageHeader, Panel, Select, Skeleton, Textarea, cn } from "@/components/ui/primitives";
import { ApiError, api, newIdempotencyKey } from "@/lib/api";
import { formatDateTime, formatMinutes, humanize, plural, relativeTime, utcTitle } from "@/lib/format";
import { useCan, useMe } from "@/lib/hooks";
import { SEVERITY_OPTIONS, TRANSITIONS, TRANSITION_LABEL } from "@/lib/options";
import type { Alert, AuditEntry, EventRecord, EvidenceItem, Incident, IncidentStatus, Indicator, Note, Page, Playbook, ResponseAction, TimelineItem, UserRef, Verdict } from "@/lib/types";

type LinkedIndicator = { indicator: Indicator; providers: { provider: string; status: string; reported_verdict: string; fetched_at: string }[] };

function errText(e: unknown) {
  return e instanceof ApiError ? e.detail : "Unexpected error";
}

function useIncidentMutation<T>(id: string, fn: (v: T) => Promise<unknown>, success: string) {
  const qc = useQueryClient();
  const toast = useToast();
  return useMutation({
    mutationFn: fn,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["incident", id] });
      qc.invalidateQueries({ queryKey: ["incidents"] });
      toast({ kind: "success", title: success });
    },
    onError: (e) => {
      toast({ kind: "error", title: "Action failed", description: errText(e) });
      if (e instanceof ApiError && e.status === 409) qc.invalidateQueries({ queryKey: ["incident", id] });
    },
  });
}

// --- transition dialog ----------------------------------------------------------------------

function TransitionDialog({ incident, target, onClose }: { incident: Incident; target: IncidentStatus | null; onClose: () => void }) {
  const [verdict, setVerdict] = useState<Verdict | "">(incident.verdict ?? "");
  const [reason, setReason] = useState("");
  const [closure, setClosure] = useState("");
  const m = useIncidentMutation(incident.id, (body: object) => api(`/incidents/${incident.id}/transition`, { method: "POST", body }), `Status changed to ${target}`);
  if (!target) return null;
  const closing = target === "closed";
  const reopening = incident.status === "closed";
  const valid = closing ? !!verdict && closure.trim().length >= 5 : reopening ? reason.trim().length >= 5 : true;
  return (
    <Dialog
      open
      onOpenChange={(o) => !o && onClose()}
      title={reopening ? `Reopen ${incident.reference}` : `${TRANSITION_LABEL[target]}`}
      description={closing ? "Record the verdict and why the incident can be closed. Pending response actions block closure." : reopening ? "Reopening requires the lead role and is recorded in the audit log." : `Move ${incident.reference} from ${incident.status} to ${target}.`}
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button
            variant={closing ? "primary" : "primary"}
            disabled={!valid}
            loading={m.isPending}
            onClick={() =>
              m.mutate(
                { version: incident.version, status: target, verdict: verdict || null, closure_reason: closing ? closure : null, reason: reopening ? reason : reason || null },
                { onSuccess: onClose },
              )
            }
          >
            {reopening ? "Reopen" : TRANSITION_LABEL[target]}
          </Button>
        </>
      }
    >
      <div className="space-y-3">
        {closing && (
          <>
            <fieldset>
              <legend className="mb-1.5 text-xs font-medium text-muted">Verdict</legend>
              <div className="space-y-1.5">
                {VERDICT_OPTIONS.map((v) => (
                  <label key={v.value} className={cn("flex cursor-pointer gap-2.5 rounded-md border px-3 py-2", verdict === v.value ? "border-accent/60 bg-accent-soft" : "border-line-strong hover:bg-overlay")}>
                    <input type="radio" name="verdict" value={v.value} checked={verdict === v.value} onChange={() => setVerdict(v.value)} className="mt-0.5 accent-[var(--color-accent)]" />
                    <span>
                      <span className="block text-sm text-fg">{v.label}</span>
                      <span className="block text-xs text-muted">{v.help}</span>
                    </span>
                  </label>
                ))}
              </div>
            </fieldset>
            <Field label="Closure reason" htmlFor="closure" hint="What was done and why no further action is needed.">
              <Textarea id="closure" value={closure} onChange={(e) => setClosure(e.target.value)} maxLength={4000} />
            </Field>
          </>
        )}
        {reopening && (
          <Field label="Reason for reopening" htmlFor="reopen-reason">
            <Textarea id="reopen-reason" value={reason} onChange={(e) => setReason(e.target.value)} maxLength={2000} />
          </Field>
        )}
        {!closing && !reopening && (
          <Field label="Comment (optional)" htmlFor="t-reason" hint="Added to the status-change note.">
            <Input id="t-reason" value={reason} onChange={(e) => setReason(e.target.value)} maxLength={2000} />
          </Field>
        )}
      </div>
    </Dialog>
  );
}

// --- properties rail --------------------------------------------------------------------------

function PropertiesRail({ incident }: { incident: Incident }) {
  const canEdit = useCan("analyst") && incident.status !== "closed";
  const users = useQuery({ queryKey: ["users"], queryFn: () => api<UserRef[]>("/users"), staleTime: 5 * 60_000 });
  const m = useIncidentMutation(incident.id, (body: object) => api(`/incidents/${incident.id}`, { method: "PATCH", body: { version: incident.version, ...body } }), "Incident updated");
  const mtta = incident.acknowledged_at ? (new Date(incident.acknowledged_at).getTime() - new Date(incident.created_at).getTime()) / 60000 : null;
  const mttr = incident.resolved_at ? (new Date(incident.resolved_at).getTime() - new Date(incident.created_at).getTime()) / 60000 : null;
  return (
    <div className="space-y-4">
      <Panel title="Properties" id="props">
        <div className="space-y-3 text-sm">
          <div className="flex items-center justify-between gap-3">
            <span className="text-xs text-muted">Status</span>
            <IncidentStatusBadge status={incident.status} />
          </div>
          <div className="flex items-center justify-between gap-3">
            <label htmlFor="sev" className="text-xs text-muted">
              Severity
            </label>
            {canEdit ? (
              <Select id="sev" className="w-36" value={incident.severity} disabled={m.isPending} onChange={(e) => m.mutate({ severity: e.target.value })}>
                {SEVERITY_OPTIONS.map((o) => (
                  <option key={o.value} value={o.value}>
                    {o.label}
                  </option>
                ))}
              </Select>
            ) : (
              <SeverityBadge severity={incident.severity} />
            )}
          </div>
          <div className="flex items-center justify-between gap-3">
            <label htmlFor="assignee" className="text-xs text-muted">
              Assignee
            </label>
            {canEdit ? (
              <Select id="assignee" className="w-36" value={incident.assignee?.id ?? ""} disabled={m.isPending} onChange={(e) => m.mutate(e.target.value ? { assignee_id: e.target.value } : { clear_assignee: true })}>
                <option value="">Unassigned</option>
                {users.data?.map((u) => (
                  <option key={u.id} value={u.id}>
                    {u.display_name}
                  </option>
                ))}
              </Select>
            ) : (
              <span className="text-xs text-fg">{incident.assignee?.display_name ?? "Unassigned"}</span>
            )}
          </div>
          <div className="flex items-center justify-between gap-3">
            <span className="text-xs text-muted">Verdict</span>
            <VerdictBadge verdict={incident.verdict} />
          </div>
          <div className="flex items-center justify-between gap-3">
            <span className="text-xs text-muted">Source</span>
            <span className="text-xs text-fg capitalize">{incident.source}</span>
          </div>
          <div>
            <span className="text-xs text-muted">Tags</span>
            <div className="mt-1 flex flex-wrap gap-1">{incident.tags.length ? incident.tags.map((t) => <Tag key={t}>{t}</Tag>) : <span className="text-xs text-subtle">None</span>}</div>
          </div>
        </div>
      </Panel>
      <Panel title="Timestamps" description="Local time; hover for UTC" id="times">
        <dl className="space-y-2 text-xs">
          {(
            [
              ["Opened", incident.created_at],
              ["Acknowledged", incident.acknowledged_at],
              ["Contained", incident.contained_at],
              ["Resolved", incident.resolved_at],
              ["Closed", incident.closed_at],
            ] as const
          ).map(([label, at]) => (
            <div key={label} className="flex justify-between gap-3">
              <dt className="text-muted">{label}</dt>
              <dd className={at ? "text-fg" : "text-subtle"} title={utcTitle(at)}>
                {at ? formatDateTime(at) : "—"}
              </dd>
            </div>
          ))}
          <div className="flex justify-between gap-3 border-t border-line pt-2">
            <dt className="text-muted">Time to acknowledge</dt>
            <dd className="text-fg">{formatMinutes(mtta)}</dd>
          </div>
          <div className="flex justify-between gap-3">
            <dt className="text-muted">Time to resolve</dt>
            <dd className="text-fg">{formatMinutes(mttr)}</dd>
          </div>
        </dl>
      </Panel>
      <Panel title="Closure assessment" id="closure">
        {incident.status === "closed" ? (
          <div className="space-y-2">
            <VerdictBadge verdict={incident.verdict} />
            <p className="text-sm whitespace-pre-wrap text-fg">{incident.closure_reason}</p>
          </div>
        ) : (
          <p className="text-xs text-muted">Closing requires a verdict and a closure reason, and no pending response actions. True positive, benign positive, false positive and undetermined are recorded separately from severity.</p>
        )}
      </Panel>
    </div>
  );
}

// --- notes ------------------------------------------------------------------------------------

function NotesTab({ incident }: { incident: Incident }) {
  const canWrite = useCan("analyst") && incident.status !== "closed";
  const notes = useQuery({ queryKey: ["incident", incident.id, "notes"], queryFn: () => api<Note[]>(`/incidents/${incident.id}/notes`) });
  const [body, setBody] = useState("");
  const [type, setType] = useState<"analyst" | "assessment">("analyst");
  const m = useIncidentMutation(incident.id, (b: object) => api(`/incidents/${incident.id}/notes`, { method: "POST", body: b }), "Note added");
  const visible = notes.data?.filter((n) => n.note_type !== "system") ?? [];
  return (
    <div className="space-y-4 p-4">
      {canWrite && (
        <form
          onSubmit={(e) => {
            e.preventDefault();
            if (body.trim()) m.mutate({ body, note_type: type }, { onSuccess: () => setBody("") });
          }}
          className="space-y-2"
        >
          <label htmlFor="note" className="sr-only">
            New note
          </label>
          <Textarea id="note" value={body} onChange={(e) => setBody(e.target.value)} placeholder="Record an observation, hypothesis or decision. Notes are append-only." maxLength={10000} />
          <div className="flex items-center justify-between gap-2">
            <Select aria-label="Note type" className="w-48" value={type} onChange={(e) => setType(e.target.value as "analyst" | "assessment")}>
              <option value="analyst">Analyst note</option>
              <option value="assessment">Assessment (in report)</option>
            </Select>
            <Button type="submit" variant="primary" size="sm" loading={m.isPending} disabled={!body.trim()}>
              Add note
            </Button>
          </div>
        </form>
      )}
      {notes.isError ? (
        <ErrorState error={notes.error} onRetry={() => notes.refetch()} />
      ) : !notes.data ? (
        <Skeleton className="h-20" />
      ) : visible.length === 0 ? (
        <EmptyState title="No notes yet" description="Analyst notes and assessments appear here and in the report." />
      ) : (
        <ul className="space-y-3">
          {visible
            .slice()
            .reverse()
            .map((n) => (
              <li key={n.id} className={cn("rounded-lg border p-3", n.note_type === "assessment" ? "border-accent/30 bg-accent-soft/40" : "border-line bg-raised/40")}>
                <div className="mb-1.5 flex items-center justify-between gap-2 text-xs">
                  <span className="font-medium text-fg">
                    {n.author?.display_name ?? "Unknown"}
                    {n.note_type === "assessment" && <span className="ml-2 text-accent">Assessment</span>}
                  </span>
                  <span className="text-subtle" title={utcTitle(n.created_at)}>
                    {formatDateTime(n.created_at)}
                  </span>
                </div>
                <p className="text-sm whitespace-pre-wrap text-fg">{n.body}</p>
              </li>
            ))}
        </ul>
      )}
    </div>
  );
}

// --- indicators -------------------------------------------------------------------------------

function IndicatorsTab({ incident }: { incident: Incident }) {
  const canLookup = useCan("analyst") && incident.status !== "closed";
  const qc = useQueryClient();
  const toast = useToast();
  const linked = useQuery({ queryKey: ["incident", incident.id, "indicators"], queryFn: () => api<LinkedIndicator[]>(`/incidents/${incident.id}/indicators`) });
  const [value, setValue] = useState("");
  const m = useMutation({
    mutationFn: () => api("/iocs/lookup", { method: "POST", body: { value, incident_id: incident.id } }),
    onSuccess: () => {
      setValue("");
      qc.invalidateQueries({ queryKey: ["incident", incident.id] });
      toast({ kind: "success", title: "Indicator investigated and linked" });
    },
    onError: (e) => toast({ kind: "error", title: "Lookup failed", description: errText(e) }),
  });
  return (
    <div className="space-y-4 p-4">
      {canLookup && (
        <form
          onSubmit={(e) => {
            e.preventDefault();
            if (value.trim()) m.mutate();
          }}
          className="flex gap-2"
        >
          <label htmlFor="ioc" className="sr-only">
            Indicator
          </label>
          <Input id="ioc" value={value} onChange={(e) => setValue(e.target.value)} placeholder="IP, domain, URL or hash (defanged input is accepted)" maxLength={2048} />
          <Button type="submit" icon={<Search className="size-3.5" aria-hidden />} loading={m.isPending} disabled={!value.trim()}>
            Investigate
          </Button>
        </form>
      )}
      {!linked.data ? (
        <Skeleton className="h-16" />
      ) : linked.data.length === 0 ? (
        <EmptyState icon={<ShieldQuestion className="size-5" aria-hidden />} title="No indicators linked" description="Investigate an indicator here, or run the 'Enrich associated IOCs' playbook to extract them from linked events." />
      ) : (
        <ul className="divide-y divide-line rounded-lg border border-line">
          {linked.data.map(({ indicator, providers }) => (
            <li key={indicator.id} className="flex flex-col gap-2 px-3 py-2.5 sm:flex-row sm:items-center">
              <div className="min-w-0 flex-1">
                <Link href={`/threat-intel?id=${indicator.id}`} className="mono text-sm break-all text-fg hover:underline">
                  {indicator.value}
                </Link>
                <p className="text-xs text-subtle uppercase">{indicator.ioc_type}</p>
              </div>
              <div className="flex flex-wrap items-center gap-2 text-xs">
                <span className="text-muted">Analyst:</span>
                <IntelVerdictBadge verdict={indicator.analyst_verdict} />
                <span className="ml-2 text-muted">Providers:</span>
                {providers.length ? providers.map((p) => <span key={p.provider} title={`${p.provider}: ${p.status}`}><IntelVerdictBadge verdict={p.status === "ok" ? p.reported_verdict : "unknown"} /></span>) : <span className="text-subtle">no data</span>}
              </div>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

// --- response ------------------------------------------------------------------------------------

function ResponseTab({ incident, events }: { incident: Incident; events: EventRecord[] }) {
  const { data: me } = useMe();
  const canRun = useCan("analyst");
  const isLead = useCan("lead");
  const qc = useQueryClient();
  const toast = useToast();
  const playbooks = useQuery({ queryKey: ["playbooks"], queryFn: () => api<Playbook[]>("/playbooks"), staleTime: 10 * 60_000 });
  const actions = useQuery({ queryKey: ["incident", incident.id, "actions"], queryFn: () => api<Page<ResponseAction>>("/response-actions", { query: { incident_id: incident.id, page_size: 50 } }) });
  const [confirm, setConfirm] = useState<Playbook | null>(null);
  const [ips, setIps] = useState("");
  const [decision, setDecision] = useState<{ action: ResponseAction; decision: "approved" | "rejected" } | null>(null);
  const [reason, setReason] = useState("");

  const externalIps = useMemo(() => {
    const set = new Set<string>();
    for (const e of events) for (const ip of [e.src_ip, e.dst_ip]) if (ip && !/^(10\.|192\.168\.|127\.|172\.(1[6-9]|2\d|3[01])\.)/.test(ip)) set.add(ip);
    return [...set];
  }, [events]);

  const run = useMutation({
    mutationFn: (pb: Playbook) =>
      api<{ status: string; idempotent_replay: boolean }>(`/playbooks/${pb.id}/run`, {
        method: "POST",
        body: { incident_id: incident.id, idempotency_key: newIdempotencyKey(pb.id), parameters: pb.id === "simulate_firewall_block" ? { ip_addresses: ips.split(/[\s,]+/).filter(Boolean), duration_hours: 24 } : {} },
      }),
    onSuccess: (r, pb) => {
      qc.invalidateQueries({ queryKey: ["incident", incident.id] });
      toast({ kind: r.status === "failed" ? "error" : "success", title: `${pb.name}: ${humanize(r.status)}` });
      setConfirm(null);
    },
    onError: (e) => toast({ kind: "error", title: "Playbook not run", description: errText(e) }),
  });
  const decide = useMutation({
    mutationFn: () => api<ResponseAction>(`/response-actions/${decision!.action.id}/decision`, { method: "POST", body: { decision: decision!.decision, reason } }),
    onSuccess: (a) => {
      qc.invalidateQueries({ queryKey: ["incident", incident.id] });
      qc.invalidateQueries({ queryKey: ["response-actions"] });
      toast({ kind: "success", title: `Action ${humanize(a.status).toLowerCase()}` });
      setDecision(null);
      setReason("");
    },
    onError: (e) => toast({ kind: "error", title: "Decision not recorded", description: errText(e) }),
  });

  return (
    <div className="space-y-5 p-4">
      <div>
        <h3 className="mb-2 text-xs font-medium tracking-wide text-subtle uppercase">Playbooks</h3>
        {!playbooks.data ? (
          <Skeleton className="h-24" />
        ) : (
          <ul className="grid gap-2 sm:grid-cols-2">
            {playbooks.data.map((pb) => (
              <li key={pb.id} className="flex flex-col justify-between gap-2 rounded-lg border border-line bg-raised/30 p-3">
                <div>
                  <p className="flex flex-wrap items-center gap-2 text-sm font-medium text-fg">
                    {pb.name}
                    {pb.simulated && <SimulatedBadge />}
                    {pb.requires_approval && <span className="text-xs text-warn">Needs approval</span>}
                  </p>
                  <p className="mt-1 text-xs text-muted">{pb.description}</p>
                </div>
                {canRun && (incident.status !== "closed" || pb.id === "closure_report") && (
                  <Button
                    size="sm"
                    className="self-start"
                    icon={<Play className="size-3" aria-hidden />}
                    onClick={() => {
                      setIps(externalIps.join(", "));
                      setConfirm(pb);
                    }}
                  >
                    Run
                  </Button>
                )}
              </li>
            ))}
          </ul>
        )}
      </div>

      <div>
        <h3 className="mb-2 text-xs font-medium tracking-wide text-subtle uppercase">Response actions</h3>
        {!actions.data ? (
          <Skeleton className="h-16" />
        ) : actions.data.items.length === 0 ? (
          <EmptyState title="No response actions yet" description="Running a playbook records an action with its parameters, requester and result." />
        ) : (
          <ul className="divide-y divide-line rounded-lg border border-line">
            {actions.data.items.map((a) => {
              const mine = a.requested_by === me?.id;
              const canDecide = a.status === "pending_approval" && isLead && !mine;
              return (
                <li key={a.id} className="space-y-1.5 px-3 py-2.5">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-sm font-medium text-fg">{humanize(a.action_type)}</span>
                    <span className={cn("rounded px-1.5 py-px text-xs", a.status === "pending_approval" ? "bg-warn/15 text-warn" : a.status === "executed" ? "bg-ok/10 text-ok" : a.status === "failed" ? "bg-danger/15 text-danger" : "bg-raised text-muted")}>{humanize(a.status)}</span>
                    {a.simulated && <SimulatedBadge />}
                    <span className="ml-auto text-xs text-subtle" title={utcTitle(a.created_at)}>
                      {a.requested_by_name ?? "Unknown"} · {relativeTime(a.created_at)}
                    </span>
                  </div>
                  {Object.keys(a.parameters).length > 0 && <p className="mono text-xs break-all text-muted">{JSON.stringify(a.parameters)}</p>}
                  {a.approval && (
                    <p className="text-xs text-muted">
                      {humanize(a.approval.decision)} by {a.approval.decided_by}: “{a.approval.reason}”
                    </p>
                  )}
                  {a.error && <p className="text-xs text-danger">{a.error}</p>}
                  {a.status === "pending_approval" && (
                    <div className="flex flex-wrap items-center gap-2 pt-1">
                      {canDecide ? (
                        <>
                          <Button size="sm" variant="primary" icon={<Check className="size-3" aria-hidden />} onClick={() => setDecision({ action: a, decision: "approved" })}>
                            Approve
                          </Button>
                          <Button size="sm" variant="danger" icon={<X className="size-3" aria-hidden />} onClick={() => setDecision({ action: a, decision: "rejected" })}>
                            Reject
                          </Button>
                        </>
                      ) : (
                        <span className="text-xs text-subtle">{mine ? "You requested this action, so another lead must approve it." : "Awaiting approval from a lead."}</span>
                      )}
                    </div>
                  )}
                </li>
              );
            })}
          </ul>
        )}
      </div>

      <ConfirmDialog
        open={!!confirm}
        onOpenChange={(o) => !o && setConfirm(null)}
        title={confirm ? `Run “${confirm.name}”?` : ""}
        description={confirm?.requires_approval ? "This creates a request that a different lead must approve. Execution is simulated; no firewall is contacted." : confirm?.description}
        confirmLabel={confirm?.requires_approval ? "Request approval" : "Run playbook"}
        loading={run.isPending}
        onConfirm={() => confirm && run.mutate(confirm)}
      >
        {confirm?.id === "simulate_firewall_block" && (
          <Field label="External IP addresses to block" htmlFor="ips" hint="Comma separated. Internal and reserved addresses are refused by the server.">
            <Input id="ips" value={ips} onChange={(e) => setIps(e.target.value)} className="mono" />
          </Field>
        )}
      </ConfirmDialog>

      <ConfirmDialog
        open={!!decision}
        onOpenChange={(o) => !o && setDecision(null)}
        title={decision?.decision === "approved" ? "Approve simulated action" : "Reject action"}
        description="Your decision and reason are recorded in the audit log."
        confirmLabel={decision?.decision === "approved" ? "Approve" : "Reject"}
        destructive={decision?.decision === "rejected"}
        loading={decide.isPending}
        onConfirm={() => reason.trim().length >= 3 && decide.mutate()}
      >
        <Field label="Reason" htmlFor="decision-reason">
          <Textarea id="decision-reason" value={reason} onChange={(e) => setReason(e.target.value)} maxLength={2000} />
        </Field>
      </ConfirmDialog>
    </div>
  );
}

// --- page --------------------------------------------------------------------------------------

function SummaryEditor({ incident }: { incident: Incident }) {
  const [open, setOpen] = useState(false);
  const [summary, setSummary] = useState(incident.summary);
  const m = useIncidentMutation(incident.id, (b: object) => api(`/incidents/${incident.id}`, { method: "PATCH", body: { version: incident.version, ...b } }), "Summary updated");
  const canEdit = useCan("analyst") && incident.status !== "closed";
  return (
    <>
      {canEdit && (
        <Button size="sm" variant="ghost" icon={<Pencil className="size-3" aria-hidden />} onClick={() => { setSummary(incident.summary); setOpen(true); }}>
          Edit
        </Button>
      )}
      <Dialog
        open={open}
        onOpenChange={setOpen}
        title="Edit summary"
        description="The summary is analyst-written. Generated summaries are stored separately as evidence and never overwrite this text."
        footer={<Button variant="primary" loading={m.isPending} onClick={() => m.mutate({ summary }, { onSuccess: () => setOpen(false) })}>Save</Button>}
      >
        <label htmlFor="summary-edit" className="sr-only">Summary</label>
        <Textarea id="summary-edit" className="min-h-40" value={summary} onChange={(e) => setSummary(e.target.value)} maxLength={10000} />
      </Dialog>
    </>
  );
}

const TAB = "shrink-0 whitespace-nowrap border-b-2 border-transparent px-3 pb-2.5 pt-3 text-sm text-muted transition-colors hover:text-fg data-[state=active]:border-accent data-[state=active]:font-medium data-[state=active]:text-fg";

export default function IncidentDetailPage() {
  const { id } = useParams<{ id: string }>();
  const canTransition = useCan("analyst");
  const isLead = useCan("lead");
  const [target, setTarget] = useState<IncidentStatus | null>(null);

  const incident = useQuery({ queryKey: ["incident", id], queryFn: () => api<Incident>(`/incidents/${id}`) });
  const timeline = useQuery({ queryKey: ["incident", id, "timeline"], queryFn: () => api<TimelineItem[]>(`/incidents/${id}/timeline`), enabled: incident.isSuccess });
  const events = useQuery({ queryKey: ["incident", id, "events"], queryFn: () => api<EventRecord[]>(`/incidents/${id}/events`), enabled: incident.isSuccess });
  const alerts = useQuery({ queryKey: ["incident", id, "alerts"], queryFn: () => api<Alert[]>(`/incidents/${id}/alerts`), enabled: incident.isSuccess });
  const evidence = useQuery({ queryKey: ["incident", id, "evidence"], queryFn: () => api<EvidenceItem[]>(`/incidents/${id}/evidence`), enabled: incident.isSuccess });
  const auditLog = useQuery({ queryKey: ["incident", id, "audit"], queryFn: () => api<AuditEntry[]>(`/incidents/${id}/audit`), enabled: incident.isSuccess });

  if (incident.isError) {
    const notFound = incident.error instanceof ApiError && incident.error.status === 404;
    return (
      <>
        <PageHeader title={notFound ? "Incident not found" : "Incident"} breadcrumbs={[{ label: "Incidents", href: "/incidents" }, { label: "Unavailable" }]} />
        <Panel>{notFound ? <EmptyState title="This incident does not exist or you do not have access to it." action={<ButtonLink href="/incidents">Back to incidents</ButtonLink>} /> : <ErrorState error={incident.error} onRetry={() => incident.refetch()} />}</Panel>
      </>
    );
  }
  if (!incident.data) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-4 w-40" />
        <Skeleton className="h-7 w-2/3" />
        <div className="grid gap-4 lg:grid-cols-3">
          <Skeleton className="h-96 lg:col-span-2" />
          <Skeleton className="h-96" />
        </div>
      </div>
    );
  }
  const inc = incident.data;
  // Reopening a closed incident is offered only to leads; the server enforces this too.
  const next = inc.status === "closed" && !isLead ? [] : TRANSITIONS[inc.status];

  return (
    <>
      <PageHeader
        breadcrumbs={[{ label: "Incidents", href: "/incidents" }, { label: inc.reference }]}
        title={
          <span>
            <span className="mono mr-2 text-muted">{inc.reference}</span>
            {inc.title}
          </span>
        }
        meta={
          <>
            <SeverityBadge severity={inc.severity} />
            <IncidentStatusBadge status={inc.status} />
            {inc.is_synthetic && <SyntheticBadge />}
            <span className="text-xs text-subtle" title={utcTitle(inc.created_at)}>
              Opened {relativeTime(inc.created_at)}
            </span>
          </>
        }
        actions={
          <>
            <ButtonLink href={`/reports/${inc.id}`} icon={<FileText className="size-3.5" aria-hidden />}>
              Report
            </ButtonLink>
            {canTransition &&
              next.map((s, i) => (
                <Button key={s} variant={i === 0 ? "primary" : "secondary"} onClick={() => setTarget(s)}>
                  {inc.status === "closed" ? "Reopen" : TRANSITION_LABEL[s]}
                </Button>
              ))}
          </>
        }
      />

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-[minmax(0,1fr)_320px]">
        <div className="min-w-0 space-y-4">
          <Panel title="Summary" actions={<SummaryEditor incident={inc} />} id="summary">
            {inc.summary ? <p className="text-sm whitespace-pre-wrap text-fg">{inc.summary}</p> : <p className="text-sm text-subtle">No summary yet.</p>}
            <div className="mt-3 flex flex-wrap gap-x-5 gap-y-1 text-xs text-muted">
              <span>{plural(inc.alert_count, "linked alert")}</span>
              <span>{plural(inc.event_count, "evidence event")}</span>
              <span>{evidence.data ? plural(evidence.data.length, "evidence record") : "… evidence records"}</span>
            </div>
          </Panel>

          <Tabs.Root defaultValue="timeline" className="rounded-lg border border-line bg-surface">
            <Tabs.List aria-label="Incident sections" className="flex overflow-x-auto border-b border-line px-2">
              <Tabs.Trigger value="timeline" className={TAB}>Timeline</Tabs.Trigger>
              <Tabs.Trigger value="evidence" className={TAB}>Evidence</Tabs.Trigger>
              <Tabs.Trigger value="alerts" className={TAB}>Alerts <span className="text-subtle">{alerts.data?.length ?? ""}</span></Tabs.Trigger>
              <Tabs.Trigger value="indicators" className={TAB}>Indicators</Tabs.Trigger>
              <Tabs.Trigger value="response" className={TAB}>Response</Tabs.Trigger>
              <Tabs.Trigger value="notes" className={TAB}>Notes</Tabs.Trigger>
              <Tabs.Trigger value="audit" className={TAB}>Audit</Tabs.Trigger>
            </Tabs.List>
            <Tabs.Content value="timeline" className="max-h-[70vh] overflow-y-auto px-4 pb-2">
              {timeline.isError ? <ErrorState error={timeline.error} onRetry={() => timeline.refetch()} /> : !timeline.data ? <Skeleton className="my-4 h-40" /> : <Timeline items={timeline.data} />}
            </Tabs.Content>
            <Tabs.Content value="evidence">
              <h3 className="px-4 pt-3 text-xs font-medium tracking-wide text-subtle uppercase">Supporting events</h3>
              {!events.data ? <Skeleton className="m-4 h-24" /> : <EventList events={events.data} />}
              <h3 className="border-t border-line px-4 pt-3 text-xs font-medium tracking-wide text-subtle uppercase">Evidence records</h3>
              {!evidence.data ? <Skeleton className="m-4 h-24" /> : <EvidenceList items={evidence.data} />}
            </Tabs.Content>
            <Tabs.Content value="alerts">
              {!alerts.data ? (
                <Skeleton className="m-4 h-24" />
              ) : alerts.data.length === 0 ? (
                <EmptyState title="No alerts linked" description="Escalate alerts from the queue to link them here." />
              ) : (
                <ul className="divide-y divide-line">
                  {alerts.data.map((a) => (
                    <li key={a.id}>
                      <Link href={`/alerts/${a.id}`} className="flex flex-col gap-1 px-4 py-3 hover:bg-raised/60 sm:flex-row sm:items-center sm:gap-3">
                        <SeverityBadge severity={a.severity} />
                        <span className="min-w-0 flex-1 truncate text-sm text-fg">{a.title}</span>
                        <span className="mono text-xs text-muted">{a.rule_id}</span>
                        <ConfidenceMeter confidence={a.confidence} />
                        <AlertStatusBadge status={a.status} />
                      </Link>
                    </li>
                  ))}
                </ul>
              )}
            </Tabs.Content>
            <Tabs.Content value="indicators">
              <IndicatorsTab incident={inc} />
            </Tabs.Content>
            <Tabs.Content value="response">
              <ResponseTab incident={inc} events={events.data ?? []} />
            </Tabs.Content>
            <Tabs.Content value="notes">
              <NotesTab incident={inc} />
            </Tabs.Content>
            <Tabs.Content value="audit">
              {!auditLog.data ? (
                <Skeleton className="m-4 h-24" />
              ) : auditLog.data.length === 0 ? (
                <EmptyState title="No audit records" />
              ) : (
                <ul className="divide-y divide-line">
                  {auditLog.data.map((a) => (
                    <li key={a.id} className="flex flex-col gap-0.5 px-5 py-3 sm:flex-row sm:items-center sm:gap-3">
                      <span className="mono w-52 shrink-0 text-xs text-fg">{a.action}</span>
                      <span className="min-w-0 flex-1 truncate text-xs text-muted">{a.actor_label}</span>
                      <span className="text-xs text-subtle" title={utcTitle(a.created_at)}>
                        {formatDateTime(a.created_at)}
                      </span>
                    </li>
                  ))}
                </ul>
              )}
              <div className="border-t border-line px-5 py-3 text-right">
                <Link href={`/audit?target_id=${inc.id}`} className="inline-flex items-center gap-1 text-xs text-accent hover:underline">
                  Search full audit log <ArrowUpRight className="size-3" aria-hidden />
                </Link>
              </div>
            </Tabs.Content>
          </Tabs.Root>
        </div>
        <PropertiesRail incident={inc} />
      </div>
      <TransitionDialog key={target ?? "none"} incident={inc} target={target} onClose={() => setTarget(null)} />
    </>
  );
}
