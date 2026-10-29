"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowUpRight, CheckCircle2, Link2, Siren, Unlink } from "lucide-react";
import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import { useState } from "react";

import { EventList, JsonViewer } from "@/components/investigation";
import { LinkEventsDialog } from "@/components/links";
import { AlertStatusBadge, ConfidenceMeter, SeverityBadge, VERDICT_OPTIONS, VerdictBadge } from "@/components/ui/badges";
import { ConfirmDialog, Dialog, useToast } from "@/components/ui/overlays";
import { Button, ButtonLink, EmptyState, ErrorState, Field, KeyValue, PageHeader, Panel, Select, Skeleton, Textarea } from "@/components/ui/primitives";
import { ApiError, api } from "@/lib/api";
import { formatDateTime, humanize, relativeTime, utcTitle } from "@/lib/format";
import { useCan } from "@/lib/hooks";
import type { Alert, EventRecord, Incident, Page, RuleMeta, Verdict } from "@/lib/types";

interface AlertDetail {
  alert: Alert;
  rule: RuleMeta;
  events: EventRecord[];
  assignee: { id: string; display_name: string } | null;
}

function EscalateDialog({ alert, open, onOpenChange }: { alert: Alert; open: boolean; onOpenChange: (o: boolean) => void }) {
  const router = useRouter();
  const toast = useToast();
  const qc = useQueryClient();
  const [mode, setMode] = useState<"new" | "existing">("new");
  const [incidentId, setIncidentId] = useState("");
  const open_ = useQuery({
    queryKey: ["incidents", "open-for-link"],
    queryFn: () => api<Page<Incident>>("/incidents", { query: { status: ["new", "open", "investigating", "contained", "resolved"], page_size: 50 } }),
    enabled: open,
  });
  const m = useMutation({
    mutationFn: () => api<{ incident_id: string; reference: string; created: boolean }>(`/alerts/${alert.id}/escalate`, { method: "POST", body: mode === "existing" ? { incident_id: incidentId } : {} }),
    onSuccess: (r) => {
      qc.invalidateQueries({ queryKey: ["alert", alert.id] });
      qc.invalidateQueries({ queryKey: ["alerts"] });
      qc.invalidateQueries({ queryKey: ["incidents"] });
      toast({ kind: "success", title: r.created ? `${r.reference} opened` : `Linked to ${r.reference}` });
      router.push(`/incidents/${r.incident_id}`);
    },
    onError: (e) => toast({ kind: "error", title: "Escalation failed", description: e instanceof ApiError ? e.detail : undefined }),
  });
  return (
    <Dialog
      open={open}
      onOpenChange={onOpenChange}
      title="Escalate alert"
      description="Linking copies the alert's matching events into the incident as evidence."
      footer={
        <Button variant="primary" loading={m.isPending} disabled={mode === "existing" && !incidentId} onClick={() => m.mutate()}>
          {mode === "new" ? "Create incident" : "Link to incident"}
        </Button>
      }
    >
      <fieldset className="space-y-2">
        <legend className="sr-only">Escalation target</legend>
        <label className="flex items-center gap-2 text-sm text-fg">
          <input type="radio" name="mode" checked={mode === "new"} onChange={() => setMode("new")} className="accent-[var(--color-accent)]" /> Create a new incident
        </label>
        <label className="flex items-center gap-2 text-sm text-fg">
          <input type="radio" name="mode" checked={mode === "existing"} onChange={() => setMode("existing")} className="accent-[var(--color-accent)]" /> Link to an existing incident
        </label>
        {mode === "existing" && (
          <Field label="Incident" htmlFor="link-incident">
            <Select id="link-incident" value={incidentId} onChange={(e) => setIncidentId(e.target.value)}>
              <option value="">Select an open incident…</option>
              {open_.data?.items.map((i) => (
                <option key={i.id} value={i.id}>
                  {i.reference} · {i.title}
                </option>
              ))}
            </Select>
          </Field>
        )}
      </fieldset>
    </Dialog>
  );
}

function TriageDialog({ alert, open, onOpenChange }: { alert: Alert; open: boolean; onOpenChange: (o: boolean) => void }) {
  const toast = useToast();
  const qc = useQueryClient();
  const [disposition, setDisposition] = useState<Verdict>("false_positive");
  const [reason, setReason] = useState("");
  const m = useMutation({
    mutationFn: () => api(`/alerts/${alert.id}`, { method: "PATCH", body: { status: "closed", disposition, disposition_reason: reason } }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["alert", alert.id] });
      qc.invalidateQueries({ queryKey: ["alerts"] });
      toast({ kind: "success", title: "Alert closed" });
      onOpenChange(false);
    },
    onError: (e) => toast({ kind: "error", title: "Triage not saved", description: e instanceof ApiError ? e.detail : undefined }),
  });
  return (
    <Dialog
      open={open}
      onOpenChange={onOpenChange}
      title="Close alert with a decision"
      description="The disposition and reason are stored on the alert and in the audit log."
      footer={
        <Button variant="primary" loading={m.isPending} disabled={reason.trim().length < 3} onClick={() => m.mutate()}>
          Close alert
        </Button>
      }
    >
      <div className="space-y-3">
        <Field label="Disposition" htmlFor="disp">
          <Select id="disp" value={disposition} onChange={(e) => setDisposition(e.target.value as Verdict)}>
            {VERDICT_OPTIONS.map((v) => (
              <option key={v.value} value={v.value}>
                {v.label}
              </option>
            ))}
          </Select>
        </Field>
        <p className="text-xs text-muted">{VERDICT_OPTIONS.find((v) => v.value === disposition)?.help}</p>
        <Field label="Reason" htmlFor="disp-reason">
          <Textarea id="disp-reason" value={reason} onChange={(e) => setReason(e.target.value)} maxLength={4000} />
        </Field>
      </div>
    </Dialog>
  );
}

export default function AlertDetailPage() {
  const { id } = useParams<{ id: string }>();
  const canTriage = useCan("analyst");
  const toast = useToast();
  const qc = useQueryClient();
  const [escalating, setEscalating] = useState(false);
  const [closing, setClosing] = useState(false);
  const [linking, setLinking] = useState(false);
  const [unlinking, setUnlinking] = useState(false);
  const q = useQuery({ queryKey: ["alert", id], queryFn: () => api<AlertDetail>(`/alerts/${id}`) });
  const ack = useMutation({
    mutationFn: () => api(`/alerts/${id}`, { method: "PATCH", body: { status: "acknowledged" } }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["alert", id] });
      qc.invalidateQueries({ queryKey: ["alerts"] });
      toast({ kind: "success", title: "Alert acknowledged" });
    },
    onError: (e) => toast({ kind: "error", title: "Could not acknowledge", description: e instanceof ApiError ? e.detail : undefined }),
  });

  const unlink = useMutation({
    mutationFn: () => api(`/alerts/${id}/incident`, { method: "DELETE" }),
    onSuccess: () => {
      for (const key of ["alert", "alerts", "incident", "incidents"]) qc.invalidateQueries({ queryKey: [key] });
      toast({ kind: "success", title: "Taken out of the incident" });
      setUnlinking(false);
    },
    onError: (e) => toast({ kind: "error", title: "Not unlinked", description: e instanceof ApiError ? e.detail : undefined }),
  });

  if (q.isError) {
    const notFound = q.error instanceof ApiError && q.error.status === 404;
    return (
      <>
        <PageHeader title="Alert" breadcrumbs={[{ label: "Alerts", href: "/alerts" }, { label: "Unavailable" }]} />
        <Panel>{notFound ? <EmptyState title="This alert does not exist or you do not have access to it." action={<ButtonLink href="/alerts">Back to alerts</ButtonLink>} /> : <ErrorState error={q.error} onRetry={() => q.refetch()} />}</Panel>
      </>
    );
  }
  if (!q.data) return <Skeleton className="h-96" />;
  const { alert, rule, events } = q.data;
  const evidenceEntries = Object.entries(alert.evidence_summary ?? {}).filter(([k]) => k !== "command_line");

  return (
    <>
      <PageHeader
        breadcrumbs={[{ label: "Alerts", href: "/alerts" }, { label: alert.rule_id }]}
        title={alert.title}
        meta={
          <>
            <SeverityBadge severity={alert.severity} />
            <ConfidenceMeter confidence={alert.confidence} />
            <AlertStatusBadge status={alert.status} />
            {alert.disposition && <VerdictBadge verdict={alert.disposition} />}
          </>
        }
        actions={
          canTriage && (
            <>
              {alert.status === "new" && (
                <Button loading={ack.isPending} onClick={() => ack.mutate()} icon={<CheckCircle2 className="size-3.5" aria-hidden />}>
                  Acknowledge
                </Button>
              )}
              <Button icon={<Link2 className="size-3.5" aria-hidden />} onClick={() => setLinking(true)}>
                Link events
              </Button>
              {alert.incident_id && (
                <Button icon={<Unlink className="size-3.5" aria-hidden />} onClick={() => setUnlinking(true)}>
                  Remove from incident
                </Button>
              )}
              {alert.status !== "closed" && !alert.incident_id && <Button onClick={() => setClosing(true)}>Close with decision</Button>}
              {alert.incident_id ? (
                <ButtonLink href={`/incidents/${alert.incident_id}`} variant="primary" icon={<Siren className="size-3.5" aria-hidden />}>
                  Open INC-{String(alert.incident_number ?? 0).padStart(4, "0")}
                </ButtonLink>
              ) : (
                alert.status !== "closed" && (
                  <Button variant="primary" icon={<Siren className="size-3.5" aria-hidden />} onClick={() => setEscalating(true)}>
                    Escalate
                  </Button>
                )
              )}
            </>
          )
        }
      />
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-[minmax(0,1fr)_340px]">
        <div className="min-w-0 space-y-4">
          <Panel title="Why this alert fired" description={alert.description} id="why">
            <KeyValue
              columns={3}
              items={[
                ...Object.entries(alert.entities).map(([k, v]) => ({ label: humanize(k), value: String(v), mono: true })),
                { label: "Matched events", value: String(alert.occurrence_count) },
                { label: "First seen", value: <span title={utcTitle(alert.first_seen)}>{formatDateTime(alert.first_seen)}</span> },
                { label: "Last seen", value: <span title={utcTitle(alert.last_seen)}>{formatDateTime(alert.last_seen)}</span> },
              ]}
            />
            {evidenceEntries.length > 0 && (
              <div className="mt-4">
                <p className="mb-1 text-xs font-medium tracking-wide text-subtle uppercase">Rule evidence</p>
                <JsonViewer value={Object.fromEntries(evidenceEntries)} maxHeight="12rem" />
              </div>
            )}
            {typeof alert.evidence_summary.command_line === "string" && (
              <div className="mt-4">
                <p className="mb-1 text-xs font-medium tracking-wide text-subtle uppercase">Command line (untrusted)</p>
                <JsonViewer value={alert.evidence_summary.command_line} maxHeight="8rem" />
              </div>
            )}
            {alert.disposition_reason && (
              <p className="mt-4 rounded-md border border-line bg-raised/40 p-3 text-sm text-fg">
                <span className="mb-1 block text-xs font-medium tracking-wide text-subtle uppercase">Triage decision</span>
                {alert.disposition_reason}
              </p>
            )}
          </Panel>
          <Panel title="Matching events" description="The events the rule matched, and any linked by an analyst. Select a timestamp to view the full record." bodyClassName="p-0" id="events">
            <EventList events={events} />
          </Panel>
        </div>
        <div className="space-y-4">
          <Panel title={rule.name} description={<span className="mono">{rule.id} · v{rule.version}</span>} id="rule">
            <div className="space-y-3 text-sm">
              <p className="text-muted">{rule.description}</p>
              <div>
                <p className="text-xs font-medium tracking-wide text-subtle uppercase">Rationale</p>
                <p className="mt-0.5 text-fg">{rule.rationale}</p>
              </div>
              <div>
                <p className="text-xs font-medium tracking-wide text-subtle uppercase">Required telemetry</p>
                <ul className="mt-0.5 list-disc space-y-0.5 pl-4 text-xs text-muted">
                  {rule.required_telemetry.map((t) => (
                    <li key={t} className="mono">{t}</li>
                  ))}
                </ul>
              </div>
              <div>
                <p className="text-xs font-medium tracking-wide text-subtle uppercase">Known false positives</p>
                <ul className="mt-0.5 list-disc space-y-0.5 pl-4 text-xs text-muted">
                  {rule.false_positives.map((t) => (
                    <li key={t}>{t}</li>
                  ))}
                </ul>
              </div>
              <div>
                <p className="text-xs font-medium tracking-wide text-subtle uppercase">ATT&amp;CK (design intent)</p>
                <p className="mono mt-0.5 text-xs text-muted">{rule.attack_techniques.join(", ")}</p>
              </div>
              <Link href={`/detections#${rule.id}`} className="inline-flex items-center gap-1 text-xs text-accent hover:underline">
                Rule tests and coverage <ArrowUpRight className="size-3" aria-hidden />
              </Link>
            </div>
          </Panel>
          <Panel title="Triage" id="triage">
            <dl className="space-y-2 text-xs">
              <div className="flex justify-between"><dt className="text-muted">Status</dt><dd><AlertStatusBadge status={alert.status} /></dd></div>
              <div className="flex justify-between"><dt className="text-muted">Disposition</dt><dd><VerdictBadge verdict={alert.disposition} /></dd></div>
              <div className="flex justify-between"><dt className="text-muted">Assignee</dt><dd className="text-fg">{q.data.assignee?.display_name ?? "Unassigned"}</dd></div>
              <div className="flex justify-between"><dt className="text-muted">Updated</dt><dd className="text-fg" title={utcTitle(alert.updated_at)}>{relativeTime(alert.updated_at)}</dd></div>
            </dl>
          </Panel>
        </div>
      </div>
      <EscalateDialog alert={alert} open={escalating} onOpenChange={setEscalating} />
      <TriageDialog alert={alert} open={closing} onOpenChange={setClosing} />
      <LinkEventsDialog target="alerts" id={alert.id} exclude={events.map((e) => e.id)} open={linking} onOpenChange={setLinking} />
      <ConfirmDialog
        open={unlinking}
        onOpenChange={setUnlinking}
        title="Remove this alert from its incident?"
        description="The alert goes back to acknowledged. The incident keeps the evidence already copied into it."
        confirmLabel="Remove from incident"
        loading={unlink.isPending}
        onConfirm={() => unlink.mutate()}
      />
    </>
  );
}
