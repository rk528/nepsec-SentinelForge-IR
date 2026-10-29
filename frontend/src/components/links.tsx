"use client";

// Dialogs that link incidents, alerts and events to one another, and raise an alert by hand.

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useRouter } from "next/navigation";
import { useState } from "react";

import { SeverityBadge } from "@/components/ui/badges";
import { Dialog, useToast } from "@/components/ui/overlays";
import { Button, Field, Input, Select, Skeleton, Textarea } from "@/components/ui/primitives";
import { ApiError, api } from "@/lib/api";
import { formatDateTime } from "@/lib/format";
import { SEVERITY_OPTIONS } from "@/lib/options";
import type { Alert, EventRecord, Incident, Page, Severity } from "@/lib/types";

const OPEN_INCIDENTS = ["new", "open", "investigating", "contained", "resolved"];

function errText(e: unknown) {
  return e instanceof ApiError ? e.detail : undefined;
}

function toggle(ids: string[], id: string) {
  return ids.includes(id) ? ids.filter((x) => x !== id) : [...ids, id];
}

/** Every query that shows a link, so that both ends of a new link refresh. */
function useInvalidateLinks() {
  const qc = useQueryClient();
  return () => {
    for (const key of ["alert", "alerts", "incident", "incidents", "event"]) qc.invalidateQueries({ queryKey: [key] });
  };
}

function EventPicker({ picked, onChange, exclude = [] }: { picked: string[]; onChange: (ids: string[]) => void; exclude?: string[] }) {
  const [q, setQ] = useState("");
  const [hours, setHours] = useState("168");
  const events = useQuery({
    queryKey: ["events", "picker", { q, hours }],
    queryFn: ({ signal }) => api<Page<EventRecord>>("/events", { query: { q: q || undefined, hours: hours || undefined, page_size: 50 }, signal }),
    placeholderData: (prev) => prev,
  });
  const rows = (events.data?.items ?? []).filter((e) => !exclude.includes(e.id));
  return (
    <div className="space-y-3">
      <div className="grid grid-cols-[minmax(0,1fr)_8rem] gap-2">
        <Field label="Search events" htmlFor="pick-q">
          <Input id="pick-q" value={q} onChange={(e) => setQ(e.target.value)} placeholder="Host, user, IP, domain, process…" maxLength={200} />
        </Field>
        <Field label="Within" htmlFor="pick-hours">
          <Select id="pick-hours" value={hours} onChange={(e) => setHours(e.target.value)}>
            <option value="24">24 hours</option>
            <option value="168">7 days</option>
            <option value="720">30 days</option>
            <option value="">Any time</option>
          </Select>
        </Field>
      </div>
      <div className="max-h-72 overflow-y-auto rounded-md border border-line">
        {!events.data ? (
          <Skeleton className="m-3 h-24" />
        ) : rows.length === 0 ? (
          <p className="p-4 text-xs text-muted">No events match.</p>
        ) : (
          <ul>
            {rows.map((e) => (
              <li key={e.id} className="border-b border-line/60 last:border-0">
                <label className="flex cursor-pointer items-start gap-2 px-3 py-2 text-xs hover:bg-overlay/50">
                  <input type="checkbox" checked={picked.includes(e.id)} onChange={() => onChange(toggle(picked, e.id))} className="mt-0.5 accent-[var(--color-accent)]" />
                  <span className="min-w-0 flex-1">
                    <span className="mono text-fg">{formatDateTime(e.event_time)}</span> <span className="mono text-muted">{e.event_type}</span>
                    <span className="block truncate text-muted">{[e.host, e.user_name, e.src_ip, e.domain, e.process_name].filter(Boolean).join(" · ") || e.message || "—"}</span>
                  </span>
                </label>
              </li>
            ))}
          </ul>
        )}
      </div>
      <p className="text-xs text-subtle">{picked.length} selected</p>
    </div>
  );
}

/** Link events to an alert or an incident. */
export function LinkEventsDialog({ target, id, exclude, open, onOpenChange }: { target: "alerts" | "incidents"; id: string; exclude?: string[]; open: boolean; onOpenChange: (o: boolean) => void }) {
  const toast = useToast();
  const invalidate = useInvalidateLinks();
  const [picked, setPicked] = useState<string[]>([]);
  const [reason, setReason] = useState("");
  const m = useMutation({
    mutationFn: () => api<{ linked: number }>(`/${target}/${id}/events`, { method: "POST", body: { event_ids: picked, reason: reason.trim() || undefined } }),
    onSuccess: (r) => {
      invalidate();
      toast({ kind: "success", title: r.linked === 1 ? "1 event linked" : `${r.linked} events linked` });
      setPicked([]);
      setReason("");
      onOpenChange(false);
    },
    onError: (e) => toast({ kind: "error", title: "Events not linked", description: errText(e) }),
  });
  return (
    <Dialog
      open={open}
      onOpenChange={onOpenChange}
      size="lg"
      title={target === "alerts" ? "Link events to this alert" : "Link events to this incident"}
      description={target === "alerts" ? "They become part of the alert's evidence, and of its incident's when it has one." : "They are added to the incident's evidence and timeline."}
      footer={
        <Button variant="primary" loading={m.isPending} disabled={picked.length === 0} onClick={() => m.mutate()}>
          Link {picked.length || ""} event{picked.length === 1 ? "" : "s"}
        </Button>
      }
    >
      <div className="space-y-3">
        <EventPicker picked={picked} onChange={setPicked} exclude={exclude} />
        <Field label="Why they belong (optional)" htmlFor="link-reason">
          <Input id="link-reason" value={reason} onChange={(e) => setReason(e.target.value)} maxLength={300} placeholder="Same user, minutes later" />
        </Field>
      </div>
    </Dialog>
  );
}

/** Bring existing alerts into an incident. */
export function LinkAlertsDialog({ incidentId, open, onOpenChange }: { incidentId: string; open: boolean; onOpenChange: (o: boolean) => void }) {
  const toast = useToast();
  const invalidate = useInvalidateLinks();
  const [q, setQ] = useState("");
  const [picked, setPicked] = useState<string[]>([]);
  const alerts = useQuery({
    queryKey: ["alerts", "picker", { q }],
    queryFn: ({ signal }) => api<Page<Alert>>("/alerts", { query: { q: q || undefined, status: ["new", "acknowledged", "escalated"], page_size: 50 }, signal }),
    enabled: open,
    placeholderData: (prev) => prev,
  });
  const rows = (alerts.data?.items ?? []).filter((a) => a.incident_id !== incidentId);
  const m = useMutation({
    mutationFn: () => api<{ linked: number }>(`/incidents/${incidentId}/alerts`, { method: "POST", body: { alert_ids: picked } }),
    onSuccess: (r) => {
      invalidate();
      toast({ kind: "success", title: r.linked === 1 ? "1 alert linked" : `${r.linked} alerts linked` });
      setPicked([]);
      onOpenChange(false);
    },
    onError: (e) => toast({ kind: "error", title: "Alerts not linked", description: errText(e) }),
  });
  return (
    <Dialog
      open={open}
      onOpenChange={onOpenChange}
      size="lg"
      title="Link alerts to this incident"
      description="Each alert is marked escalated and its events come with it as evidence. An alert already in another incident moves here."
      footer={
        <Button variant="primary" loading={m.isPending} disabled={picked.length === 0} onClick={() => m.mutate()}>
          Link {picked.length || ""} alert{picked.length === 1 ? "" : "s"}
        </Button>
      }
    >
      <div className="space-y-3">
        <Field label="Search alerts" htmlFor="pick-alert-q">
          <Input id="pick-alert-q" value={q} onChange={(e) => setQ(e.target.value)} placeholder="Title or rule" maxLength={200} />
        </Field>
        <div className="max-h-72 overflow-y-auto rounded-md border border-line">
          {!alerts.data ? (
            <Skeleton className="m-3 h-24" />
          ) : rows.length === 0 ? (
            <p className="p-4 text-xs text-muted">No open alerts match.</p>
          ) : (
            <ul>
              {rows.map((a) => (
                <li key={a.id} className="border-b border-line/60 last:border-0">
                  <label className="flex cursor-pointer items-center gap-2 px-3 py-2 text-xs hover:bg-overlay/50">
                    <input type="checkbox" checked={picked.includes(a.id)} onChange={() => setPicked(toggle(picked, a.id))} className="accent-[var(--color-accent)]" />
                    <SeverityBadge severity={a.severity} compact />
                    <span className="min-w-0 flex-1 truncate text-fg">{a.title}</span>
                    <span className="mono shrink-0 text-subtle">{a.incident_number ? `INC-${String(a.incident_number).padStart(4, "0")}` : a.rule_id}</span>
                  </label>
                </li>
              ))}
            </ul>
          )}
        </div>
        <p className="text-xs text-subtle">{picked.length} selected</p>
      </div>
    </Dialog>
  );
}

function IncidentSelect({ value, onChange, enabled, optional }: { value: string; onChange: (v: string) => void; enabled: boolean; optional?: boolean }) {
  const incidents = useQuery({
    queryKey: ["incidents", "open-for-link"],
    queryFn: () => api<Page<Incident>>("/incidents", { query: { status: OPEN_INCIDENTS, page_size: 50 } }),
    enabled,
  });
  return (
    <Select id="pick-incident" value={value} onChange={(e) => onChange(e.target.value)}>
      <option value="">{optional ? "None" : "Select an open incident…"}</option>
      {incidents.data?.items.map((i) => (
        <option key={i.id} value={i.id}>
          {i.reference} · {i.title}
        </option>
      ))}
    </Select>
  );
}

/** Add one event to an alert or an incident, from the event's own page. */
export function AddEventToDialog({ eventId, target, open, onOpenChange }: { eventId: string; target: "alert" | "incident"; open: boolean; onOpenChange: (o: boolean) => void }) {
  const toast = useToast();
  const invalidate = useInvalidateLinks();
  const [incidentId, setIncidentId] = useState("");
  const [alertId, setAlertId] = useState("");
  const alerts = useQuery({
    queryKey: ["alerts", "open-for-link"],
    queryFn: () => api<Page<Alert>>("/alerts", { query: { status: ["new", "acknowledged", "escalated"], page_size: 50 } }),
    enabled: open && target === "alert",
  });
  const chosen = target === "alert" ? alertId : incidentId;
  const m = useMutation({
    mutationFn: () => api<{ linked: number }>(`/${target === "alert" ? "alerts" : "incidents"}/${chosen}/events`, { method: "POST", body: { event_ids: [eventId], reason: "Added from the event page" } }),
    onSuccess: (r) => {
      invalidate();
      toast({ kind: "success", title: r.linked ? `Added to the ${target}` : `Already linked to that ${target}` });
      onOpenChange(false);
    },
    onError: (e) => toast({ kind: "error", title: "Not linked", description: errText(e) }),
  });
  return (
    <Dialog
      open={open}
      onOpenChange={onOpenChange}
      title={target === "alert" ? "Add this event to an alert" : "Add this event to an incident"}
      description={target === "alert" ? "It becomes part of the alert's evidence, and of its incident's when it has one." : "It is added to the incident's evidence and timeline."}
      footer={
        <Button variant="primary" loading={m.isPending} disabled={!chosen} onClick={() => m.mutate()}>
          Add event
        </Button>
      }
    >
      {target === "alert" ? (
        <Field label="Alert" htmlFor="pick-alert">
          <Select id="pick-alert" value={alertId} onChange={(e) => setAlertId(e.target.value)}>
            <option value="">Select an open alert…</option>
            {alerts.data?.items.map((a) => (
              <option key={a.id} value={a.id}>
                [{a.severity}] {a.title}
              </option>
            ))}
          </Select>
        </Field>
      ) : (
        <Field label="Incident" htmlFor="pick-incident">
          <IncidentSelect value={incidentId} onChange={setIncidentId} enabled={open} />
        </Field>
      )}
    </Dialog>
  );
}

/** Raise an alert by hand, optionally from events and straight into an incident. */
export function RaiseAlertDialog({ open, onOpenChange, eventIds = [], incidentId }: { open: boolean; onOpenChange: (o: boolean) => void; eventIds?: string[]; incidentId?: string }) {
  const router = useRouter();
  const toast = useToast();
  const invalidate = useInvalidateLinks();
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [severity, setSeverity] = useState<Severity>("medium");
  const [incident, setIncident] = useState(incidentId ?? "");
  const [picked, setPicked] = useState<string[]>(eventIds);
  const [choosing, setChoosing] = useState(false);
  const m = useMutation({
    mutationFn: () =>
      api<Alert>("/alerts", {
        method: "POST",
        body: { title: title.trim(), description: description.trim(), severity, event_ids: picked, incident_id: incident || undefined },
      }),
    onSuccess: (a) => {
      invalidate();
      toast({ kind: "success", title: "Alert raised" });
      onOpenChange(false);
      router.push(`/alerts/${a.id}`);
    },
    onError: (e) => toast({ kind: "error", title: "Alert not raised", description: errText(e) }),
  });
  return (
    <Dialog
      open={open}
      onOpenChange={onOpenChange}
      size="lg"
      title="Raise an alert"
      description="For something no rule caught: a user's report, a tip from another team, or events you picked. It joins the queue like any detection."
      footer={
        <Button variant="primary" loading={m.isPending} disabled={title.trim().length < 3} onClick={() => m.mutate()}>
          Raise alert
        </Button>
      }
    >
      <div className="space-y-3">
        <Field label="Title" htmlFor="raise-title">
          <Input id="raise-title" value={title} onChange={(e) => setTitle(e.target.value)} maxLength={300} placeholder="User reported a fake Microsoft sign-in page" />
        </Field>
        <Field label="What happened" htmlFor="raise-desc">
          <Textarea id="raise-desc" value={description} onChange={(e) => setDescription(e.target.value)} maxLength={10000} placeholder="Who reported it, what they saw, what you checked." />
        </Field>
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <Field label="Severity" htmlFor="raise-sev">
            <Select id="raise-sev" value={severity} onChange={(e) => setSeverity(e.target.value as Severity)}>
              {SEVERITY_OPTIONS.map((o) => (
                <option key={o.value} value={o.value}>
                  {o.label}
                </option>
              ))}
            </Select>
          </Field>
          {!incidentId && (
            <Field label="Add to incident (optional)" htmlFor="pick-incident">
              <IncidentSelect value={incident} onChange={setIncident} enabled={open} optional />
            </Field>
          )}
        </div>
        <div className="flex items-center justify-between gap-2 text-xs">
          <span className="text-muted">{picked.length === 0 ? "No events attached" : `${picked.length} event${picked.length === 1 ? "" : "s"} attached`}</span>
          <Button size="sm" onClick={() => setChoosing((c) => !c)}>
            {choosing ? "Done choosing" : "Choose events"}
          </Button>
        </div>
        {choosing && <EventPicker picked={picked} onChange={setPicked} />}
      </div>
    </Dialog>
  );
}
