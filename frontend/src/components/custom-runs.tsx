"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Check, Circle, Clock, ListChecks, Play, RotateCcw, SkipForward, Sparkles, Workflow, XCircle } from "lucide-react";
import { useState } from "react";

import { useToast } from "@/components/ui/overlays";
import { ConfirmDialog } from "@/components/ui/overlays";
import { Button, EmptyState, Field, Input, Skeleton, Textarea, cn } from "@/components/ui/primitives";
import { ApiError, api } from "@/lib/api";
import { relativeTime, utcTitle } from "@/lib/format";
import { useCan } from "@/lib/hooks";
import type { CustomPlaybook, CustomPlaybookRun, Incident, RunStep } from "@/lib/types";

type Pending = { run: CustomPlaybookRun; index: number; action: "complete" | "skip" | "run" };

const STATUS: Record<RunStep["status"], { icon: typeof Check; label: string; className: string }> = {
  pending: { icon: Circle, label: "To do", className: "text-subtle" },
  done: { icon: Check, label: "Done", className: "text-ok" },
  skipped: { icon: SkipForward, label: "Skipped", className: "text-muted" },
  awaiting_approval: { icon: Clock, label: "Awaiting approval", className: "text-warn" },
  failed: { icon: XCircle, label: "Failed", className: "text-danger" },
};

function errText(e: unknown) {
  return e instanceof ApiError ? e.message : "Something went wrong";
}

/** The incident's custom playbooks: suggested ones to start, and checklists in progress. */
export function CustomPlaybookRuns({ incident, externalIps }: { incident: Incident; externalIps: string[] }) {
  const canRun = useCan("analyst");
  const qc = useQueryClient();
  const toast = useToast();
  const playbooks = useQuery({ queryKey: ["custom-playbooks", { incident: incident.id }], queryFn: () => api<CustomPlaybook[]>("/custom-playbooks", { query: { incident_id: incident.id } }) });
  const runs = useQuery({ queryKey: ["incident", incident.id, "custom-runs"], queryFn: () => api<CustomPlaybookRun[]>("/custom-playbook-runs", { query: { incident_id: incident.id } }) });
  const [pending, setPending] = useState<Pending | null>(null);
  const [note, setNote] = useState("");
  const [ips, setIps] = useState("");
  const open = incident.status !== "closed";

  const refresh = () => qc.invalidateQueries({ queryKey: ["incident", incident.id] });
  const start = useMutation({
    mutationFn: (p: CustomPlaybook) => api<CustomPlaybookRun>(`/custom-playbooks/${p.id}/start`, { method: "POST", body: { incident_id: incident.id } }),
    onSuccess: (r) => {
      refresh();
      toast({ kind: "success", title: `Started “${r.name}”` });
    },
    onError: (e) => toast({ kind: "error", title: "Playbook not started", description: errText(e) }),
  });
  const step = useMutation({
    mutationFn: ({ run, index, action, body }: { run: CustomPlaybookRun; index: number; action: string; body?: Record<string, unknown> }) =>
      api<CustomPlaybookRun>(`/custom-playbook-runs/${run.id}/steps/${index}`, { method: "POST", body: { action, ...body } }),
    onSuccess: (r, v) => {
      refresh();
      setPending(null);
      setNote("");
      const s = r.steps[v.index];
      toast({ kind: s.status === "failed" ? "error" : "success", title: `${s.title}: ${STATUS[s.status].label.toLowerCase()}`, description: r.status === "completed" ? `“${r.name}” is complete.` : undefined });
    },
    onError: (e) => toast({ kind: "error", title: "Step not updated", description: errText(e) }),
  });

  const ask = (run: CustomPlaybookRun, index: number, action: Pending["action"]) => {
    setNote("");
    setIps(externalIps.join(", "));
    setPending({ run, index, action });
  };
  const pendingStep = pending ? pending.run.steps[pending.index] : null;
  const needsIps = pending?.action === "run" && pendingStep?.action === "simulate_firewall_block";
  const startedIds = new Set(runs.data?.filter((r) => r.status === "in_progress").map((r) => r.playbook_id));
  const available = playbooks.data?.filter((p) => !startedIds.has(p.id)) ?? [];

  return (
    <div>
      <h3 className="mb-2 text-xs font-medium tracking-wide text-subtle uppercase">Your playbooks</h3>
      {!playbooks.data || !runs.data ? (
        <Skeleton className="h-24" />
      ) : (
        <div className="space-y-3">
          {runs.data.map((run) => {
            const done = run.steps.filter((s) => s.status === "done" || s.status === "skipped").length;
            return (
              <section key={run.id} aria-label={run.name} className="rounded-lg border border-line">
                <header className="flex flex-wrap items-center gap-2 border-b border-line px-3 py-2">
                  <ListChecks className="size-4 text-subtle" aria-hidden />
                  <span className="text-sm font-medium text-fg">{run.name}</span>
                  <span className={cn("rounded px-1.5 py-px text-xs", run.status === "completed" ? "bg-ok/10 text-ok" : "bg-accent/10 text-accent")}>{run.status === "completed" ? "Complete" : `${done} of ${run.steps.length} done`}</span>
                  <span className="ml-auto text-xs text-subtle" title={run.started_at ? utcTitle(run.started_at) : undefined}>
                    {run.started_by ?? "Unknown"} · {run.started_at ? relativeTime(run.started_at) : ""}
                  </span>
                </header>
                <div className="h-1 bg-raised" aria-hidden>
                  <div className="h-1 bg-ok transition-all" style={{ width: `${(done / run.steps.length) * 100}%` }} />
                </div>
                <ol className="divide-y divide-line">
                  {run.steps.map((s, i) => {
                    const st = STATUS[s.status];
                    const Icon = st.icon;
                    const actionable = canRun && open && (s.status === "pending" || s.status === "failed");
                    return (
                      <li key={i} className="flex flex-col gap-2 px-3 py-2.5 sm:flex-row sm:items-start">
                        <div className="flex min-w-0 flex-1 gap-2.5">
                          <Icon className={cn("mt-0.5 size-4 shrink-0", st.className)} aria-label={st.label} />
                          <div className="min-w-0">
                            <p className={cn("flex flex-wrap items-center gap-1.5 text-sm", s.status === "skipped" ? "text-muted line-through" : "text-fg")}>
                              <span className="mono text-xs text-subtle">{i + 1}.</span>
                              {s.title}
                              {s.kind === "action" && <Workflow className="size-3 text-teal" aria-label="Automated action" />}
                            </p>
                            {s.instructions && <p className="mt-0.5 text-xs whitespace-pre-line text-muted">{s.instructions}</p>}
                            {(s.note || s.by) && (
                              <p className="mt-1 text-xs text-subtle">
                                {st.label}
                                {s.by && <> by {s.by}</>}
                                {s.at && <> · {relativeTime(s.at)}</>}
                                {s.note && <span className="text-muted">: “{s.note}”</span>}
                              </p>
                            )}
                          </div>
                        </div>
                        {canRun && open && (
                          <div className="flex shrink-0 flex-wrap gap-1.5 pl-6 sm:pl-0">
                            {actionable && s.kind === "action" && (
                              <Button size="sm" variant="primary" icon={<Play className="size-3" aria-hidden />} onClick={() => ask(run, i, "run")}>
                                {s.status === "failed" ? "Retry" : "Run"}
                              </Button>
                            )}
                            {actionable && s.kind === "task" && (
                              <Button size="sm" variant="primary" icon={<Check className="size-3" aria-hidden />} onClick={() => ask(run, i, "complete")}>
                                Mark done
                              </Button>
                            )}
                            {actionable && (
                              <Button size="sm" variant="ghost" onClick={() => ask(run, i, "skip")}>
                                Skip
                              </Button>
                            )}
                            {(s.status === "done" || s.status === "skipped") && (
                              <Button size="sm" variant="ghost" aria-label={`Reopen step ${i + 1}`} icon={<RotateCcw className="size-3" aria-hidden />} loading={step.isPending && step.variables?.index === i && step.variables.run.id === run.id} onClick={() => step.mutate({ run, index: i, action: "reopen" })} />
                            )}
                          </div>
                        )}
                      </li>
                    );
                  })}
                </ol>
              </section>
            );
          })}

          {available.length > 0 ? (
            <ul className="grid gap-2 sm:grid-cols-2">
              {available.map((p) => (
                <li key={p.id} className={cn("flex flex-col justify-between gap-2 rounded-lg border bg-raised/30 p-3", p.suggested ? "border-accent/40" : "border-line")}>
                  <div>
                    <p className="flex flex-wrap items-center gap-2 text-sm font-medium text-fg">
                      {p.name}
                      {p.suggested && (
                        <span className="inline-flex items-center gap-1 rounded bg-accent/15 px-1.5 py-px text-xs text-accent">
                          <Sparkles className="size-3" aria-hidden /> Suggested
                        </span>
                      )}
                    </p>
                    <p className="mt-1 text-xs text-muted">{p.description || `${p.steps.length} steps`}</p>
                  </div>
                  {canRun && open && (
                    <Button size="sm" className="self-start" icon={<Play className="size-3" aria-hidden />} loading={start.isPending && start.variables?.id === p.id} onClick={() => start.mutate(p)}>
                      Start checklist
                    </Button>
                  )}
                </li>
              ))}
            </ul>
          ) : (
            runs.data.length === 0 && <EmptyState title="No playbooks of your own yet" description="Leads can build them on the Playbooks page from automated actions and manual tasks." />
          )}
        </div>
      )}

      <ConfirmDialog
        open={!!pending}
        onOpenChange={(o) => !o && setPending(null)}
        title={pendingStep ? (pending?.action === "run" ? `Run “${pendingStep.title}”?` : pending?.action === "skip" ? `Skip “${pendingStep.title}”?` : `Complete “${pendingStep.title}”`) : ""}
        description={pending?.action === "skip" ? "Say why; the reason is kept with the step and in the audit log." : pending?.action === "complete" ? "Your note is saved as evidence on the incident." : needsIps ? "This requests approval from a lead who did not request it. Execution is simulated." : undefined}
        confirmLabel={pending?.action === "run" ? (needsIps ? "Request approval" : "Run") : pending?.action === "skip" ? "Skip step" : "Mark done"}
        loading={step.isPending}
        onConfirm={() => {
          if (!pending || (pending.action === "skip" && note.trim().length < 3)) return;
          step.mutate({ run: pending.run, index: pending.index, action: pending.action, body: { note: note.trim(), parameters: needsIps ? { ip_addresses: ips.split(/[\s,]+/).filter(Boolean), duration_hours: 24 } : {} } });
        }}
      >
        {needsIps && (
          <Field label="External IP addresses to block" htmlFor="cpb-ips" hint="Comma separated. Internal and reserved addresses are refused by the server.">
            <Input id="cpb-ips" value={ips} onChange={(e) => setIps(e.target.value)} className="mono" />
          </Field>
        )}
        {pending?.action !== "run" && (
          <Field label={pending?.action === "skip" ? "Reason" : "Note (optional)"} htmlFor="cpb-note">
            <Textarea id="cpb-note" value={note} onChange={(e) => setNote(e.target.value)} maxLength={4000} placeholder={pending?.action === "skip" ? "e.g. Not applicable: the account is a service account" : "What you did or found"} />
          </Field>
        )}
      </ConfirmDialog>
    </div>
  );
}
