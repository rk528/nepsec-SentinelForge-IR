"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ListChecks, Pencil, ShieldCheck, Trash2, Workflow } from "lucide-react";
import { useState } from "react";

import { NewPlaybookButton, PlaybookBuilder } from "@/components/playbook-builder";
import { SimulatedBadge } from "@/components/ui/badges";
import { ConfirmDialog, useToast } from "@/components/ui/overlays";
import { Button, EmptyState, ErrorState, PageHeader, Panel, Skeleton } from "@/components/ui/primitives";
import { api } from "@/lib/api";
import { humanize, plural, relativeTime } from "@/lib/format";
import { useCan } from "@/lib/hooks";
import type { CustomPlaybook, Playbook } from "@/lib/types";

function CustomPlaybooks() {
  const isLead = useCan("lead");
  const q = useQuery({ queryKey: ["custom-playbooks"], queryFn: () => api<CustomPlaybook[]>("/custom-playbooks") });
  const builtins = useQuery({ queryKey: ["playbooks"], queryFn: () => api<Playbook[]>("/playbooks"), staleTime: 10 * 60_000 });
  const [builder, setBuilder] = useState<{ editing: CustomPlaybook | null; n: number } | null>(null);
  const [archive, setArchive] = useState<CustomPlaybook | null>(null);
  const qc = useQueryClient();
  const toast = useToast();
  const remove = useMutation({
    mutationFn: (p: CustomPlaybook) => api<void>(`/custom-playbooks/${p.id}`, { method: "DELETE" }),
    onSuccess: (_, p) => {
      qc.invalidateQueries({ queryKey: ["custom-playbooks"] });
      toast({ kind: "success", title: `Archived “${p.name}”` });
      setArchive(null);
    },
  });
  const actionName = (id: string | null) => builtins.data?.find((p) => p.id === id)?.name ?? humanize(id ?? "");

  return (
    <Panel
      title="Your playbooks"
      id="custom"
      description="Your own response procedures: ordered automated actions and manual tasks, started from an incident's Response tab."
      actions={isLead ? <NewPlaybookButton onClick={() => setBuilder({ editing: null, n: Date.now() })} /> : undefined}
      bodyClassName="p-0"
    >
      {q.isError ? (
        <ErrorState error={q.error} onRetry={() => q.refetch()} />
      ) : !q.data ? (
        <Skeleton className="m-4 h-20" />
      ) : q.data.length === 0 ? (
        <EmptyState
          icon={<ListChecks className="size-5" aria-hidden />}
          title="No playbooks of your own yet"
          description={isLead ? "Create one for a situation you handle often, such as a compromised account or a lost laptop." : "A lead can create playbooks for your team."}
        />
      ) : (
        <ul className="divide-y divide-line">
          {q.data.map((p) => (
            <li key={p.id} className="flex flex-col gap-3 px-4 py-3 md:flex-row md:items-start md:gap-4">
              <ListChecks className="mt-0.5 hidden size-4 shrink-0 text-subtle md:block" aria-hidden />
              <div className="min-w-0 flex-1">
                <p className="text-sm font-medium text-fg">{p.name}</p>
                {p.description && <p className="mt-0.5 text-xs text-muted">{p.description}</p>}
                <ol className="mt-2 flex flex-wrap gap-1.5">
                  {p.steps.map((s, i) => (
                    <li key={i} className="inline-flex max-w-full items-center gap-1 rounded-md border border-line bg-raised/40 px-2 py-0.5 text-xs text-muted">
                      <span className="mono text-subtle">{i + 1}</span>
                      {s.kind === "action" ? <Workflow className="size-3 shrink-0 text-teal" aria-label="Automated" /> : <ListChecks className="size-3 shrink-0" aria-label="Manual task" />}
                      <span className="truncate">{s.kind === "action" && !s.title ? actionName(s.action) : s.title}</span>
                    </li>
                  ))}
                </ol>
                <p className="mt-2 text-xs text-subtle">
                  {plural(p.steps.length, "step")}
                  {p.trigger_rules.length > 0 && <> · suggested for {p.trigger_rules.join(", ")}</>}
                  {p.created_by && <> · by {p.created_by}</>} · updated {relativeTime(p.updated_at)}
                </p>
              </div>
              {isLead && (
                <div className="flex shrink-0 gap-2">
                  <Button size="sm" icon={<Pencil className="size-3" aria-hidden />} onClick={() => setBuilder({ editing: p, n: Date.now() })}>
                    Edit
                  </Button>
                  <Button size="sm" variant="ghost" icon={<Trash2 className="size-3" aria-hidden />} onClick={() => setArchive(p)}>
                    Archive
                  </Button>
                </div>
              )}
            </li>
          ))}
        </ul>
      )}
      {builder && <PlaybookBuilder key={builder.n} open onOpenChange={(o) => !o && setBuilder(null)} editing={builder.editing} />}
      <ConfirmDialog
        open={!!archive}
        onOpenChange={(o) => !o && setArchive(null)}
        title={archive ? `Archive “${archive.name}”?` : ""}
        description="It will no longer be offered on incidents. Runs already started keep their steps and history."
        confirmLabel="Archive"
        destructive
        loading={remove.isPending}
        onConfirm={() => archive && remove.mutate(archive)}
      />
    </Panel>
  );
}

export default function PlaybooksPage() {
  const q = useQuery({ queryKey: ["playbooks"], queryFn: () => api<Playbook[]>("/playbooks") });
  const categories = q.data ? [...new Set(q.data.map((p) => p.category))] : [];
  return (
    <>
      <PageHeader title="Response playbooks" description="Playbooks run from an incident's Response tab. Each run records the requester, parameters and result as a response action, and outputs are stored as evidence." />
      <div className="mb-4 flex gap-2.5 rounded-lg border border-teal/25 bg-teal/[0.06] px-4 py-3 text-xs text-muted">
        <ShieldCheck className="mt-0.5 size-4 shrink-0 text-teal" aria-hidden />
        <p>
          Disruptive actions are <strong className="text-fg">simulated</strong> in this release: no firewall, identity provider or endpoint is contacted. Gated playbooks require approval from a lead who did not request them, and the server refuses to target internal or reserved addresses.
        </p>
      </div>
      <div className="space-y-4">
        <CustomPlaybooks />
        <h2 className="pt-2 text-xs font-medium tracking-wide text-subtle uppercase">Built-in actions</h2>
        {q.isError ? (
          <Panel><ErrorState error={q.error} onRetry={() => q.refetch()} /></Panel>
        ) : !q.data ? (
          <Skeleton className="h-64 rounded-lg" />
        ) : q.data.length === 0 ? (
          <Panel><EmptyState title="No playbooks" /></Panel>
        ) : (
          categories.map((cat) => (
            <Panel key={cat} title={humanize(cat)} bodyClassName="p-0" id={cat}>
              <ul className="divide-y divide-line">
                {q.data
                  .filter((p) => p.category === cat)
                  .map((p) => (
                    <li key={p.id} className="flex flex-col gap-2 px-4 py-3 md:flex-row md:items-start md:gap-4">
                      <Workflow className="mt-0.5 hidden size-4 shrink-0 text-subtle md:block" aria-hidden />
                      <div className="min-w-0 flex-1">
                        <p className="flex flex-wrap items-center gap-2 text-sm font-medium text-fg">
                          {p.name} <span className="mono text-xs font-normal text-subtle">{p.id}</span>
                          {p.simulated && <SimulatedBadge />}
                        </p>
                        <p className="mt-0.5 text-xs text-muted">{p.description}</p>
                        {p.rollback_plan && <p className="mt-1 text-xs text-subtle">Rollback: {p.rollback_plan}</p>}
                      </div>
                      <div className="flex shrink-0 flex-wrap gap-3 text-xs text-muted">
                        <span>Minimum role: <span className="text-fg capitalize">{p.min_role}</span></span>
                        <span className={p.requires_approval ? "text-warn" : ""}>{p.requires_approval ? "Second-person approval" : "Runs immediately"}</span>
                      </div>
                    </li>
                  ))}
              </ul>
            </Panel>
          ))
        )}
      </div>
    </>
  );
}
