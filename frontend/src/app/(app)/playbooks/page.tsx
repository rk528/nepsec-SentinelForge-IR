"use client";

import { useQuery } from "@tanstack/react-query";
import { ShieldCheck, Workflow } from "lucide-react";

import { SimulatedBadge } from "@/components/ui/badges";
import { EmptyState, ErrorState, PageHeader, Panel, Skeleton } from "@/components/ui/primitives";
import { api } from "@/lib/api";
import { humanize } from "@/lib/format";
import type { Playbook } from "@/lib/types";

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
      {q.isError ? (
        <Panel><ErrorState error={q.error} onRetry={() => q.refetch()} /></Panel>
      ) : !q.data ? (
        <Skeleton className="h-64 rounded-lg" />
      ) : q.data.length === 0 ? (
        <Panel><EmptyState title="No playbooks" /></Panel>
      ) : (
        <div className="space-y-4">
          {categories.map((cat) => (
            <Panel key={cat} title={humanize(cat)} bodyClassName="p-0" id={cat}>
              <ul className="divide-y divide-line">
                {q.data
                  .filter((p) => p.category === cat)
                  .map((p) => (
                    <li key={p.id} className="flex flex-col gap-2 px-4 py-3 md:flex-row md:items-start md:gap-4">
                      <Workflow className="mt-0.5 hidden size-4 shrink-0 text-subtle md:block" aria-hidden />
                      <div className="min-w-0 flex-1">
                        <p className="flex flex-wrap items-center gap-2 text-[13px] font-medium text-fg">
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
          ))}
        </div>
      )}
    </>
  );
}
