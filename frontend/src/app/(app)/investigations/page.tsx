"use client";

import { useQuery } from "@tanstack/react-query";
import Link from "next/link";

import { IncidentStatusBadge, IntelVerdictBadge, SeverityBadge } from "@/components/ui/badges";
import { EmptyState, ErrorState, PageHeader, Panel, Skeleton } from "@/components/ui/primitives";
import { api } from "@/lib/api";
import { relativeTime, utcTitle } from "@/lib/format";
import { useMe } from "@/lib/hooks";
import type { Incident, Indicator, Page, ResponseAction } from "@/lib/types";

export default function InvestigationsPage() {
  const { data: me } = useMe();
  const mine = useQuery({
    queryKey: ["incidents", "mine", me?.id],
    queryFn: () => api<Page<Incident>>("/incidents", { query: { assignee_id: me!.id, status: ["new", "open", "investigating", "contained", "resolved"], sort: "updated_at", page_size: 50 } }),
    enabled: !!me,
  });
  const unassigned = useQuery({ queryKey: ["incidents", "unassigned"], queryFn: () => api<Page<Incident>>("/incidents", { query: { unassigned: true, status: ["new", "open", "investigating"], page_size: 10 } }) });
  const pending = useQuery({ queryKey: ["response-actions", ["pending_approval"], 1], queryFn: () => api<Page<ResponseAction>>("/response-actions", { query: { status: ["pending_approval"], page_size: 10 } }) });
  const iocs = useQuery({ queryKey: ["iocs", 1], queryFn: () => api<Page<Indicator>>("/iocs", { query: { page: 1, page_size: 8 } }) });

  const list = (q: typeof mine, empty: string) =>
    q.isError ? <ErrorState error={q.error} onRetry={() => q.refetch()} /> : !q.data ? <Skeleton className="m-4 h-24" /> : q.data.items.length === 0 ? <EmptyState title={empty} /> : (
      <ul className="divide-y divide-line">
        {q.data.items.map((i) => (
          <li key={i.id}>
            <Link href={`/incidents/${i.id}`} className="flex items-center gap-3 px-4 py-2.5 hover:bg-raised/60">
              <SeverityBadge severity={i.severity} compact />
              <span className="mono w-20 text-xs text-muted">{i.reference}</span>
              <span className="min-w-0 flex-1 truncate text-[13px] text-fg">{i.title}</span>
              <IncidentStatusBadge status={i.status} />
              <span className="hidden w-16 text-right text-xs text-subtle sm:block" title={utcTitle(i.updated_at)}>{relativeTime(i.updated_at)}</span>
            </Link>
          </li>
        ))}
      </ul>
    );

  return (
    <>
      <PageHeader title="My investigations" description={me ? `Work assigned to ${me.display_name}, plus queues that need an owner.` : undefined} />
      <div className="grid gap-4 xl:grid-cols-2">
        <Panel title="Assigned to me" description="Not yet closed" bodyClassName="p-0" id="mine">{list(mine, "Nothing assigned to you")}</Panel>
        <Panel title="Needs an owner" description="Unassigned incidents that are new, open or investigating" bodyClassName="p-0" id="unassigned">{list(unassigned, "Every active incident has an owner")}</Panel>
        <Panel title="Awaiting approval" bodyClassName="p-0" id="pending">
          {!pending.data ? <Skeleton className="m-4 h-16" /> : pending.data.items.length === 0 ? <EmptyState title="No actions awaiting approval" /> : (
            <ul className="divide-y divide-line">
              {pending.data.items.map((a) => (
                <li key={a.id}>
                  <Link href="/response-actions?status=pending_approval" className="flex items-center gap-3 px-4 py-2.5 text-[13px] hover:bg-raised/60">
                    <span className="mono text-xs text-muted">INC-{String(a.incident_number ?? 0).padStart(4, "0")}</span>
                    <span className="flex-1 text-fg">{a.action_type.replace(/_/g, " ")}</span>
                    <span className="text-xs text-subtle">by {a.requested_by_name}</span>
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </Panel>
        <Panel title="Recent indicator lookups" bodyClassName="p-0" id="iocs">
          {!iocs.data ? <Skeleton className="m-4 h-16" /> : iocs.data.items.length === 0 ? <EmptyState title="No lookups yet" /> : (
            <ul className="divide-y divide-line">
              {iocs.data.items.map((i) => (
                <li key={i.id}>
                  <Link href={`/threat-intel?id=${i.id}`} className="flex items-center gap-3 px-4 py-2.5 hover:bg-raised/60">
                    <span className="mono min-w-0 flex-1 truncate text-xs text-fg">{i.value}</span>
                    <IntelVerdictBadge verdict={i.analyst_verdict} />
                    <span className="w-16 text-right text-xs text-subtle">{relativeTime(i.last_looked_up)}</span>
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </Panel>
      </div>
    </>
  );
}
