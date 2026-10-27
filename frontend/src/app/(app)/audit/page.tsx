"use client";

import { useQuery } from "@tanstack/react-query";
import Link from "next/link";
import { Suspense, useState } from "react";

import { JsonViewer } from "@/components/investigation";
import { Pagination } from "@/components/ui/data-table";
import { SearchBox, Toolbar } from "@/components/ui/filters";
import { ApiError, api } from "@/lib/api";
import { Button, EmptyState, ErrorState, Input, PageHeader, Panel, Select, SkeletonRows } from "@/components/ui/primitives";
import { formatDateTime, utcTitle } from "@/lib/format";
import { useUrlState } from "@/lib/hooks";
import type { AuditEntry, Page } from "@/lib/types";

const ACTIONS = ["auth.*", "incident.*", "alert.*", "ioc.*", "playbook.*", "response_action.*", "detection.*", "data_source.*", "user.*", "ingest.*", "scenario.*"];

function targetHref(a: AuditEntry): string | null {
  if (!a.target_id) return null;
  if (a.target_type === "incident") return `/incidents/${a.target_id}`;
  if (a.target_type === "alert") return `/alerts/${a.target_id}`;
  if (a.target_type === "indicator") return `/threat-intel?id=${a.target_id}`;
  return null;
}

function Audit() {
  const url = useUrlState();
  const q = url.get("q");
  const action = url.get("action");
  const actor = url.get("actor");
  const targetId = url.get("target_id");
  const page = Number(url.get("page", "1")) || 1;
  const [expanded, setExpanded] = useState<string | null>(null);
  const [actorDraft, setActorDraft] = useState(actor);
  const data = useQuery({
    queryKey: ["audit", { q, action, actor, targetId, page }],
    queryFn: () => api<Page<AuditEntry>>("/audit", { query: { q, action, actor, target_id: targetId, page, page_size: 50 } }),
    placeholderData: (p) => p,
  });
  const forbidden = data.error instanceof ApiError && data.error.status === 403;

  return (
    <>
      <PageHeader title="Audit log" description="Append-only record of security-relevant actions. The database rejects updates and deletes to this table." />
      <Panel bodyClassName="p-0">
        <Toolbar>
          <SearchBox label="Search audit log" placeholder="Search action, actor or target ID" value={q} onChange={(v) => url.set({ q: v })} />
          <label htmlFor="act" className="sr-only">Action</label>
          <Select id="act" className="w-48" value={action} onChange={(e) => url.set({ action: e.target.value || null })}>
            <option value="">All actions</option>
            {ACTIONS.map((a) => <option key={a} value={a}>{a}</option>)}
          </Select>
          <form className="flex gap-2" onSubmit={(e) => { e.preventDefault(); url.set({ actor: actorDraft || null }); }}>
            <Input aria-label="Actor" placeholder="Actor email" className="w-48" value={actorDraft} onChange={(e) => setActorDraft(e.target.value)} />
            <Button type="submit" size="sm">Filter</Button>
          </form>
          {targetId && <Button size="sm" variant="ghost" onClick={() => url.set({ target_id: null })}>Clear target filter</Button>}
        </Toolbar>
        {forbidden ? (
          <EmptyState title="Audit search requires the lead role" description="Incident-level audit history is still available on each incident's Audit tab." />
        ) : data.isError ? (
          <ErrorState error={data.error} onRetry={() => data.refetch()} />
        ) : !data.data ? (
          <SkeletonRows rows={10} cols={4} />
        ) : data.data.items.length === 0 ? (
          <EmptyState title="No audit records match" />
        ) : (
          <>
            <ul className="divide-y divide-line">
              {data.data.items.map((a) => {
                const href = targetHref(a);
                const open = expanded === a.id;
                return (
                  <li key={a.id} className="px-4 py-2.5">
                    <div className="flex flex-col gap-1 md:flex-row md:items-center md:gap-4">
                      <span className="mono w-44 shrink-0 text-xs text-subtle" title={utcTitle(a.created_at)}>{formatDateTime(a.created_at)}</span>
                      <span className="mono w-56 shrink-0 text-xs text-fg">{a.action}</span>
                      <span className="min-w-0 flex-1 truncate text-xs text-muted">{a.actor_label}</span>
                      <span className="text-xs text-subtle">
                        {a.target_type && (href ? <Link href={href} className="hover:text-fg hover:underline">{a.target_type}</Link> : a.target_type)}
                      </span>
                      <button type="button" aria-expanded={open} onClick={() => setExpanded(open ? null : a.id)} className="text-xs text-accent hover:underline">
                        {open ? "Hide" : "Details"}
                      </button>
                    </div>
                    {open && (
                      <div className="mt-2 grid gap-2 text-xs md:grid-cols-[1fr_16rem]">
                        <JsonViewer value={a.details} maxHeight="12rem" />
                        <dl className="space-y-1 text-muted">
                          <div><dt className="inline text-subtle">Target ID: </dt><dd className="mono inline break-all">{a.target_id ?? "—"}</dd></div>
                          <div><dt className="inline text-subtle">IP: </dt><dd className="mono inline">{a.ip ?? "—"}</dd></div>
                          <div><dt className="inline text-subtle">Request ID: </dt><dd className="mono inline break-all">{a.request_id ?? "—"}</dd></div>
                        </dl>
                      </div>
                    )}
                  </li>
                );
              })}
            </ul>
            <Pagination page={page} pageSize={50} total={data.data.total} onPage={(p) => url.set({ page: p }, { resetPage: false })} />
          </>
        )}
      </Panel>
    </>
  );
}

export default function AuditPage() {
  return (
    <Suspense>
      <Audit />
    </Suspense>
  );
}
