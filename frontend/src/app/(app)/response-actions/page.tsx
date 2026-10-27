"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Check, X } from "lucide-react";
import Link from "next/link";
import { Suspense, useState } from "react";

import { JsonViewer } from "@/components/investigation";
import { SimulatedBadge } from "@/components/ui/badges";
import { Pagination } from "@/components/ui/data-table";
import { FilterChips, Toolbar } from "@/components/ui/filters";
import { ConfirmDialog, useToast } from "@/components/ui/overlays";
import { Button, EmptyState, ErrorState, Field, PageHeader, Panel, SkeletonRows, Textarea, cn } from "@/components/ui/primitives";
import { ApiError, api } from "@/lib/api";
import { formatDateTime, humanize, relativeTime, utcTitle } from "@/lib/format";
import { useCan, useMe, useUrlState } from "@/lib/hooks";
import type { Page, ResponseAction } from "@/lib/types";

const STATUSES = [
  { value: "pending_approval", label: "Pending approval" },
  { value: "executed", label: "Executed" },
  { value: "rejected", label: "Rejected" },
  { value: "failed", label: "Failed" },
  { value: "cancelled", label: "Cancelled" },
];

function ResponseActions() {
  const url = useUrlState();
  const status = url.getAll("status");
  const page = Number(url.get("page", "1")) || 1;
  const { data: me } = useMe();
  const isLead = useCan("lead");
  const qc = useQueryClient();
  const toast = useToast();
  const [decision, setDecision] = useState<{ action: ResponseAction; decision: "approved" | "rejected" } | null>(null);
  const [reason, setReason] = useState("");
  const q = useQuery({ queryKey: ["response-actions", status, page], queryFn: () => api<Page<ResponseAction>>("/response-actions", { query: { status, page, page_size: 20 } }), placeholderData: (p) => p });
  const decide = useMutation({
    mutationFn: () => api<ResponseAction>(`/response-actions/${decision!.action.id}/decision`, { method: "POST", body: { decision: decision!.decision, reason } }),
    onSuccess: (a) => {
      qc.invalidateQueries({ queryKey: ["response-actions"] });
      qc.invalidateQueries({ queryKey: ["incident", a.incident_id] });
      toast({ kind: "success", title: `Action ${humanize(a.status).toLowerCase()}` });
      setDecision(null);
      setReason("");
    },
    onError: (e) => toast({ kind: "error", title: "Decision not recorded", description: e instanceof ApiError ? e.detail : undefined }),
  });
  const cancel = useMutation({
    mutationFn: (id: string) => api(`/response-actions/${id}/cancel`, { method: "POST" }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["response-actions"] });
      toast({ kind: "success", title: "Request cancelled" });
    },
    onError: (e) => toast({ kind: "error", title: "Could not cancel", description: e instanceof ApiError ? e.detail : undefined }),
  });

  return (
    <>
      <PageHeader title="Response actions" description="Every playbook run, with requester, parameters, approval and result. Approvals require the lead role and a different person from the requester." />
      <Panel bodyClassName="p-0">
        <Toolbar>
          <FilterChips label="Status" options={STATUSES} selected={status} onChange={(v) => url.set({ status: v })} />
        </Toolbar>
        {q.isError ? (
          <ErrorState error={q.error} onRetry={() => q.refetch()} />
        ) : !q.data ? (
          <SkeletonRows rows={5} />
        ) : q.data.items.length === 0 ? (
          <EmptyState title={status.length ? "No actions with this status" : "No response actions yet"} description="Run a playbook from an incident's Response tab." />
        ) : (
          <>
            <ul className="divide-y divide-line">
              {q.data.items.map((a) => {
                const mine = a.requested_by === me?.id;
                return (
                  <li key={a.id} className="space-y-2 px-4 py-3">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="text-[13px] font-medium text-fg">{humanize(a.action_type)}</span>
                      <span className={cn("rounded px-1.5 py-px text-[11px]", a.status === "pending_approval" ? "bg-warn/15 text-warn" : a.status === "executed" ? "bg-ok/10 text-ok" : a.status === "failed" ? "bg-danger/15 text-danger" : "bg-raised text-muted")}>{humanize(a.status)}</span>
                      {a.simulated && <SimulatedBadge />}
                      <Link href={`/incidents/${a.incident_id}`} className="mono text-xs text-accent hover:underline">
                        INC-{String(a.incident_number ?? 0).padStart(4, "0")}
                      </Link>
                      <span className="ml-auto text-xs text-subtle" title={utcTitle(a.created_at)}>
                        Requested by {a.requested_by_name ?? "unknown"} {relativeTime(a.created_at)}
                      </span>
                    </div>
                    {Object.keys(a.parameters).length > 0 && <JsonViewer value={a.parameters} maxHeight="6rem" />}
                    {a.status === "executed" && Object.keys(a.result).length > 0 && (
                      <details className="text-xs">
                        <summary className="cursor-pointer text-muted hover:text-fg">Result{a.executed_at ? ` · ${formatDateTime(a.executed_at)}` : ""}</summary>
                        <div className="mt-1.5"><JsonViewer value={a.result} maxHeight="14rem" /></div>
                      </details>
                    )}
                    {a.approval && <p className="text-xs text-muted">{humanize(a.approval.decision)} by {a.approval.decided_by} on {formatDateTime(a.approval.decided_at)}: “{a.approval.reason}”</p>}
                    {a.rollback_plan && <p className="text-xs text-subtle">Rollback: {a.rollback_plan}</p>}
                    {a.error && <p className="text-xs text-danger">{a.error}</p>}
                    {a.status === "pending_approval" && (
                      <div className="flex flex-wrap items-center gap-2">
                        {isLead && !mine && (
                          <>
                            <Button size="sm" variant="primary" icon={<Check className="size-3" aria-hidden />} onClick={() => setDecision({ action: a, decision: "approved" })}>Approve</Button>
                            <Button size="sm" variant="danger" icon={<X className="size-3" aria-hidden />} onClick={() => setDecision({ action: a, decision: "rejected" })}>Reject</Button>
                          </>
                        )}
                        {(mine || isLead) && <Button size="sm" variant="ghost" loading={cancel.isPending && cancel.variables === a.id} onClick={() => cancel.mutate(a.id)}>Cancel request</Button>}
                        {mine && <span className="text-xs text-subtle">Another lead must approve your request.</span>}
                        {!isLead && !mine && <span className="text-xs text-subtle">Awaiting a lead&apos;s decision.</span>}
                      </div>
                    )}
                  </li>
                );
              })}
            </ul>
            <Pagination page={page} pageSize={20} total={q.data.total} onPage={(p) => url.set({ page: p }, { resetPage: false })} />
          </>
        )}
      </Panel>
      <ConfirmDialog
        open={!!decision}
        onOpenChange={(o) => !o && setDecision(null)}
        title={decision?.decision === "approved" ? "Approve simulated action" : "Reject action"}
        description="Approval runs the simulation immediately and records what would have changed. Your decision is audited."
        confirmLabel={decision?.decision === "approved" ? "Approve" : "Reject"}
        destructive={decision?.decision === "rejected"}
        loading={decide.isPending}
        onConfirm={() => reason.trim().length >= 3 && decide.mutate()}
      >
        <Field label="Reason (required)" htmlFor="reason">
          <Textarea id="reason" value={reason} onChange={(e) => setReason(e.target.value)} maxLength={2000} />
        </Field>
      </ConfirmDialog>
    </>
  );
}

export default function ResponseActionsPage() {
  return (
    <Suspense>
      <ResponseActions />
    </Suspense>
  );
}
