"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Plus } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { Suspense, useState } from "react";
import { useForm } from "react-hook-form";
import { z } from "zod";

import { IncidentStatusBadge, SeverityBadge, SyntheticBadge, Tag } from "@/components/ui/badges";
import { DataTable, Pagination, type Column } from "@/components/ui/data-table";
import { FilterChips, SearchBox, Toolbar } from "@/components/ui/filters";
import { Dialog, useToast } from "@/components/ui/overlays";
import { Button, EmptyState, ErrorState, Field, Input, PageHeader, Panel, Select, SkeletonRows, Textarea } from "@/components/ui/primitives";
import { ApiError, api } from "@/lib/api";
import { plural, relativeTime, utcTitle } from "@/lib/format";
import { useCan, useUrlState } from "@/lib/hooks";
import { SEVERITY_OPTIONS, STATUS_OPTIONS } from "@/lib/options";
import type { Incident, Page, UserRef } from "@/lib/types";

const createSchema = z.object({
  title: z.string().trim().min(3, "At least 3 characters").max(300),
  severity: z.enum(["critical", "high", "medium", "low", "informational"]),
  summary: z.string().max(10000).optional(),
  tags: z.string().max(400).optional(),
});
type CreateValues = z.infer<typeof createSchema>;

function NewIncidentDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  const router = useRouter();
  const toast = useToast();
  const qc = useQueryClient();
  const { register, handleSubmit, reset, formState: { errors } } = useForm<CreateValues>({ resolver: zodResolver(createSchema), defaultValues: { severity: "medium" } });
  const m = useMutation({
    mutationFn: (v: CreateValues) => api<Incident>("/incidents", { method: "POST", body: { ...v, summary: v.summary ?? "", tags: (v.tags ?? "").split(",").map((t) => t.trim()).filter(Boolean) } }),
    onSuccess: (inc) => {
      qc.invalidateQueries({ queryKey: ["incidents"] });
      toast({ kind: "success", title: `${inc.reference} created` });
      reset();
      onOpenChange(false);
      router.push(`/incidents/${inc.id}`);
    },
    onError: (e) => toast({ kind: "error", title: "Could not create incident", description: e instanceof ApiError ? e.detail : undefined }),
  });
  return (
    <Dialog
      open={open}
      onOpenChange={onOpenChange}
      title="New incident"
      description="Create an incident manually. Alerts can be linked to it from the alert queue."
      footer={
        <>
          <Button variant="ghost" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button variant="primary" type="submit" form="new-incident" loading={m.isPending}>
            Create incident
          </Button>
        </>
      }
    >
      <form id="new-incident" onSubmit={handleSubmit((v) => m.mutate(v))} className="space-y-3" noValidate>
        <Field label="Title" htmlFor="title" error={errors.title?.message}>
          <Input id="title" autoFocus aria-invalid={!!errors.title} {...register("title")} />
        </Field>
        <Field label="Severity" htmlFor="severity" hint="Impact if the activity is malicious. This is not the same as confidence.">
          <Select id="severity" {...register("severity")}>
            {SEVERITY_OPTIONS.map((o) => (
              <option key={o.value} value={o.value}>
                {o.label}
              </option>
            ))}
          </Select>
        </Field>
        <Field label="Summary" htmlFor="summary" error={errors.summary?.message}>
          <Textarea id="summary" {...register("summary")} />
        </Field>
        <Field label="Tags" htmlFor="tags" hint="Comma separated, e.g. phishing, vpn">
          <Input id="tags" {...register("tags")} />
        </Field>
      </form>
    </Dialog>
  );
}

const columns: Column<Incident>[] = [
  { key: "ref", header: "Ref", sortKey: "number", hideBelow: "sm", render: (i) => <span className="mono text-xs whitespace-nowrap text-muted">{i.reference}</span>, className: "w-24 whitespace-nowrap" },
  {
    key: "title",
    header: "Incident",
    render: (i) => (
      <div className="py-0.5 sm:min-w-[15rem]">
        <Link href={`/incidents/${i.id}`} className="block leading-snug font-medium text-fg hover:underline lg:truncate">
          {i.title}
        </Link>
        {/* On phones the reference, severity and status columns collapse into this cell. */}
        <div className="mt-1.5 flex flex-wrap items-center gap-1.5 sm:hidden">
          <span className="mono text-xs text-muted">{i.reference}</span>
          <SeverityBadge severity={i.severity} />
          <IncidentStatusBadge status={i.status} />
        </div>
        <div className="mt-0.5 flex flex-wrap items-center gap-1">
          {i.is_synthetic && <SyntheticBadge />}
          {i.tags.slice(0, 3).map((t) => (
            <Tag key={t}>{t}</Tag>
          ))}
        </div>
      </div>
    ),
    className: "max-w-[28rem]",
  },
  { key: "severity", header: "Severity", sortKey: "severity", hideBelow: "sm", render: (i) => <SeverityBadge severity={i.severity} />, className: "w-28" },
  { key: "status", header: "Status", hideBelow: "sm", render: (i) => <IncidentStatusBadge status={i.status} />, className: "w-32" },
  { key: "assignee", header: "Assignee", hideBelow: "md", render: (i) => (i.assignee ? <span className="text-sm whitespace-nowrap text-fg">{i.assignee.display_name}</span> : <span className="text-sm whitespace-nowrap text-muted">Unassigned</span>) },
  { key: "evidence", header: "Evidence", hideBelow: "xl", render: (i) => <span className="text-sm whitespace-nowrap text-muted tabular-nums">{plural(i.alert_count, "alert")} · {plural(i.event_count, "event")}</span> },
  { key: "updated", header: "Updated", sortKey: "updated_at", hideBelow: "sm", render: (i) => <span className="text-sm whitespace-nowrap text-muted" title={utcTitle(i.updated_at)}>{relativeTime(i.updated_at)}</span>, className: "w-24" },
];

function Incidents() {
  const url = useUrlState();
  const canCreate = useCan("analyst");
  const [creating, setCreating] = useState(false);
  const status = url.getAll("status");
  const severity = url.getAll("severity");
  const q = url.get("q");
  const assignee = url.get("assignee_id");
  const sort = url.get("sort", "created_at");
  const order = (url.get("order", "desc") as "asc" | "desc") || "desc";
  const page = Number(url.get("page", "1")) || 1;
  const unassigned = url.get("unassigned") === "true";

  const users = useQuery({ queryKey: ["users"], queryFn: () => api<UserRef[]>("/users"), staleTime: 5 * 60_000 });
  const data = useQuery({
    queryKey: ["incidents", { status, severity, q, assignee, sort, order, page, unassigned }],
    queryFn: ({ signal }) => api<Page<Incident>>("/incidents", { query: { status, severity, q, assignee_id: assignee || undefined, unassigned: unassigned || undefined, sort, order, page, page_size: 25 }, signal }),
    placeholderData: (prev) => prev,
  });
  const filtered = status.length + severity.length > 0 || !!q || !!assignee || unassigned;

  return (
    <>
      <PageHeader
        title="Incidents"
        description="Investigations opened from escalated alerts or created manually."
        actions={canCreate && <Button variant="primary" icon={<Plus className="size-3.5" aria-hidden />} onClick={() => setCreating(true)}>New incident</Button>}
      />
      <Panel bodyClassName="p-0">
        <Toolbar>
          <SearchBox label="Search incidents" placeholder="Search title, summary or INC-0001" value={q} onChange={(v) => url.set({ q: v })} />
          <FilterChips label="Status" options={STATUS_OPTIONS} selected={status} onChange={(v) => url.set({ status: v })} />
          <FilterChips label="Severity" options={SEVERITY_OPTIONS} selected={severity} onChange={(v) => url.set({ severity: v })} />
          <div className="flex items-center gap-2 lg:ml-auto">
            <label htmlFor="assignee" className="sr-only">
              Assignee
            </label>
            <Select id="assignee" className="w-44" value={unassigned ? "__none" : assignee} onChange={(e) => (e.target.value === "__none" ? url.set({ unassigned: "true", assignee_id: null }) : url.set({ assignee_id: e.target.value, unassigned: null }))}>
              <option value="">Any assignee</option>
              <option value="__none">Unassigned</option>
              {users.data?.map((u) => (
                <option key={u.id} value={u.id}>
                  {u.display_name}
                </option>
              ))}
            </Select>
          </div>
        </Toolbar>
        {data.isError ? (
          <ErrorState error={data.error} onRetry={() => data.refetch()} />
        ) : !data.data ? (
          <SkeletonRows />
        ) : data.data.items.length === 0 ? (
          <EmptyState
            title={filtered ? "No incidents match these filters" : "No incidents yet"}
            description={filtered ? "Try removing a filter or widening the search." : "Escalate an alert from the alert queue, or create an incident manually."}
            action={filtered ? <Button size="sm" onClick={() => url.set({ status: null, severity: null, q: null, assignee_id: null, unassigned: null })}>Clear filters</Button> : <Link href="/alerts" className="text-xs text-accent hover:underline">Go to alert queue</Link>}
          />
        ) : (
          <>
            <DataTable
              caption="Incidents"
              columns={columns}
              rows={data.data.items}
              rowKey={(i) => i.id}
              rowHref={(i) => `/incidents/${i.id}`}
              sort={sort}
              order={order}
              onSort={(k) => url.set({ sort: k, order: sort === k && order === "desc" ? "asc" : "desc" })}
            />
            <Pagination page={page} pageSize={25} total={data.data.total} onPage={(p) => url.set({ page: p }, { resetPage: false })} />
          </>
        )}
      </Panel>
      <NewIncidentDialog open={creating} onOpenChange={setCreating} />
    </>
  );
}

export default function IncidentsPage() {
  return (
    <Suspense>
      <Incidents />
    </Suspense>
  );
}
