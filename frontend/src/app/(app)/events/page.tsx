"use client";

import { useQuery } from "@tanstack/react-query";
import { Suspense, useState } from "react";

import { EventDialog } from "@/components/investigation";
import { SyntheticBadge } from "@/components/ui/badges";
import { DataTable, Pagination, type Column } from "@/components/ui/data-table";
import { SearchBox, Toolbar } from "@/components/ui/filters";
import { Button, EmptyState, ErrorState, Input, PageHeader, Panel, Segmented, Select, SkeletonRows } from "@/components/ui/primitives";
import { api } from "@/lib/api";
import { formatDateTime, utcTitle } from "@/lib/format";
import { useUrlState } from "@/lib/hooks";
import type { DataSource, EventRecord, Page } from "@/lib/types";

const EVENT_TYPES = ["auth.success", "auth.failure", "process.start", "iam.user_created", "iam.group_member_added", "log.cleared", "service.stopped", "network.connection", "dns.query", "proxy.request", "email.delivered", "file.created"];

const RANGES = [
  { value: "24", label: "24h" },
  { value: "168", label: "7d" },
  { value: "720", label: "30d" },
  { value: "", label: "All" },
];

function Events() {
  const url = useUrlState();
  const [open, setOpen] = useState<EventRecord | null>(null);
  const q = url.get("q");
  const type = url.get("event_type");
  const host = url.get("host");
  const user = url.get("user");
  const ip = url.get("ip");
  const domain = url.get("domain");
  const source = url.get("data_source_id");
  const hours = url.get("hours");
  const page = Number(url.get("page", "1")) || 1;
  const [pivot, setPivot] = useState({ host, user, ip, domain });

  const sources = useQuery({ queryKey: ["data-sources"], queryFn: () => api<DataSource[]>("/data-sources"), staleTime: 5 * 60_000 });
  const data = useQuery({
    queryKey: ["events", { q, type, host, user, ip, domain, source, hours, page }],
    queryFn: ({ signal }) => api<Page<EventRecord>>("/events", { query: { q, event_type: type ? [type] : undefined, host, user, ip, domain, data_source_id: source || undefined, hours: hours || undefined, page, page_size: 50 }, signal }),
    placeholderData: (prev) => prev,
  });

  const pivotFilter = (field: "host" | "user" | "ip" | "domain", value: string | null) =>
    value ? (
      <button type="button" onClick={() => url.set({ [field]: value })} className="mono text-xs text-fg hover:text-accent hover:underline" title={`Filter by ${field} ${value}`}>
        {value}
      </button>
    ) : (
      <span className="text-xs text-subtle">—</span>
    );

  const columns: Column<EventRecord>[] = [
    {
      key: "time",
      header: "Time",
      render: (e) => (
        <button type="button" onClick={() => setOpen(e)} className="mono text-xs whitespace-nowrap text-fg hover:text-accent hover:underline" title={utcTitle(e.event_time)}>
          {formatDateTime(e.event_time)}
        </button>
      ),
      className: "w-44",
    },
    { key: "type", header: "Type", render: (e) => <span className="mono text-xs text-muted">{e.event_type}</span> },
    { key: "host", header: "Host", render: (e) => pivotFilter("host", e.host) },
    { key: "user", header: "User", hideBelow: "md", render: (e) => pivotFilter("user", e.user_name) },
    { key: "src", header: "Source IP", hideBelow: "lg", render: (e) => pivotFilter("ip", e.src_ip) },
    { key: "dst", header: "Destination", hideBelow: "lg", render: (e) => (e.domain ? pivotFilter("domain", e.domain) : pivotFilter("ip", e.dst_ip)) },
    { key: "detail", header: "Detail", hideBelow: "md", render: (e) => <span className="mono block max-w-xs truncate text-xs text-subtle">{e.command_line ?? e.process_name ?? e.email_subject ?? e.message ?? ""}</span> },
    { key: "src_name", header: "Source", hideBelow: "lg", render: (e) => <span className="flex items-center gap-1.5 text-xs text-muted"><span className="max-w-40 truncate">{e.data_source_name}</span>{e.is_synthetic && <SyntheticBadge />}</span> },
  ];
  const filtered = !!(q || type || host || user || ip || domain || source || hours);

  return (
    <>
      <PageHeader
        title="Event explorer"
        description="Normalised telemetry, newest first. Select a host, user, IP or domain to pivot. Raw payloads are treated as untrusted text."
        actions={<Segmented label="Time range" value={RANGES.some((r) => r.value === hours) ? hours : ""} options={RANGES} onChange={(v) => url.set({ hours: v || null })} />}
      />
      <Panel bodyClassName="p-0">
        <Toolbar>
          <SearchBox label="Search events" placeholder="Free text: host, user, IP, domain, process, command" value={q} onChange={(v) => url.set({ q: v })} />
          <label htmlFor="etype" className="sr-only">Event type</label>
          <Select id="etype" className="w-48" value={type} onChange={(e) => url.set({ event_type: e.target.value || null })}>
            <option value="">All event types</option>
            {EVENT_TYPES.map((t) => <option key={t} value={t}>{t}</option>)}
          </Select>
          <label htmlFor="esrc" className="sr-only">Data source</label>
          <Select id="esrc" className="w-56" value={source} onChange={(e) => url.set({ data_source_id: e.target.value || null })}>
            <option value="">All data sources</option>
            {sources.data?.map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}
          </Select>
          <form
            className="flex flex-wrap items-center gap-2"
            onSubmit={(e) => {
              e.preventDefault();
              url.set({ host: pivot.host || null, user: pivot.user || null, ip: pivot.ip || null, domain: pivot.domain || null });
            }}
          >
            {(["host", "user", "ip", "domain"] as const).map((f) => (
              <Input key={f} aria-label={`Exact ${f}`} placeholder={f} className="w-28 mono" value={pivot[f] ?? ""} onChange={(e) => setPivot((p) => ({ ...p, [f]: e.target.value }))} />
            ))}
            <Button type="submit" size="sm">Apply</Button>
          </form>
          {filtered && (
            <Button size="sm" variant="ghost" onClick={() => { setPivot({ host: "", user: "", ip: "", domain: "" }); url.set({ q: null, event_type: null, host: null, user: null, ip: null, domain: null, data_source_id: null, hours: null }); }}>
              Clear all
            </Button>
          )}
        </Toolbar>
        {data.isError ? (
          <ErrorState error={data.error} onRetry={() => data.refetch()} />
        ) : !data.data ? (
          <SkeletonRows rows={10} />
        ) : data.data.items.length === 0 ? (
          <EmptyState title={filtered ? "No events match" : "No events ingested yet"} description={filtered ? "Pivots use exact matches. Try free-text search or widen the time range." : "Send events to the ingestion API or run a synthetic scenario from Settings."} />
        ) : (
          <>
            <DataTable caption="Events" columns={columns} rows={data.data.items} rowKey={(e) => e.id} />
            <Pagination page={page} pageSize={50} total={data.data.total} onPage={(p) => url.set({ page: p }, { resetPage: false })} />
          </>
        )}
      </Panel>
      <EventDialog event={open} onClose={() => setOpen(null)} />
    </>
  );
}

export default function EventsPage() {
  return (
    <Suspense>
      <Events />
    </Suspense>
  );
}
