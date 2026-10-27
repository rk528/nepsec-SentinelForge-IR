"use client";

import { useQuery } from "@tanstack/react-query";
import Link from "next/link";
import { Suspense } from "react";

import { AlertStatusBadge, ConfidenceMeter, SeverityBadge } from "@/components/ui/badges";
import { DataTable, Pagination, type Column } from "@/components/ui/data-table";
import { FilterChips, SearchBox, Toolbar } from "@/components/ui/filters";
import { Button, EmptyState, ErrorState, PageHeader, Panel, Segmented, Select, SkeletonRows } from "@/components/ui/primitives";
import { api } from "@/lib/api";
import { relativeTime, utcTitle } from "@/lib/format";
import { useUrlState } from "@/lib/hooks";
import { ALERT_STATUS_OPTIONS, SEVERITY_OPTIONS } from "@/lib/options";
import type { Alert, Page, RuleRow } from "@/lib/types";

const columns: Column<Alert>[] = [
  { key: "severity", header: "Severity", sortKey: "severity", hideBelow: "sm", render: (a) => <SeverityBadge severity={a.severity} />, className: "w-28" },
  {
    key: "title",
    header: "Alert",
    render: (a) => (
      <div className="min-w-0 py-0.5">
        <Link href={`/alerts/${a.id}`} className="block leading-snug font-medium text-fg hover:underline lg:truncate">
          {a.title}
        </Link>
        <p className="mt-0.5 text-xs text-muted lg:truncate">
          <span className="mono">{a.rule_id}</span> · {a.rule_name}
        </p>
        {/* On phones severity, status and timing collapse into this cell. */}
        <div className="mt-1.5 flex flex-wrap items-center gap-1.5 sm:hidden">
          <SeverityBadge severity={a.severity} />
          <AlertStatusBadge status={a.status} />
          <span className="text-xs text-muted">{relativeTime(a.last_seen)}</span>
        </div>
      </div>
    ),
    className: "max-w-[30rem]",
  },
  { key: "confidence", header: "Confidence", hideBelow: "lg", render: (a) => <ConfidenceMeter confidence={a.confidence} /> },
  { key: "status", header: "Status", hideBelow: "sm", render: (a) => <AlertStatusBadge status={a.status} />, className: "w-32" },
  {
    key: "incident",
    header: "Incident",
    hideBelow: "md",
    render: (a) =>
      a.incident_id ? (
        <Link href={`/incidents/${a.incident_id}`} className="mono text-xs whitespace-nowrap text-accent hover:underline">
          INC-{String(a.incident_number ?? 0).padStart(4, "0")}
        </Link>
      ) : (
        <span className="text-xs text-subtle">—</span>
      ),
  },
  { key: "count", header: "Events", sortKey: "occurrence_count", hideBelow: "md", render: (a) => <span className="text-xs text-muted tabular-nums">{a.occurrence_count}</span> },
  { key: "first", header: "First seen", sortKey: "first_seen", hideBelow: "lg", render: (a) => <span className="text-sm whitespace-nowrap text-muted" title={utcTitle(a.first_seen)}>{relativeTime(a.first_seen)}</span> },
  { key: "last", header: "Last seen", sortKey: "last_seen", hideBelow: "sm", render: (a) => <span className="text-sm whitespace-nowrap text-muted" title={utcTitle(a.last_seen)}>{relativeTime(a.last_seen)}</span>, className: "w-24" },
];

const RANGES = [
  { value: "24", label: "24h" },
  { value: "168", label: "7d" },
  { value: "720", label: "30d" },
  { value: "", label: "All" },
];

function Alerts() {
  const url = useUrlState();
  const status = url.getAll("status");
  const severity = url.getAll("severity");
  const ruleIds = url.getAll("rule_id");
  const q = url.get("q");
  const hours = url.get("hours");
  const escalated = url.get("escalated");
  const sort = url.get("sort", "last_seen");
  const order = (url.get("order", "desc") as "asc" | "desc") || "desc";
  const page = Number(url.get("page", "1")) || 1;

  const rules = useQuery({ queryKey: ["rules"], queryFn: () => api<RuleRow[]>("/detections"), staleTime: 5 * 60_000 });
  const data = useQuery({
    queryKey: ["alerts", { status, severity, ruleIds, q, hours, escalated, sort, order, page }],
    queryFn: ({ signal }) => api<Page<Alert>>("/alerts", { query: { status, severity, rule_id: ruleIds, q, hours: hours || undefined, escalated: escalated || undefined, sort, order, page, page_size: 25 }, signal }),
    placeholderData: (prev) => prev,
  });
  const filtered = status.length + severity.length + ruleIds.length > 0 || !!q || !!escalated;
  const rangeValue = RANGES.some((r) => r.value === hours) ? hours : "";

  return (
    <>
      <PageHeader
        title="Alert queue"
        description="Deduplicated detections awaiting triage. Each alert records the rule that fired and the events that matched."
        actions={<Segmented label="Time range" value={rangeValue} options={RANGES} onChange={(v) => url.set({ hours: v || null })} />}
      />
      <Panel bodyClassName="p-0">
        <Toolbar>
          <SearchBox label="Search alerts" placeholder="Search title, description or rule" value={q} onChange={(v) => url.set({ q: v })} />
          <FilterChips label="Status" options={ALERT_STATUS_OPTIONS} selected={status} onChange={(v) => url.set({ status: v })} />
          <FilterChips label="Severity" options={SEVERITY_OPTIONS} selected={severity} onChange={(v) => url.set({ severity: v })} />
          <div className="flex items-center gap-2 lg:ml-auto">
            <label htmlFor="rule" className="sr-only">
              Detection rule
            </label>
            <Select id="rule" className="w-56" value={ruleIds[0] ?? ""} onChange={(e) => url.set({ rule_id: e.target.value ? [e.target.value] : null })}>
              <option value="">All detection sources</option>
              {rules.data?.map((r) => (
                <option key={r.id} value={r.id}>
                  {r.id} · {r.name}
                </option>
              ))}
            </Select>
            <label htmlFor="esc" className="sr-only">
              Escalation
            </label>
            <Select id="esc" className="w-36" value={escalated} onChange={(e) => url.set({ escalated: e.target.value || null })}>
              <option value="">Any linkage</option>
              <option value="false">Not escalated</option>
              <option value="true">Linked to incident</option>
            </Select>
          </div>
        </Toolbar>
        {data.isError ? (
          <ErrorState error={data.error} onRetry={() => data.refetch()} />
        ) : !data.data ? (
          <SkeletonRows />
        ) : data.data.items.length === 0 ? (
          <EmptyState
            title={filtered || hours ? "No alerts match these filters" : "No alerts yet"}
            description={filtered || hours ? "Widen the time range or clear filters." : "Alerts appear when ingested events match a detection rule."}
            action={(filtered || hours) && <Button size="sm" onClick={() => url.set({ status: null, severity: null, rule_id: null, q: null, hours: null, escalated: null })}>Clear filters</Button>}
          />
        ) : (
          <>
            <DataTable caption="Alerts" columns={columns} rows={data.data.items} rowKey={(a) => a.id} rowHref={(a) => `/alerts/${a.id}`} sort={sort} order={order} onSort={(k) => url.set({ sort: k, order: sort === k && order === "desc" ? "asc" : "desc" })} />
            <Pagination page={page} pageSize={25} total={data.data.total} onPage={(p) => url.set({ page: p }, { resetPage: false })} />
          </>
        )}
      </Panel>
    </>
  );
}

export default function AlertsPage() {
  return (
    <Suspense>
      <Alerts />
    </Suspense>
  );
}
