"use client";

import { useQuery } from "@tanstack/react-query";
import { FileText } from "lucide-react";
import Link from "next/link";
import { Suspense } from "react";

import { IncidentStatusBadge, SeverityBadge, VerdictBadge } from "@/components/ui/badges";
import { DataTable, Pagination, type Column } from "@/components/ui/data-table";
import { SearchBox, Toolbar } from "@/components/ui/filters";
import { EmptyState, ErrorState, PageHeader, Panel, SkeletonRows } from "@/components/ui/primitives";
import { api } from "@/lib/api";
import { formatDateTime } from "@/lib/format";
import { useUrlState } from "@/lib/hooks";
import type { Incident, Page } from "@/lib/types";

const columns: Column<Incident>[] = [
  { key: "ref", header: "Ref", render: (i) => <span className="mono text-xs whitespace-nowrap text-muted">{i.reference}</span>, className: "w-24 whitespace-nowrap" },
  {
    key: "title",
    header: "Incident",
    render: (i) => (
      <Link href={`/reports/${i.id}`} className="inline-flex items-center gap-2 font-medium text-fg hover:underline">
        <FileText className="size-3.5 text-subtle" aria-hidden />
        <span className="truncate">{i.title}</span>
      </Link>
    ),
  },
  { key: "sev", header: "Severity", render: (i) => <SeverityBadge severity={i.severity} />, className: "w-28" },
  { key: "status", header: "Status", render: (i) => <IncidentStatusBadge status={i.status} />, className: "w-32" },
  { key: "verdict", header: "Verdict", hideBelow: "md", render: (i) => <VerdictBadge verdict={i.verdict} /> },
  { key: "closed", header: "Closed", hideBelow: "lg", render: (i) => <span className="text-xs text-subtle">{i.closed_at ? formatDateTime(i.closed_at) : "Open"}</span> },
];

function Reports() {
  const url = useUrlState();
  const q = url.get("q");
  const page = Number(url.get("page", "1")) || 1;
  const data = useQuery({ queryKey: ["incidents", "reports", q, page], queryFn: () => api<Page<Incident>>("/incidents", { query: { q, page, page_size: 25, sort: "updated_at" } }), placeholderData: (p) => p });
  return (
    <>
      <PageHeader title="Reports" description="Evidence-backed incident reports assembled from stored records. Export as Markdown or JSON, or print to PDF from the report view." />
      <Panel bodyClassName="p-0">
        <Toolbar>
          <SearchBox label="Search incidents" placeholder="Search incidents" value={q} onChange={(v) => url.set({ q: v })} />
        </Toolbar>
        {data.isError ? (
          <ErrorState error={data.error} onRetry={() => data.refetch()} />
        ) : !data.data ? (
          <SkeletonRows />
        ) : data.data.items.length === 0 ? (
          <EmptyState title="No incidents to report on" />
        ) : (
          <>
            <DataTable caption="Incident reports" columns={columns} rows={data.data.items} rowKey={(i) => i.id} rowHref={(i) => `/reports/${i.id}`} />
            <Pagination page={page} pageSize={25} total={data.data.total} onPage={(p) => url.set({ page: p }, { resetPage: false })} />
          </>
        )}
      </Panel>
    </>
  );
}

export default function ReportsPage() {
  return (
    <Suspense>
      <Reports />
    </Suspense>
  );
}
