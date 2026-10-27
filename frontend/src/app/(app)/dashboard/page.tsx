"use client";

import { useQuery } from "@tanstack/react-query";
import { ArrowUpRight, Clock, Radar, Siren, Timer } from "lucide-react";
import Link from "next/link";
import { Suspense, type ReactNode } from "react";

import { BarList, SeverityTrendChart } from "@/components/charts";
import { IncidentStatusBadge, SEVERITY_COLOR, SEVERITY_ORDER, SeverityBadge, StatusDot, SyntheticBadge } from "@/components/ui/badges";
import { EmptyState, ErrorState, PageHeader, Panel, Segmented, Skeleton, cn } from "@/components/ui/primitives";
import { api } from "@/lib/api";
import { formatMinutes, humanize, relativeTime, utcTitle } from "@/lib/format";
import { useUrlState } from "@/lib/hooks";
import type { IncidentStatus, Severity } from "@/lib/types";

interface Summary {
  range: { days: number; start: string; end: string };
  synthetic: boolean;
  open_incidents: { total: number; by_severity: Record<Severity, number> };
  incident_status: Record<IncidentStatus, number>;
  incident_trend: ({ date: string } & Record<Severity, number>)[];
  alert_trend: ({ date: string } & Record<Severity, number>)[];
  detections: { total: number; by_rule: { rule_id: string; name: string; count: number }[]; by_status: Record<string, number> };
  mtta: { minutes: number | null; sample_size: number };
  mttr: { minutes: number | null; sample_size: number };
  priority_incidents: { id: string; reference: string; title: string; severity: Severity; status: IncidentStatus; created_at: string }[];
  telemetry: {
    sources: { id: string; name: string; source_type: string; events_in_range: number; last_event_at: string | null; healthy: boolean; is_synthetic: boolean }[];
    assets_total: number;
    assets_reporting_24h: number;
  };
  recent_activity: { id: string; actor: string; action: string; target_type: string | null; target_id: string | null; at: string }[];
}

const RANGES = [
  { value: 1, label: "24h" },
  { value: 7, label: "7d" },
  { value: 14, label: "14d" },
  { value: 30, label: "30d" },
];

function Kpi({ label, value, sub, icon, href }: { label: string; value: ReactNode; sub: ReactNode; icon: ReactNode; href?: string }) {
  const body = (
    <>
      <div className="flex items-center justify-between text-xs text-muted">
        <span>{label}</span>
        <span className="text-subtle">{icon}</span>
      </div>
      <div className="mt-2 text-2xl font-semibold tracking-tight text-fg tabular-nums">{value}</div>
      <div className="mt-1 text-xs text-muted">{sub}</div>
    </>
  );
  const cls = "block rounded-lg border border-line bg-surface p-4 transition-colors";
  return href ? (
    <Link href={href} className={cn(cls, "group hover:border-line-strong hover:bg-raised/40")}>
      {body}
    </Link>
  ) : (
    <div className={cls}>{body}</div>
  );
}

function activityHref(a: Summary["recent_activity"][number]): string | undefined {
  if (!a.target_id) return undefined;
  if (a.target_type === "incident") return `/incidents/${a.target_id}`;
  if (a.target_type === "alert") return `/alerts/${a.target_id}`;
  if (a.target_type === "indicator") return `/threat-intel?id=${a.target_id}`;
  return undefined;
}

function Dashboard() {
  const url = useUrlState();
  const days = Number(url.get("days", "14")) || 14;
  const q = useQuery({ queryKey: ["dashboard", days], queryFn: () => api<Summary>("/dashboard/summary", { query: { days } }) });
  const s = q.data;

  return (
    <>
      <PageHeader
        title="Security overview"
        description="Computed from stored incidents, alerts and telemetry. Select a metric to see the records behind it."
        meta={s?.synthetic ? <SyntheticBadge /> : undefined}
        actions={<Segmented label="Time range" value={days} options={RANGES} onChange={(v) => url.set({ days: v })} />}
      />
      {q.isError ? (
        <Panel>
          <ErrorState error={q.error} onRetry={() => q.refetch()} />
        </Panel>
      ) : (
        <div className="space-y-4">
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4">
            {!s ? (
              Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-[106px] rounded-lg" />)
            ) : (
              <>
                <Kpi
                  label="Open incidents"
                  icon={<Siren className="size-4" aria-hidden />}
                  value={s.open_incidents.total}
                  href="/incidents?status=new&status=open&status=investigating&status=contained"
                  sub={
                    <span className="flex flex-wrap gap-x-3">
                      {SEVERITY_ORDER.filter((k) => s.open_incidents.by_severity[k]).map((k) => (
                        <span key={k} className="inline-flex items-center gap-1">
                          <span className="size-1.5 rounded-full" style={{ background: SEVERITY_COLOR[k] }} />
                          {s.open_incidents.by_severity[k]} {k === "informational" ? "info" : k}
                        </span>
                      ))}
                      {s.open_incidents.total === 0 && "None open"}
                    </span>
                  }
                />
                <Kpi label={`Alerts, last ${days === 1 ? "24h" : `${days}d`}`} icon={<Radar className="size-4" aria-hidden />} value={s.detections.total} href={`/alerts?hours=${days * 24}`} sub={`${s.detections.by_status.new ?? 0} awaiting triage · ${s.detections.by_status.escalated ?? 0} escalated`} />
                <Kpi label="Mean time to acknowledge" icon={<Clock className="size-4" aria-hidden />} value={formatMinutes(s.mtta.minutes)} sub={s.mtta.sample_size ? `Across ${s.mtta.sample_size} incident${s.mtta.sample_size === 1 ? "" : "s"} opened in range` : "No acknowledged incidents in range"} />
                <Kpi label="Mean time to resolve" icon={<Timer className="size-4" aria-hidden />} value={formatMinutes(s.mttr.minutes)} sub={s.mttr.sample_size ? `Across ${s.mttr.sample_size} resolved incident${s.mttr.sample_size === 1 ? "" : "s"}` : "No resolved incidents in range"} />
              </>
            )}
          </div>

          <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
            <Panel title="Alert volume by severity" description="Alerts by first-seen day (UTC)" className="xl:col-span-2" id="alert-volume">
              {s ? <SeverityTrendChart data={s.alert_trend} label="Daily alert volume by severity" emptyText="No alerts were raised in this time range." /> : <Skeleton className="h-56" />}
            </Panel>
            <Panel title="Investigation status" description="Open incidents, plus any updated in range" id="status">
              {s ? (
                <BarList
                  emptyText="No incidents in this range."
                  items={(["new", "open", "investigating", "contained", "resolved", "closed"] as IncidentStatus[]).map((st) => ({
                    key: st,
                    label: <IncidentStatusBadge status={st} />,
                    value: s.incident_status[st] ?? 0,
                    href: `/incidents?status=${st}`,
                    color: "var(--color-line-strong)",
                  }))}
                />
              ) : (
                <Skeleton className="h-48" />
              )}
            </Panel>
          </div>

          <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
            <Panel title="High-priority open incidents" description="Critical and high severity, not yet closed" className="xl:col-span-2" bodyClassName="p-0" id="priority">
              {!s ? (
                <div className="space-y-3 p-4">
                  <Skeleton />
                  <Skeleton />
                  <Skeleton />
                </div>
              ) : s.priority_incidents.length === 0 ? (
                <EmptyState title="No high-priority incidents open" description="Critical and high severity incidents will appear here." />
              ) : (
                <ul className="divide-y divide-line">
                  {s.priority_incidents.map((i) => (
                    <li key={i.id}>
                      <Link href={`/incidents/${i.id}`} className="flex items-center gap-3 px-4 py-2.5 hover:bg-raised/60">
                        <SeverityBadge severity={i.severity} />
                        <span className="mono w-20 shrink-0 text-xs text-muted">{i.reference}</span>
                        <span className="min-w-0 flex-1 truncate text-[13px] text-fg">{i.title}</span>
                        <span className="hidden sm:block">
                          <IncidentStatusBadge status={i.status} />
                        </span>
                        <span className="hidden w-16 text-right text-xs text-subtle md:block" title={utcTitle(i.created_at)}>
                          {relativeTime(i.created_at)}
                        </span>
                      </Link>
                    </li>
                  ))}
                </ul>
              )}
            </Panel>
            <Panel title="Detections by rule" description="Alerts raised in range" id="by-rule">
              {s ? (
                <BarList
                  emptyText="No rules fired in this range."
                  items={s.detections.by_rule.map((r) => ({ key: r.rule_id, label: <span><span className="mono text-muted">{r.rule_id}</span> {r.name}</span>, value: r.count, href: `/alerts?rule_id=${r.rule_id}&hours=${days * 24}` }))}
                />
              ) : (
                <Skeleton className="h-48" />
              )}
            </Panel>
          </div>

          <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
            <Panel
              title="Telemetry health"
              description={s ? `${s.telemetry.assets_reporting_24h} of ${s.telemetry.assets_total} assets reported in the last 24h` : "Data source status"}
              bodyClassName="p-0"
              id="telemetry"
            >
              {!s ? (
                <div className="space-y-3 p-4">
                  <Skeleton />
                  <Skeleton />
                </div>
              ) : s.telemetry.sources.length === 0 ? (
                <EmptyState title="No data sources" description="Create a data source in Settings to start ingesting events." />
              ) : (
                <ul className="divide-y divide-line">
                  {s.telemetry.sources.map((src) => (
                    <li key={src.id} className="flex items-center gap-3 px-4 py-2.5 text-[13px]">
                      <span className="inline-flex w-24 items-center gap-1.5 text-xs">
                        <StatusDot className={src.healthy ? "bg-ok" : "bg-warn"} />
                        {src.healthy ? "Reporting" : "Stale"}
                      </span>
                      <Link href={`/events?data_source_id=${src.id}`} className="min-w-0 flex-1 truncate text-fg hover:underline">
                        {src.name}
                      </Link>
                      <span className="hidden text-xs text-muted tabular-nums sm:block">{src.events_in_range.toLocaleString()} events</span>
                      <span className="w-20 text-right text-xs text-subtle" title={utcTitle(src.last_event_at)}>
                        {relativeTime(src.last_event_at)}
                      </span>
                    </li>
                  ))}
                </ul>
              )}
            </Panel>
            <Panel title="Recent analyst actions" description="From the audit log" bodyClassName="p-0" id="activity" actions={<Link href="/audit" className="inline-flex items-center gap-1 text-xs text-muted hover:text-fg">Audit log <ArrowUpRight className="size-3" aria-hidden /></Link>}>
              {!s ? (
                <div className="space-y-3 p-4">
                  <Skeleton />
                  <Skeleton />
                </div>
              ) : s.recent_activity.length === 0 ? (
                <EmptyState title="No analyst activity yet" description="Notes, status changes and approvals will appear here." />
              ) : (
                <ul className="divide-y divide-line">
                  {s.recent_activity.map((a) => {
                    const href = activityHref(a);
                    const text = (
                      <>
                        <span className="text-fg">{a.actor}</span> <span className="text-muted">{humanize(a.action.split(".").slice(1).join(" "))}</span>{" "}
                        <span className="text-subtle">{a.target_type ? humanize(a.target_type).toLowerCase() : ""}</span>
                      </>
                    );
                    return (
                      <li key={a.id} className="flex items-center gap-3 px-4 py-2.5 text-[13px]">
                        <span className="min-w-0 flex-1 truncate">{href ? <Link href={href} className="hover:underline">{text}</Link> : text}</span>
                        <span className="text-xs text-subtle" title={utcTitle(a.at)}>
                          {relativeTime(a.at)}
                        </span>
                      </li>
                    );
                  })}
                </ul>
              )}
            </Panel>
          </div>
        </div>
      )}
    </>
  );
}

export default function DashboardPage() {
  return (
    <Suspense>
      <Dashboard />
    </Suspense>
  );
}
