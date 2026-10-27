"use client";

import { useQuery } from "@tanstack/react-query";
import Link from "next/link";
import { useParams } from "next/navigation";

import { EventList, JsonViewer, eventFields } from "@/components/investigation";
import { SeverityBadge, SyntheticBadge } from "@/components/ui/badges";
import { ButtonLink, EmptyState, ErrorState, KeyValue, PageHeader, Panel, Skeleton } from "@/components/ui/primitives";
import { ApiError, api } from "@/lib/api";
import { formatDateTime, humanize } from "@/lib/format";
import type { EventRecord, Severity } from "@/lib/types";

interface EventDetail {
  event: EventRecord;
  provenance: { data_source: { id: string; name: string; type: string; synthetic: boolean }; ingested_at: string; fingerprint: string; scenario_id: string | null };
  alerts: { id: string; title: string; severity: Severity; rule_id: string }[];
  incidents: { id: string; reference: string; title: string; link_reason: string | null }[];
}

export default function EventDetailPage() {
  const { id } = useParams<{ id: string }>();
  const q = useQuery({ queryKey: ["event", id], queryFn: () => api<EventDetail>(`/events/${id}`) });
  const related = useQuery({ queryKey: ["event", id, "related"], queryFn: () => api<EventRecord[]>(`/events/${id}/related`), enabled: q.isSuccess });

  if (q.isError) {
    const notFound = q.error instanceof ApiError && q.error.status === 404;
    return (
      <>
        <PageHeader title="Event" breadcrumbs={[{ label: "Events", href: "/events" }, { label: "Unavailable" }]} />
        <Panel>{notFound ? <EmptyState title="This event does not exist or you do not have access to it." action={<ButtonLink href="/events">Back to events</ButtonLink>} /> : <ErrorState error={q.error} onRetry={() => q.refetch()} />}</Panel>
      </>
    );
  }
  if (!q.data) return <Skeleton className="h-96" />;
  const { event, provenance, alerts, incidents } = q.data;
  return (
    <>
      <PageHeader breadcrumbs={[{ label: "Events", href: "/events" }, { label: event.id.slice(0, 8) }]} title={humanize(event.event_type)} description={`${event.host ?? "Unknown host"} · ${formatDateTime(event.event_time)}`} meta={event.is_synthetic ? <SyntheticBadge /> : undefined} />
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-[minmax(0,1fr)_340px]">
        <div className="min-w-0 space-y-4">
          <Panel title="Normalised fields" id="fields">
            <KeyValue columns={3} items={eventFields(event)} />
            {event.command_line && (
              <div className="mt-4">
                <p className="mb-1 text-[11px] font-medium tracking-wide text-subtle uppercase">Command line (untrusted)</p>
                <JsonViewer value={event.command_line} maxHeight="8rem" />
              </div>
            )}
          </Panel>
          <Panel title="Raw payload" description="Exactly as received. Rendered as inert text; never executed or interpreted." id="raw">
            {event.raw ? <JsonViewer value={event.raw} /> : <p className="text-xs text-muted">Raw payloads are visible to analysts and above.</p>}
          </Panel>
          <Panel title="Related events" description="Same host, user or IP within ±60 minutes" bodyClassName="p-0" id="related">
            {!related.data ? <Skeleton className="m-4 h-24" /> : <EventList events={related.data} empty="No related events in the window." />}
          </Panel>
        </div>
        <div className="space-y-4">
          <Panel title="Provenance" id="prov">
            <KeyValue
              columns={1}
              items={[
                { label: "Data source", value: provenance.data_source.name },
                { label: "Source type", value: provenance.data_source.type },
                { label: "Ingested", value: formatDateTime(provenance.ingested_at) },
                { label: "Scenario", value: provenance.scenario_id, mono: true },
                { label: "Fingerprint (SHA-256)", value: provenance.fingerprint, mono: true },
              ]}
            />
          </Panel>
          <Panel title="Referenced by" id="refs">
            {alerts.length === 0 && incidents.length === 0 ? (
              <p className="text-xs text-muted">Not referenced by any alert or incident.</p>
            ) : (
              <ul className="space-y-2 text-[13px]">
                {alerts.map((a) => (
                  <li key={a.id} className="flex items-center gap-2">
                    <SeverityBadge severity={a.severity} compact />
                    <Link href={`/alerts/${a.id}`} className="min-w-0 flex-1 truncate text-fg hover:underline">{a.title}</Link>
                  </li>
                ))}
                {incidents.map((i) => (
                  <li key={i.id}>
                    <Link href={`/incidents/${i.id}`} className="text-fg hover:underline">
                      <span className="mono text-muted">{i.reference}</span> {i.title}
                    </Link>
                    {i.link_reason && <p className="text-xs text-subtle">{i.link_reason}</p>}
                  </li>
                ))}
              </ul>
            )}
          </Panel>
        </div>
      </div>
    </>
  );
}
