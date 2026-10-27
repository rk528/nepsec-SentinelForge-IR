"use client";

import { Activity, AlertTriangle, ArrowUpRight, CircleDot, FileCheck2, MessageSquare, ScrollText, ShieldCheck, Zap } from "lucide-react";
import Link from "next/link";
import { useState } from "react";

import { formatBytes, formatDateTime, formatTime, humanize, utcTitle } from "@/lib/format";
import type { EventRecord, EvidenceItem, TimelineItem } from "@/lib/types";

import { SeverityBadge, SyntheticBadge } from "./ui/badges";
import { Dialog } from "./ui/overlays";
import { EmptyState, KeyValue, cn } from "./ui/primitives";

/**
 * Renders untrusted JSON as text. Values are never interpreted as HTML,
 * links or instructions; React escapes everything inside <pre>.
 */
export function JsonViewer({ value, maxHeight = "24rem" }: { value: unknown; maxHeight?: string }) {
  const text = JSON.stringify(value, null, 2);
  return (
    <pre className="mono overflow-auto rounded-md border border-line bg-canvas p-3 text-[12px] leading-relaxed whitespace-pre-wrap break-all text-muted" style={{ maxHeight }}>
      {text}
    </pre>
  );
}

function eventSubject(e: EventRecord): string {
  return [e.user_name, e.target_user && `→ ${e.target_user}`, e.process_name, e.domain, e.dst_ip && `${e.dst_ip}${e.dst_port ? `:${e.dst_port}` : ""}`].filter(Boolean).join(" · ");
}

export function eventFields(e: EventRecord) {
  const items: { label: string; value: React.ReactNode; mono?: boolean }[] = [
    { label: "Event time", value: <span title={utcTitle(e.event_time)}>{formatDateTime(e.event_time)}</span> },
    { label: "Type", value: e.event_type, mono: true },
    { label: "Host", value: e.host, mono: true },
    { label: "User", value: e.user_name, mono: true },
    { label: "Source IP", value: e.src_ip, mono: true },
    { label: "Destination", value: e.dst_ip ? `${e.dst_ip}${e.dst_port ? `:${e.dst_port}` : ""}` : null, mono: true },
    { label: "Domain", value: e.domain, mono: true },
    { label: "URL", value: e.url, mono: true },
    { label: "Process", value: e.process_name, mono: true },
    { label: "Parent process", value: e.parent_process, mono: true },
    { label: "Target account", value: e.target_user, mono: true },
    { label: "Group", value: e.group_name },
    { label: "Email sender", value: e.email_sender, mono: true },
    { label: "Email subject", value: e.email_subject },
    { label: "Bytes out", value: e.bytes_out !== null ? formatBytes(e.bytes_out) : null },
    { label: "File hash", value: e.file_hash, mono: true },
    { label: "Outcome", value: e.outcome },
    { label: "Data source", value: e.data_source_name },
  ];
  return items.filter((i) => i.value !== null && i.value !== undefined && i.value !== "");
}

export function EventDialog({ event, onClose }: { event: EventRecord | null; onClose: () => void }) {
  return (
    <Dialog open={!!event} onOpenChange={(o) => !o && onClose()} title={event ? humanize(event.event_type) : "Event"} description={event ? "Normalised fields, then the raw payload as received." : undefined} size="lg">
      {event && (
        <div className="space-y-4">
          {event.is_synthetic && <SyntheticBadge />}
          <KeyValue items={eventFields(event)} />
          {event.command_line && (
            <div>
              <p className="mb-1 text-[11px] font-medium tracking-wide text-subtle uppercase">Command line</p>
              <JsonViewer value={event.command_line} maxHeight="8rem" />
            </div>
          )}
          <div>
            <p className="mb-1 text-[11px] font-medium tracking-wide text-subtle uppercase">Raw payload (untrusted)</p>
            {event.raw ? <JsonViewer value={event.raw} maxHeight="14rem" /> : <p className="text-xs text-muted">Raw payloads are visible to analysts and above.</p>}
          </div>
          <Link href={`/events/${event.id}`} className="inline-flex items-center gap-1 text-xs text-accent hover:underline">
            Open event page with provenance and related events <ArrowUpRight className="size-3" aria-hidden />
          </Link>
        </div>
      )}
    </Dialog>
  );
}

export function EventList({ events, empty = "No events linked." }: { events: EventRecord[]; empty?: string }) {
  const [open, setOpen] = useState<EventRecord | null>(null);
  if (events.length === 0) return <EmptyState title={empty} />;
  return (
    <>
      <div className="overflow-x-auto">
        <table className="w-full text-left text-[13px]">
          <caption className="sr-only">Events</caption>
          <thead>
            <tr className="border-b border-line text-[11px] tracking-wide text-subtle uppercase">
              <th scope="col" className="h-8 pr-3 pl-4 font-medium">Time</th>
              <th scope="col" className="px-3 font-medium">Type</th>
              <th scope="col" className="px-3 font-medium">Host</th>
              <th scope="col" className="hidden px-3 font-medium md:table-cell">Detail</th>
              <th scope="col" className="hidden pr-4 pl-3 font-medium lg:table-cell">Source</th>
            </tr>
          </thead>
          <tbody>
            {events.map((e) => (
              <tr key={e.id} className="border-b border-line/60 last:border-0 hover:bg-raised/60">
                <td className="py-2 pr-3 pl-4 whitespace-nowrap">
                  <button type="button" onClick={() => setOpen(e)} className="mono text-xs text-fg hover:text-accent hover:underline" title={utcTitle(e.event_time)}>
                    {formatDateTime(e.event_time)}
                  </button>
                </td>
                <td className="mono px-3 text-xs whitespace-nowrap text-muted">{e.event_type}</td>
                <td className="mono px-3 text-xs whitespace-nowrap text-fg">{e.host ?? "—"}</td>
                <td className="mono hidden max-w-md truncate px-3 text-xs text-muted md:table-cell">{eventSubject(e) || e.message || "—"}</td>
                <td className="hidden truncate pr-4 pl-3 text-xs text-subtle lg:table-cell">{e.data_source_name ?? "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <EventDialog event={open} onClose={() => setOpen(null)} />
    </>
  );
}

const KIND: Record<TimelineItem["kind"], { icon: typeof Activity; cls: string; label: string }> = {
  event: { icon: Activity, cls: "text-subtle", label: "Telemetry" },
  alert: { icon: AlertTriangle, cls: "text-warn", label: "Alert" },
  note: { icon: MessageSquare, cls: "text-info", label: "Note" },
  status: { icon: CircleDot, cls: "text-accent", label: "Status" },
  action: { icon: Zap, cls: "text-teal", label: "Response" },
  evidence: { icon: FileCheck2, cls: "text-ok", label: "Evidence" },
  audit: { icon: ScrollText, cls: "text-muted", label: "Audit" },
};

export function Timeline({ items }: { items: TimelineItem[] }) {
  if (items.length === 0) return <EmptyState title="Nothing on the timeline yet" />;
  return (
    <ol className="relative">
      {items.map((item, idx) => {
        const day = new Date(item.at).toDateString();
        const showDay = idx === 0 || day !== new Date(items[idx - 1].at).toDateString();
        const k = KIND[item.kind];
        const Icon = k.icon;
        const quiet = item.kind === "event";
        return (
          <li key={`${item.ref_id}-${idx}`}>
            {showDay && <p className="sticky top-0 z-10 bg-surface py-1.5 text-[11px] font-medium tracking-wide text-subtle uppercase">{new Date(item.at).toLocaleDateString(undefined, { weekday: "short", month: "short", day: "numeric", year: "numeric" })}</p>}
            <div className="relative flex gap-3 pb-3 pl-1">
              <span aria-hidden className="absolute top-6 bottom-0 left-[13px] w-px bg-line" />
              <span className={cn("relative z-[1] mt-0.5 grid size-6 shrink-0 place-items-center rounded-full border border-line bg-raised", k.cls)}>
                <Icon className="size-3" aria-hidden />
              </span>
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-baseline gap-x-2">
                  <span className="mono text-[11px] text-subtle" title={utcTitle(item.at)}>
                    {formatTime(item.at)}
                  </span>
                  <span className="sr-only">{k.label}:</span>
                  <span className={cn("text-[13px]", quiet ? "text-muted" : "text-fg")}>{item.title}</span>
                  {item.severity && <SeverityBadge severity={item.severity} />}
                </div>
                {(item.detail || item.actor) && (
                  <p className="mt-0.5 text-xs break-words text-subtle">
                    {item.actor && <span className="text-muted">{item.actor}</span>}
                    {item.actor && item.detail && " · "}
                    {item.detail && <span className={item.kind === "event" ? "mono" : ""}>{item.detail}</span>}
                  </p>
                )}
                {item.kind === "alert" && item.ref_id && (
                  <Link href={`/alerts/${item.ref_id}`} className="mt-0.5 inline-flex items-center gap-1 text-xs text-accent hover:underline">
                    View alert <ArrowUpRight className="size-3" aria-hidden />
                  </Link>
                )}
              </div>
            </div>
          </li>
        );
      })}
    </ol>
  );
}

export function EvidenceList({ items }: { items: EvidenceItem[] }) {
  const [open, setOpen] = useState<EvidenceItem | null>(null);
  if (items.length === 0) return <EmptyState title="No evidence records" description="Linking alerts and running investigation playbooks creates evidence records with provenance." />;
  return (
    <>
      <ul className="divide-y divide-line">
        {items.map((e) => (
          <li key={e.id} className="flex items-start gap-3 px-4 py-3">
            <ShieldCheck className="mt-0.5 size-4 shrink-0 text-ok" aria-hidden />
            <div className="min-w-0 flex-1">
              <button type="button" onClick={() => setOpen(e)} className="text-left text-[13px] font-medium text-fg hover:underline">
                {e.title}
              </button>
              <p className="mt-0.5 text-xs text-subtle">
                {humanize(e.evidence_type)} · {String(e.provenance.method ?? "unknown method")} · <span title={utcTitle(e.created_at)}>{formatDateTime(e.created_at)}</span>
              </p>
            </div>
            <span className="mono hidden text-[11px] text-subtle sm:block" title={`SHA-256 ${e.sha256}`}>
              sha256:{e.sha256.slice(0, 10)}…
            </span>
          </li>
        ))}
      </ul>
      <Dialog open={!!open} onOpenChange={(o) => !o && setOpen(null)} title={open?.title ?? "Evidence"} description="Immutable record. The hash covers the content below." size="lg">
        {open && (
          <div className="space-y-4">
            {open.description && <p className="text-[13px] text-muted">{open.description}</p>}
            <KeyValue
              items={[
                { label: "Type", value: humanize(open.evidence_type) },
                { label: "Collected", value: formatDateTime(open.created_at) },
                { label: "SHA-256", value: open.sha256, mono: true },
                { label: "Source reference", value: open.source_ref, mono: true },
              ]}
            />
            <div>
              <p className="mb-1 text-[11px] font-medium tracking-wide text-subtle uppercase">Provenance</p>
              <JsonViewer value={open.provenance} maxHeight="10rem" />
            </div>
            <div>
              <p className="mb-1 text-[11px] font-medium tracking-wide text-subtle uppercase">Content</p>
              {typeof open.content.markdown === "string" ? (
                <pre className="mono max-h-80 overflow-auto rounded-md border border-line bg-canvas p-3 text-[12px] whitespace-pre-wrap text-muted">{open.content.markdown}</pre>
              ) : (
                <JsonViewer value={open.content} />
              )}
            </div>
          </div>
        )}
      </Dialog>
    </>
  );
}
