"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowUpRight, Database, Globe, RefreshCw, Search, UserCheck } from "lucide-react";
import Link from "next/link";
import { Suspense, useEffect, useRef, useState } from "react";

import { IntelVerdictBadge, StatusDot } from "@/components/ui/badges";
import { DataTable, Pagination, type Column } from "@/components/ui/data-table";
import { useToast } from "@/components/ui/overlays";
import { Button, EmptyState, ErrorState, Field, Input, KeyValue, PageHeader, Panel, Select, Skeleton, SkeletonRows, Textarea, cn } from "@/components/ui/primitives";
import { ApiError, api } from "@/lib/api";
import { formatDateTime, humanize, relativeTime, utcTitle } from "@/lib/format";
import { useCan, useUrlState } from "@/lib/hooks";
import type { Enrichment, Indicator, LocalSightings, Page } from "@/lib/types";

interface Provider {
  name: string;
  label: string;
  configured: boolean;
  supported_types: string[];
  terms_url: string;
}
interface IndicatorDetail {
  indicator: Indicator;
  enrichments: Enrichment[];
  history: { at: string; by: string | null; incident_id: string | null; used_cache: boolean }[];
  local: LocalSightings;
  linked_incidents: { id: string; number: number; title: string; status: string; severity: string }[];
}

const STATUS_TEXT: Record<string, string> = {
  ok: "Result returned",
  not_found: "Provider has no record",
  error: "Provider error",
  rate_limited: "Rate limited",
  unconfigured: "Not configured",
  unsupported: "Type not supported",
  not_looked_up: "Not looked up yet",
};

function ProviderCard({ e, providers }: { e: Enrichment; providers: Provider[] }) {
  const p = providers.find((x) => x.name === e.provider);
  const { report_url: reportUrl, ...rest } = e.summary ?? {};
  const summary = Object.entries(rest).filter(([, v]) => v !== null && v !== undefined && !(Array.isArray(v) && v.length === 0));
  // Only https links are rendered, so a provider cannot inject a javascript: URL.
  const reportHref = typeof reportUrl === "string" && reportUrl.startsWith("https://") ? reportUrl : null;
  return (
    <div className="rounded-lg border border-line bg-raised/30 p-3.5">
      <div className="flex items-start justify-between gap-2">
        <div>
          <p className="text-[13px] font-medium text-fg">{e.provider_label ?? p?.label ?? e.provider}</p>
          <p className="mt-0.5 inline-flex items-center gap-1.5 text-xs text-muted">
            <StatusDot className={e.status === "ok" ? "bg-ok" : e.status === "not_found" ? "bg-info" : e.status === "unconfigured" || e.status === "unsupported" ? "bg-subtle" : "bg-warn"} />
            {STATUS_TEXT[e.status] ?? e.status}
          </p>
        </div>
        <IntelVerdictBadge verdict={e.status === "ok" ? e.reported_verdict : "unknown"} />
      </div>
      {e.error && <p className="mt-2 text-xs text-warn">{e.error}</p>}
      {e.status === "unconfigured" && <p className="mt-2 text-xs text-subtle">Set the provider&apos;s API key in the backend environment to enable it.</p>}
      {e.status === "not_found" && <p className="mt-2 text-xs text-subtle">No record is not evidence that the indicator is safe.</p>}
      {summary.length > 0 && (
        <dl className="mt-3 grid grid-cols-2 gap-x-3 gap-y-1.5 text-xs">
          {summary.slice(0, 8).map(([k, v]) => (
            <div key={k} className="min-w-0">
              <dt className="text-subtle">{humanize(k)}</dt>
              <dd className="truncate text-fg" title={Array.isArray(v) ? v.join("; ") : String(v)}>
                {Array.isArray(v) ? v.join("; ") : String(v)}
              </dd>
            </div>
          ))}
        </dl>
      )}
      {reportHref && (
        <a href={reportHref} target="_blank" rel="noopener noreferrer" className="mt-3 inline-flex items-center gap-1 text-xs text-accent hover:underline">
          Open full report <ArrowUpRight className="size-3" aria-hidden />
        </a>
      )}
      {(e.fetched_at || p) && (
        <p className="mt-3 flex flex-wrap items-center gap-x-2 text-[11px] text-subtle">
          {e.fetched_at && (
            <span title={utcTitle(e.fetched_at)}>
              {e.cached ? "Cached result from" : "Looked up"} {formatDateTime(e.fetched_at)}
            </span>
          )}
          {e.confidence && <span>· confidence {e.confidence}</span>}
          {p && (
            <a href={p.terms_url} target="_blank" rel="noopener noreferrer" className="hover:text-fg hover:underline">
              · source terms
            </a>
          )}
        </p>
      )}
    </div>
  );
}

function VerdictForm({ indicator }: { indicator: Indicator }) {
  const qc = useQueryClient();
  const toast = useToast();
  const [verdict, setVerdict] = useState(indicator.analyst_verdict);
  const [note, setNote] = useState(indicator.analyst_note ?? "");
  const m = useMutation({
    mutationFn: () => api(`/iocs/${indicator.id}`, { method: "PATCH", body: { analyst_verdict: verdict, analyst_note: note } }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["ioc"] });
      qc.invalidateQueries({ queryKey: ["iocs"] });
      toast({ kind: "success", title: "Analyst conclusion recorded" });
    },
    onError: (e) => toast({ kind: "error", title: "Not saved", description: e instanceof ApiError ? e.detail : undefined }),
  });
  return (
    <form
      className="space-y-3"
      onSubmit={(e) => {
        e.preventDefault();
        m.mutate();
      }}
    >
      <Field label="Analyst verdict" htmlFor="av" hint="Your conclusion. Kept separate from what providers report. 'Malicious' adds the indicator to the detection watchlist.">
        <Select id="av" value={verdict} onChange={(e) => setVerdict(e.target.value as Indicator["analyst_verdict"])}>
          {["unknown", "benign", "suspicious", "malicious"].map((v) => (
            <option key={v} value={v}>
              {humanize(v)}
            </option>
          ))}
        </Select>
      </Field>
      <Field label="Basis for the conclusion" htmlFor="an">
        <Textarea id="an" value={note} onChange={(e) => setNote(e.target.value)} maxLength={4000} />
      </Field>
      <Button type="submit" size="sm" variant="primary" loading={m.isPending} disabled={note.trim().length < 3}>
        Save conclusion
      </Button>
    </form>
  );
}

function IndicatorView({ id, providers }: { id: string; providers: Provider[] }) {
  const canEdit = useCan("analyst");
  const q = useQuery({ queryKey: ["ioc", id], queryFn: () => api<IndicatorDetail>(`/iocs/${id}`) });
  if (q.isError) return <Panel><ErrorState error={q.error} onRetry={() => q.refetch()} /></Panel>;
  if (!q.data) return <Skeleton className="h-80" />;
  const { indicator, enrichments, local, linked_incidents, history } = q.data;
  const latest = new Map<string, Enrichment>();
  for (const e of enrichments) if (!latest.has(e.provider)) latest.set(e.provider, e);
  const providerResults: Enrichment[] = providers.map((p) => latest.get(p.name) ?? { provider: p.name, provider_label: p.label, status: !p.supported_types.includes(indicator.ioc_type) ? "unsupported" : p.configured ? "not_looked_up" : "unconfigured", reported_verdict: "unknown" });
  return (
    <div className="space-y-4">
      <Panel
        title={<span className="mono break-all">{indicator.value}</span>}
        description={`${indicator.ioc_type.toUpperCase()} · first seen ${formatDateTime(indicator.first_seen)} · ${indicator.lookup_count} lookup(s)`}
        id="ioc-head"
        actions={<IntelVerdictBadge verdict={indicator.analyst_verdict} />}
      >
        <div className="grid gap-4 lg:grid-cols-3">
          <section aria-labelledby="prov-h" className="lg:col-span-2">
            <h3 id="prov-h" className="mb-2 flex items-center gap-1.5 text-xs font-medium tracking-wide text-subtle uppercase">
              <Globe className="size-3.5" aria-hidden /> Provider-reported findings
            </h3>
            <div className="grid gap-2 sm:grid-cols-2 xl:grid-cols-3">
              {providerResults.map((e) => (
                <ProviderCard key={e.provider} e={e} providers={providers} />
              ))}
            </div>
          </section>
          <section aria-labelledby="ana-h">
            <h3 id="ana-h" className="mb-2 flex items-center gap-1.5 text-xs font-medium tracking-wide text-subtle uppercase">
              <UserCheck className="size-3.5" aria-hidden /> Analyst conclusion
            </h3>
            {canEdit ? <VerdictForm key={indicator.id} indicator={indicator} /> : <p className="text-[13px] text-fg">{indicator.analyst_note ?? "No conclusion recorded."}</p>}
          </section>
        </div>
      </Panel>
      <div className="grid gap-4 lg:grid-cols-2">
        <Panel title={<span className="flex items-center gap-1.5"><Database className="size-3.5" aria-hidden /> Locally observed evidence</span>} description="Matches in this organisation's own telemetry" id="local">
          {local.event_count === 0 ? (
            <p className="text-xs text-muted">Not seen in stored telemetry. Absence here does not mean the indicator is safe.</p>
          ) : (
            <div className="space-y-3">
              <KeyValue
                columns={3}
                items={[
                  { label: "Matching events", value: String(local.event_count) },
                  { label: "First seen", value: formatDateTime(local.first_seen) },
                  { label: "Last seen", value: formatDateTime(local.last_seen) },
                ]}
              />
              <div className="flex flex-wrap gap-1.5">
                {local.hosts.map((h) => (
                  <Link key={h.host} href={`/events?host=${encodeURIComponent(h.host)}`} className="mono rounded bg-raised px-1.5 py-0.5 text-xs text-fg ring-1 ring-line hover:ring-accent">
                    {h.host} · {h.count}
                  </Link>
                ))}
              </div>
              <ul className="space-y-1 text-xs">
                {local.sample_events.map((e) => (
                  <li key={e.id}>
                    <Link href={`/events/${e.id}`} className="mono text-muted hover:text-fg hover:underline">
                      {formatDateTime(e.event_time)} · {e.event_type} · {e.host ?? "—"}
                    </Link>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </Panel>
        <Panel title="Related incidents" description="Linked during investigation, or containing matching evidence" id="rel">
          {linked_incidents.length + local.incidents_with_matching_evidence.length === 0 ? (
            <p className="text-xs text-muted">No related incidents.</p>
          ) : (
            <ul className="space-y-1.5 text-[13px]">
              {[...linked_incidents, ...local.incidents_with_matching_evidence.filter((i) => !linked_incidents.some((l) => l.id === i.id))].map((i) => (
                <li key={i.id}>
                  <Link href={`/incidents/${i.id}`} className="hover:underline">
                    <span className="mono text-muted">INC-{String(i.number).padStart(4, "0")}</span> <span className="text-fg">{i.title}</span>
                  </Link>
                  <span className="ml-2 text-xs text-subtle capitalize">{i.status}</span>
                </li>
              ))}
            </ul>
          )}
          {history.length > 0 && (
            <>
              <h3 className="mt-4 mb-1.5 text-xs font-medium tracking-wide text-subtle uppercase">Lookup history</h3>
              <ul className="space-y-1 text-xs text-muted">
                {history.slice(0, 8).map((h, i) => (
                  <li key={i}>
                    <span title={utcTitle(h.at)}>{formatDateTime(h.at)}</span> · {h.by ?? "system"} {h.used_cache && "· served from cache"}
                  </li>
                ))}
              </ul>
            </>
          )}
        </Panel>
      </div>
    </div>
  );
}

function ThreatIntel() {
  const url = useUrlState();
  const qc = useQueryClient();
  const toast = useToast();
  const canLookup = useCan("analyst");
  const selected = url.get("id");
  const page = Number(url.get("page", "1")) || 1;
  const [value, setValue] = useState("");
  const [preview, setPreview] = useState<{ type: string; value: string } | null>(null);
  const providers = useQuery({ queryKey: ["providers"], queryFn: () => api<Provider[]>("/iocs/providers"), staleTime: 10 * 60_000 });
  const list = useQuery({ queryKey: ["iocs", page], queryFn: () => api<Page<Indicator>>("/iocs", { query: { page, page_size: 15 } }), placeholderData: (p) => p });
  const lookup = useMutation({
    mutationFn: (force: boolean) => api<{ indicator: Indicator }>("/iocs/lookup", { method: "POST", body: { value, force_refresh: force } }),
    onSuccess: (r) => {
      qc.invalidateQueries({ queryKey: ["iocs"] });
      qc.invalidateQueries({ queryKey: ["ioc", r.indicator.id] });
      url.set({ id: r.indicator.id });
    },
    onError: (e) => toast({ kind: "error", title: "Lookup failed", description: e instanceof ApiError ? e.detail : undefined }),
  });

  // Debounced so typing does not send a request per keystroke; stale responses are dropped.
  const normaliseTimer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  const normaliseSeq = useRef(0);
  useEffect(() => () => clearTimeout(normaliseTimer.current), []);

  function normalise(v: string) {
    setValue(v);
    clearTimeout(normaliseTimer.current);
    const seq = ++normaliseSeq.current;
    if (!v.trim()) return setPreview(null);
    normaliseTimer.current = setTimeout(async () => {
      try {
        const result = await api<{ type: string; value: string }>("/iocs/normalise", { method: "POST", body: { value: v } });
        if (seq === normaliseSeq.current) setPreview(result);
      } catch {
        if (seq === normaliseSeq.current) setPreview(null);
      }
    }, 300);
  }

  const columns: Column<Indicator>[] = [
    { key: "value", header: "Indicator", render: (i) => <button type="button" onClick={() => url.set({ id: i.id }, { resetPage: false })} className={cn("mono max-w-xs truncate text-left text-xs hover:underline", i.id === selected ? "text-accent" : "text-fg")}>{i.value}</button> },
    { key: "type", header: "Type", render: (i) => <span className="text-xs text-muted uppercase">{i.ioc_type}</span> },
    { key: "verdict", header: "Analyst verdict", render: (i) => <IntelVerdictBadge verdict={i.analyst_verdict} /> },
    { key: "last", header: "Last lookup", hideBelow: "md", render: (i) => <span className="text-xs text-subtle" title={utcTitle(i.last_looked_up)}>{relativeTime(i.last_looked_up)}</span> },
  ];

  return (
    <>
      <PageHeader
        title="Threat intelligence"
        description="Investigate IPs, domains, URLs and file hashes. Provider findings, locally observed evidence and analyst conclusions are shown separately."
        meta={providers.data?.map((p) => (
          <span key={p.name} className="inline-flex items-center gap-1.5 rounded border border-line px-1.5 py-px text-[11px] text-muted">
            <StatusDot className={p.configured ? "bg-ok" : "bg-subtle"} /> {p.label}: {p.configured ? "configured" : "not configured"}
          </span>
        ))}
      />
      <div className="space-y-4">
        {canLookup && (
          <Panel id="lookup">
            <form
              className="flex flex-col gap-2 sm:flex-row"
              onSubmit={(e) => {
                e.preventDefault();
                if (value.trim()) lookup.mutate(false);
              }}
            >
              <label htmlFor="ioc-value" className="sr-only">Indicator value</label>
              <Input id="ioc-value" className="mono h-9" value={value} onChange={(e) => normalise(e.target.value)} placeholder="e.g. 203.0.113.45, invoice-portal[.]example, hxxps://…, sha256" maxLength={2048} />
              <Button type="submit" variant="primary" className="h-9" icon={<Search className="size-3.5" aria-hidden />} loading={lookup.isPending && !lookup.variables} disabled={!value.trim()}>
                Investigate
              </Button>
              <Button className="h-9" icon={<RefreshCw className="size-3.5" aria-hidden />} loading={lookup.isPending && lookup.variables === true} disabled={!value.trim()} onClick={() => lookup.mutate(true)} title="Bypass the cache">
                Refresh
              </Button>
            </form>
            <p className="mt-2 text-xs text-subtle" aria-live="polite">
              {preview ? (
                <>
                  Normalised as <span className="text-muted uppercase">{preview.type}</span> <span className="mono text-fg">{preview.value}</span>
                </>
              ) : value.trim() ? (
                "Not a recognised IP, domain, URL or hash yet."
              ) : (
                "Defanged input such as hxxp:// and [.] is accepted. Results are cached for 24 hours per provider."
              )}
            </p>
          </Panel>
        )}
        <div className="grid grid-cols-1 gap-4 xl:grid-cols-[minmax(0,1fr)_380px]">
          <div className="min-w-0">
            {selected && providers.data ? (
              <IndicatorView id={selected} providers={providers.data} />
            ) : (
              <Panel>
                <EmptyState icon={<Search className="size-5" aria-hidden />} title="Select or investigate an indicator" description="Results show which provider said what and when, what your own telemetry has seen, and your team's conclusion." />
              </Panel>
            )}
          </div>
          <Panel title="Investigation history" description="Indicators looked up in this organisation" bodyClassName="p-0" id="history" actions={selected ? <Button size="sm" variant="ghost" onClick={() => url.set({ id: null })}>Clear</Button> : undefined}>
            {list.isError ? (
              <ErrorState error={list.error} onRetry={() => list.refetch()} />
            ) : !list.data ? (
              <SkeletonRows rows={5} cols={3} />
            ) : list.data.items.length === 0 ? (
              <EmptyState title="No lookups yet" />
            ) : (
              <>
                <DataTable caption="Indicators" columns={columns} rows={list.data.items} rowKey={(i) => i.id} />
                <Pagination page={page} pageSize={15} total={list.data.total} onPage={(p) => url.set({ page: p }, { resetPage: false })} />
              </>
            )}
          </Panel>
        </div>
        <p className="flex items-center gap-1 text-[11px] text-subtle">
          Provider data is subject to each provider&apos;s terms and quotas. <Link href="/settings" className="inline-flex items-center gap-0.5 hover:text-fg">Integration status <ArrowUpRight className="size-3" aria-hidden /></Link>
        </p>
      </div>
    </>
  );
}

export default function ThreatIntelPage() {
  return (
    <Suspense>
      <ThreatIntel />
    </Suspense>
  );
}
