"use client";

import { useQuery } from "@tanstack/react-query";
import { Download, FileJson, Printer } from "lucide-react";
import { useParams } from "next/navigation";
import { useState, type ReactNode } from "react";

import { IntelVerdictBadge, SeverityBadge, SyntheticBadge, VerdictBadge } from "@/components/ui/badges";
import { useToast } from "@/components/ui/overlays";
import { Button, EmptyState, ErrorState, PageHeader, Panel, Skeleton } from "@/components/ui/primitives";
import { ApiError, api } from "@/lib/api";
import { formatDateTime, humanize } from "@/lib/format";
import type { Severity, Verdict } from "@/lib/types";

interface Report {
  report_version: number;
  generated_at: string;
  incident: { reference: string; title: string; summary: string; severity: Severity; status: string; verdict: Verdict | null; closure_reason: string | null; tags: string[]; assignee: string | null; created_at: string; acknowledged_at: string | null; contained_at: string | null; resolved_at: string | null; closed_at: string | null; is_synthetic: boolean };
  timeline: { at: string; kind: string; title: string; detail?: string | null; actor?: string | null }[];
  affected_assets: { hostname: string; type: string; criticality: string; os: string | null }[];
  affected_accounts: string[];
  alerts: { id: string; rule_id: string; title: string; severity: Severity; confidence: string; first_seen: string; disposition: string | null }[];
  evidence: { id: string; type: string; title: string; sha256: string; provenance: Record<string, unknown>; created_at: string }[];
  ioc_findings: { type: string; value: string; analyst_verdict: string; analyst_note: string | null; provider_findings: { provider: string; status: string; reported_verdict: string; fetched_at: string }[] }[];
  detection_rules: { id: string; name: string; description: string; false_positives: string[] }[];
  attack_mapping: { technique: string; name: string; tactic: string | null; via_rules: string[] }[];
  analyst_assessment: { type: string; author: string | null; at: string; text: string }[];
  containment_recommendations: { recommendations: { rule_id: string; rule_name: string; steps: string[] }[] } | null;
  limitations: string[];
}

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="border-t border-line py-5 first:border-t-0 first:pt-0">
      <h2 className="mb-3 text-sm font-semibold text-fg">{title}</h2>
      {children}
    </section>
  );
}

function download(name: string, content: string, type: string) {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  URL.revokeObjectURL(url);
}

export default function ReportPage() {
  const { id } = useParams<{ id: string }>();
  const toast = useToast();
  const [busy, setBusy] = useState(false);
  const q = useQuery({ queryKey: ["report", id], queryFn: () => api<Report>(`/incidents/${id}/report`) });

  async function exportMarkdown(ref: string) {
    setBusy(true);
    try {
      download(`${ref}-report.md`, await api<string>(`/incidents/${id}/report`, { query: { format: "markdown" }, raw: true }), "text/markdown");
    } catch (e) {
      toast({ kind: "error", title: "Export failed", description: e instanceof ApiError ? e.detail : undefined });
    } finally {
      setBusy(false);
    }
  }

  if (q.isError) {
    const notFound = q.error instanceof ApiError && q.error.status === 404;
    return (
      <>
        <PageHeader title="Report" breadcrumbs={[{ label: "Reports", href: "/reports" }, { label: "Unavailable" }]} />
        <Panel>{notFound ? <EmptyState title="This incident does not exist or you do not have access to it." /> : <ErrorState error={q.error} onRetry={() => q.refetch()} />}</Panel>
      </>
    );
  }
  if (!q.data) return <Skeleton className="h-[600px]" />;
  const r = q.data;
  const inc = r.incident;

  return (
    <>
      <div className="no-print">
        <PageHeader
          breadcrumbs={[{ label: "Reports", href: "/reports" }, { label: inc.reference }]}
          title={`Incident report: ${inc.reference}`}
          description="Assembled from stored records at the time shown. Analyst text is quoted verbatim; computed sections are labelled."
          actions={
            <>
              <Button icon={<Download className="size-3.5" aria-hidden />} loading={busy} onClick={() => exportMarkdown(inc.reference)}>Markdown</Button>
              <Button icon={<FileJson className="size-3.5" aria-hidden />} onClick={() => download(`${inc.reference}-report.json`, JSON.stringify(r, null, 2), "application/json")}>JSON</Button>
              <Button variant="primary" icon={<Printer className="size-3.5" aria-hidden />} onClick={() => window.print()}>Print / PDF</Button>
            </>
          }
        />
      </div>
      <article className="print-doc mx-auto max-w-4xl rounded-lg border border-line bg-surface px-6 py-6 md:px-10 md:py-8">
        <header className="mb-6">
          <p className="mono text-xs text-muted">{inc.reference} · report v{r.report_version} · generated {formatDateTime(r.generated_at)}</p>
          <h1 className="mt-1 text-xl font-semibold tracking-tight text-fg">{inc.title}</h1>
          <div className="mt-2 flex flex-wrap items-center gap-2">
            <SeverityBadge severity={inc.severity} />
            <span className="text-xs text-muted capitalize">Status: {inc.status}</span>
            <VerdictBadge verdict={inc.verdict} />
            {inc.is_synthetic && <SyntheticBadge />}
          </div>
        </header>

        <Section title="Summary">
          <p className="text-[13px] whitespace-pre-wrap text-fg">{inc.summary || "No summary recorded."}</p>
          <dl className="mt-3 grid grid-cols-2 gap-x-6 gap-y-1 text-xs sm:grid-cols-3">
            {(["created_at", "acknowledged_at", "contained_at", "resolved_at", "closed_at"] as const).map((k) => (
              <div key={k}>
                <dt className="text-subtle">{humanize(k.replace("_at", ""))}</dt>
                <dd className="text-fg">{inc[k] ? formatDateTime(inc[k]) : "—"}</dd>
              </div>
            ))}
            <div>
              <dt className="text-subtle">Assignee</dt>
              <dd className="text-fg">{inc.assignee ?? "—"}</dd>
            </div>
          </dl>
        </Section>

        <Section title="Timeline">
          <ol className="space-y-1 text-xs">
            {r.timeline.map((t, i) => (
              <li key={i} className="grid grid-cols-[9.5rem_5rem_1fr] gap-2">
                <span className="mono text-muted">{formatDateTime(t.at)}</span>
                <span className="text-subtle capitalize">{t.kind}</span>
                <span className="text-fg">
                  {t.title}
                  {t.detail && <span className="mono block text-muted">{t.detail}</span>}
                </span>
              </li>
            ))}
          </ol>
        </Section>

        <Section title="Affected assets and accounts">
          {r.affected_assets.length + r.affected_accounts.length === 0 ? (
            <p className="text-xs text-muted">None identified from linked evidence.</p>
          ) : (
            <div className="flex flex-wrap gap-1.5 text-xs">
              {r.affected_assets.map((a) => <span key={a.hostname} className="mono rounded border border-line px-1.5 py-0.5 text-fg">host {a.hostname} ({a.criticality})</span>)}
              {r.affected_accounts.map((a) => <span key={a} className="mono rounded border border-line px-1.5 py-0.5 text-fg">account {a}</span>)}
            </div>
          )}
        </Section>

        <Section title="Supporting evidence">
          <ul className="space-y-1.5 text-xs">
            {r.evidence.map((e) => (
              <li key={e.id}>
                <span className="text-fg">{e.title}</span> <span className="text-subtle">· {humanize(e.type)} · {String(e.provenance.method ?? "")}</span>
                <span className="mono block text-subtle">sha256 {e.sha256}</span>
              </li>
            ))}
          </ul>
          <p className="mt-2 text-xs text-muted">{r.alerts.length} alert(s) and {r.timeline.filter((t) => t.kind === "event").length} event(s) are linked as evidence.</p>
        </Section>

        <Section title="IOC findings">
          {r.ioc_findings.length === 0 ? (
            <p className="text-xs text-muted">No indicators linked.</p>
          ) : (
            <ul className="space-y-2 text-xs">
              {r.ioc_findings.map((f) => (
                <li key={f.value}>
                  <span className="mono text-fg">{f.value}</span> <span className="text-subtle uppercase">{f.type}</span> · analyst: <IntelVerdictBadge verdict={f.analyst_verdict} />
                  {f.provider_findings.length ? (
                    <ul className="mt-1 ml-4 list-disc text-muted">
                      {f.provider_findings.map((p) => <li key={p.provider}>{p.provider}: {p.status}, reported {p.reported_verdict} ({formatDateTime(p.fetched_at)})</li>)}
                    </ul>
                  ) : (
                    <p className="mt-1 ml-4 text-muted">No provider data. This does not indicate the indicator is safe.</p>
                  )}
                </li>
              ))}
            </ul>
          )}
        </Section>

        <Section title="Detection rules and ATT&CK mapping">
          <ul className="space-y-1.5 text-xs">
            {r.detection_rules.map((d) => (
              <li key={d.id}>
                <span className="mono text-fg">{d.id}</span> <span className="text-fg">{d.name}</span>
                <span className="block text-muted">{d.description}</span>
              </li>
            ))}
          </ul>
          <ul className="mt-3 flex flex-wrap gap-1.5 text-xs">
            {r.attack_mapping.map((t) => <li key={t.technique} className="rounded border border-line px-1.5 py-0.5 text-muted"><span className="mono text-fg">{t.technique}</span> {t.name}</li>)}
          </ul>
          <p className="mt-2 text-xs text-subtle">Mappings reflect each rule&apos;s design intent and are not proof of the technique.</p>
        </Section>

        <Section title="Analyst assessment">
          {r.analyst_assessment.length === 0 ? (
            <p className="text-xs text-muted">No analyst notes recorded.</p>
          ) : (
            <div className="space-y-3">
              {r.analyst_assessment.map((n, i) => (
                <blockquote key={i} className="border-l-2 border-accent/50 pl-3">
                  <p className="text-[13px] whitespace-pre-wrap text-fg">{n.text}</p>
                  <footer className="mt-1 text-xs text-subtle">{n.author ?? "Unknown"} · {n.type} · {formatDateTime(n.at)}</footer>
                </blockquote>
              ))}
            </div>
          )}
        </Section>

        <Section title="Containment and recovery recommendations">
          {r.containment_recommendations?.recommendations?.length ? (
            <ul className="space-y-2 text-xs">
              {r.containment_recommendations.recommendations.map((c) => (
                <li key={c.rule_id}>
                  <span className="text-fg">{c.rule_name}</span>
                  <ul className="mt-0.5 ml-4 list-disc text-muted">{c.steps.map((s) => <li key={s}>{s}</li>)}</ul>
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-xs text-muted">The containment recommendations playbook has not been run for this incident.</p>
          )}
        </Section>

        <Section title="Closure">
          <p className="text-xs text-muted">Verdict: <VerdictBadge verdict={inc.verdict} /></p>
          <p className="mt-2 text-[13px] whitespace-pre-wrap text-fg">{inc.closure_reason ?? "The incident is not closed."}</p>
        </Section>

        <Section title="Limitations">
          <ul className="list-disc space-y-1 pl-4 text-xs text-muted">{r.limitations.map((l) => <li key={l}>{l}</li>)}</ul>
        </Section>
      </article>
    </>
  );
}
