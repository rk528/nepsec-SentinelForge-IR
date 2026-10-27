"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ChevronDown, FlaskConical, Play } from "lucide-react";
import Link from "next/link";
import { useState } from "react";

import { ConfidenceMeter, SeverityBadge, StatusDot } from "@/components/ui/badges";
import { useToast } from "@/components/ui/overlays";
import { Button, EmptyState, ErrorState, PageHeader, Panel, Skeleton, cn } from "@/components/ui/primitives";
import { ApiError, api } from "@/lib/api";
import { formatDateTime, relativeTime } from "@/lib/format";
import { useCan } from "@/lib/hooks";
import type { RuleRow } from "@/lib/types";

function pct(v: number | null) {
  return v === null ? "n/a" : `${Math.round(v * 100)}%`;
}

function RuleCard({ rule }: { rule: RuleRow }) {
  const [open, setOpen] = useState(false);
  const t = rule.latest_test;
  return (
    <li id={rule.id} className="scroll-mt-20 rounded-lg border border-line bg-surface">
      <button type="button" onClick={() => setOpen((o) => !o)} aria-expanded={open} className="flex w-full flex-col gap-2 px-4 py-3 text-left hover:bg-raised/40 md:flex-row md:items-center md:gap-4">
        <span className="mono w-28 shrink-0 text-xs text-muted">{rule.id}</span>
        <span className="min-w-0 flex-1">
          <span className="block text-[13px] font-medium text-fg">{rule.name}</span>
          <span className="block truncate text-xs text-subtle">{rule.description}</span>
        </span>
        <span className="flex flex-wrap items-center gap-3">
          <SeverityBadge severity={rule.severity} />
          <ConfidenceMeter confidence={rule.confidence} />
          <span className="inline-flex items-center gap-1.5 text-xs text-muted">
            <StatusDot className={!t ? "bg-subtle" : t.passed ? "bg-ok" : "bg-danger"} />
            {!t ? "Untested" : t.passed ? "Tests pass" : "Tests fail"}
          </span>
          <span className="text-xs text-muted tabular-nums">{rule.alert_count} alerts</span>
          <ChevronDown className={cn("size-4 text-subtle transition-transform", open && "rotate-180")} aria-hidden />
        </span>
      </button>
      {open && (
        <div className="grid gap-5 border-t border-line px-4 py-4 lg:grid-cols-2">
          <div className="space-y-3 text-[13px]">
            <div>
              <p className="text-[11px] font-medium tracking-wide text-subtle uppercase">Rationale</p>
              <p className="mt-0.5 text-fg">{rule.rationale}</p>
            </div>
            <div>
              <p className="text-[11px] font-medium tracking-wide text-subtle uppercase">Required telemetry</p>
              <ul className="mt-0.5 list-disc pl-4 text-xs text-muted">{rule.required_telemetry.map((x) => <li key={x} className="mono">{x}</li>)}</ul>
            </div>
            <div>
              <p className="text-[11px] font-medium tracking-wide text-subtle uppercase">False-positive considerations</p>
              <ul className="mt-0.5 list-disc pl-4 text-xs text-muted">{rule.false_positives.map((x) => <li key={x}>{x}</li>)}</ul>
            </div>
            <div>
              <p className="text-[11px] font-medium tracking-wide text-subtle uppercase">ATT&amp;CK techniques (design intent)</p>
              <ul className="mt-1 flex flex-wrap gap-1.5">
                {rule.techniques.map((x) => (
                  <li key={x.id} className="rounded bg-raised px-1.5 py-0.5 text-xs text-muted ring-1 ring-line" title={x.tactic ?? undefined}>
                    <span className="mono text-fg">{x.id}</span> {x.name}
                  </li>
                ))}
              </ul>
            </div>
            <p className="text-xs text-subtle">
              Last alert {relativeTime(rule.last_alert_at)} ·{" "}
              <Link href={`/alerts?rule_id=${rule.id}`} className="text-accent hover:underline">
                View alerts
              </Link>
            </p>
          </div>
          <div>
            <p className="text-[11px] font-medium tracking-wide text-subtle uppercase">Labelled fixture evaluation</p>
            {!t ? (
              <p className="mt-1 text-xs text-muted">{rule.fixture_count} labelled cases available. Run the self-test to record results.</p>
            ) : (
              <>
                <div className="mt-2 grid grid-cols-4 gap-2 text-center">
                  {(
                    [
                      ["TP", t.true_positives],
                      ["FP", t.false_positives],
                      ["TN", t.true_negatives],
                      ["FN", t.false_negatives],
                    ] as const
                  ).map(([k, v]) => (
                    <div key={k} className="rounded-md border border-line bg-raised/40 py-1.5">
                      <p className="text-[11px] text-subtle">{k}</p>
                      <p className="text-sm font-semibold text-fg tabular-nums">{v}</p>
                    </div>
                  ))}
                </div>
                <p className="mt-2 text-xs text-muted">
                  Precision {pct(t.precision)} · Recall {pct(t.recall)} · {t.latency_ms.toFixed(2)} ms to evaluate · run {formatDateTime(t.run_at)}
                </p>
                <ul className="mt-3 space-y-1 text-xs">
                  {t.cases.map((c) => (
                    <li key={c.name} className="flex items-start gap-2">
                      <span className={cn("mono w-7 shrink-0 font-semibold", c.outcome === "TP" || c.outcome === "TN" ? "text-ok" : c.known_limitation ? "text-warn" : "text-danger")}>{c.outcome}</span>
                      <span className="text-muted">
                        {c.name} <span className="text-subtle">({c.label})</span>
                        {c.known_limitation && <span className="block text-warn">Known limitation: {c.known_limitation}</span>}
                      </span>
                    </li>
                  ))}
                </ul>
              </>
            )}
          </div>
        </div>
      )}
    </li>
  );
}

export default function DetectionsPage() {
  const canRun = useCan("analyst");
  const qc = useQueryClient();
  const toast = useToast();
  const rules = useQuery({ queryKey: ["rules"], queryFn: () => api<RuleRow[]>("/detections") });
  const selfTest = useMutation({
    mutationFn: () => api<{ rule_id: string; passed: boolean }[]>("/detections/self-test", { method: "POST" }),
    onSuccess: (r) => {
      qc.invalidateQueries({ queryKey: ["rules"] });
      qc.invalidateQueries({ queryKey: ["attack"] });
      const failed = r.filter((x) => !x.passed).length;
      toast({ kind: failed ? "error" : "success", title: failed ? `${failed} rule(s) failed` : "All rules passed their labelled cases" });
    },
    onError: (e) => toast({ kind: "error", title: "Self-test failed to run", description: e instanceof ApiError ? e.detail : undefined }),
  });
  const runDetection = useMutation({
    mutationFn: () => api<{ events_evaluated: number; alerts_created: number; alerts_updated: number; duration_ms: number }>("/detections/run", { method: "POST", body: { hours: 24 } }),
    onSuccess: (r) => {
      qc.invalidateQueries({ queryKey: ["alerts"] });
      qc.invalidateQueries({ queryKey: ["rules"] });
      toast({ kind: "success", title: `Evaluated ${r.events_evaluated} events`, description: `${r.alerts_created} new alerts, ${r.alerts_updated} existing alerts updated (${r.duration_ms} ms).` });
    },
    onError: (e) => toast({ kind: "error", title: "Detection run failed", description: e instanceof ApiError ? e.detail : undefined }),
  });

  return (
    <>
      <PageHeader
        title="Detection engineering"
        description="Rules run against normalised events and produce deduplicated alerts. Each rule ships with labelled benign and malicious fixtures; known misses are reported, not hidden."
        actions={
          canRun && (
            <>
              <Button icon={<Play className="size-3.5" aria-hidden />} loading={runDetection.isPending} onClick={() => runDetection.mutate()}>
                Run on last 24h
              </Button>
              <Button variant="primary" icon={<FlaskConical className="size-3.5" aria-hidden />} loading={selfTest.isPending} onClick={() => selfTest.mutate()}>
                Run self-test
              </Button>
            </>
          )
        }
      />
      {rules.isError ? (
        <Panel><ErrorState error={rules.error} onRetry={() => rules.refetch()} /></Panel>
      ) : !rules.data ? (
        <div className="space-y-2">{Array.from({ length: 6 }).map((_, i) => <Skeleton key={i} className="h-16 rounded-lg" />)}</div>
      ) : rules.data.length === 0 ? (
        <Panel><EmptyState title="No rules defined" /></Panel>
      ) : (
        <ul className="space-y-2">{rules.data.map((r) => <RuleCard key={r.id} rule={r} />)}</ul>
      )}
      <p className="mt-4 text-xs text-subtle">
        Rules are written in Python against a normalised schema rather than executed as Sigma. Sigma rules would need a conversion layer; that is not implemented. Precision and recall here describe small curated fixtures, not production performance.
      </p>
    </>
  );
}
