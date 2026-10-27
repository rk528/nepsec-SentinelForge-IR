"use client";

import { useQuery } from "@tanstack/react-query";
import { Info } from "lucide-react";
import Link from "next/link";

import { StatusDot } from "@/components/ui/badges";
import { ErrorState, PageHeader, Panel, Skeleton, cn } from "@/components/ui/primitives";
import { api } from "@/lib/api";
import { formatDateTime, relativeTime } from "@/lib/format";

interface TechniqueRow {
  technique: string;
  name: string;
  tactic: string;
  rules: string[];
  coverage: "tested" | "untested" | "disabled" | "gap";
  gap_reason: string | null;
  alert_count: number;
  last_observed: string | null;
  sample_alert_ids: string[];
  last_tested: string | null;
  test_passed: boolean | null;
}
interface Coverage {
  tactics: string[];
  techniques: TechniqueRow[];
  disclaimer: string;
}

const COVERAGE = {
  tested: { label: "Rule tested", dot: "bg-ok", cell: "border-ok/30 bg-ok/[0.06]" },
  untested: { label: "Rule, not yet tested", dot: "bg-warn", cell: "border-warn/30 bg-warn/[0.06]" },
  disabled: { label: "Rule disabled", dot: "bg-subtle", cell: "border-line-strong" },
  gap: { label: "Gap: no rule", dot: "bg-danger", cell: "border-dashed border-danger/35" },
};

export default function AttackCoveragePage() {
  const q = useQuery({ queryKey: ["attack"], queryFn: () => api<Coverage>("/attack/coverage") });
  const d = q.data;
  const counts = d ? Object.fromEntries(Object.keys(COVERAGE).map((k) => [k, d.techniques.filter((t) => t.coverage === k).length])) : {};

  return (
    <>
      <PageHeader
        title="MITRE ATT&CK coverage"
        description="A curated subset of Enterprise techniques relevant to the telemetry this platform ingests, including known gaps."
        meta={d && Object.entries(COVERAGE).map(([k, v]) => (
          <span key={k} className="inline-flex items-center gap-1.5 text-xs text-muted">
            <StatusDot className={v.dot} /> {v.label} <span className="text-fg tabular-nums">{counts[k]}</span>
          </span>
        ))}
      />
      {d && (
        <div className="mb-4 flex gap-2.5 rounded-lg border border-info/25 bg-info/[0.06] px-4 py-3 text-xs text-muted">
          <Info className="mt-0.5 size-4 shrink-0 text-info" aria-hidden />
          <p>{d.disclaimer} “Tested” means the rule passed its labelled fixtures, which is not the same as reliable detection in your environment.</p>
        </div>
      )}
      {q.isError ? (
        <Panel><ErrorState error={q.error} onRetry={() => q.refetch()} /></Panel>
      ) : !d ? (
        <Skeleton className="h-96 rounded-lg" />
      ) : (
        <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-3">
          {d.tactics
            .filter((tac) => d.techniques.some((t) => t.tactic === tac))
            .map((tac) => (
              <Panel key={tac} title={tac} bodyClassName="space-y-2 p-3" id={tac.replace(/\W+/g, "-")}>
                {d.techniques
                  .filter((t) => t.tactic === tac)
                  .map((t) => {
                    const c = COVERAGE[t.coverage];
                    return (
                      <div key={t.technique} className={cn("rounded-md border p-2.5", c.cell)}>
                        <div className="flex items-start justify-between gap-2">
                          <a href={`https://attack.mitre.org/techniques/${t.technique.replace(".", "/")}/`} target="_blank" rel="noopener noreferrer" className="text-sm text-fg hover:underline">
                            <span className="mono text-xs text-muted">{t.technique}</span> {t.name}
                          </a>
                          <span className="inline-flex shrink-0 items-center gap-1 text-xs text-muted">
                            <StatusDot className={c.dot} />
                            <span className="sr-only">{c.label}</span>
                          </span>
                        </div>
                        {t.coverage === "gap" ? (
                          <p className="mt-1 text-xs text-subtle">{t.gap_reason ?? "No rule maps to this technique."}</p>
                        ) : (
                          <div className="mt-1.5 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-muted">
                            <span>
                              {t.rules.map((r, i) => (
                                <span key={r}>
                                  {i > 0 && ", "}
                                  <Link href={`/detections#${r}`} className="mono hover:text-fg hover:underline">{r}</Link>
                                </span>
                              ))}
                            </span>
                            {t.alert_count > 0 ? (
                              <Link href={`/alerts?rule_id=${t.rules[0]}`} className="hover:text-fg hover:underline" title={t.last_observed ? `Last observed ${formatDateTime(t.last_observed)}` : undefined}>
                                {t.alert_count} alert{t.alert_count === 1 ? "" : "s"} · last {relativeTime(t.last_observed)}
                              </Link>
                            ) : (
                              <span className="text-subtle">Not observed</span>
                            )}
                            <span className="text-subtle">{t.last_tested ? `Tested ${relativeTime(t.last_tested)} (${t.test_passed ? "pass" : "fail"})` : "Never tested"}</span>
                          </div>
                        )}
                      </div>
                    );
                  })}
              </Panel>
            ))}
        </div>
      )}
    </>
  );
}
