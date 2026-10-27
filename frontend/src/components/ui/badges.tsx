import { clsx as cn } from "clsx";
import { FlaskConical } from "lucide-react";
import type { ReactNode } from "react";

import type { AlertStatus, Confidence, IncidentStatus, Severity, Verdict } from "@/lib/types";

const SEVERITY: Record<Severity, { label: string; cls: string; dot: string }> = {
  critical: { label: "Critical", cls: "text-sev-critical border-sev-critical/35 bg-sev-critical/10", dot: "bg-sev-critical" },
  high: { label: "High", cls: "text-sev-high border-sev-high/35 bg-sev-high/10", dot: "bg-sev-high" },
  medium: { label: "Medium", cls: "text-sev-medium border-sev-medium/35 bg-sev-medium/10", dot: "bg-sev-medium" },
  low: { label: "Low", cls: "text-sev-low border-sev-low/35 bg-sev-low/10", dot: "bg-sev-low" },
  informational: { label: "Info", cls: "text-sev-info border-sev-info/35 bg-sev-info/10", dot: "bg-sev-info" },
};

export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "informational"];
export const SEVERITY_COLOR: Record<Severity, string> = {
  critical: "#f0506e",
  high: "#f59e42",
  medium: "#e7c04a",
  low: "#5aa9e6",
  informational: "#8a93a6",
};

/** Severity: how bad it would be if real. Shown with a bar glyph whose height also encodes rank. */
export function SeverityBadge({ severity, compact }: { severity: Severity; compact?: boolean }) {
  const s = SEVERITY[severity] ?? SEVERITY.informational;
  const rank = SEVERITY_ORDER.length - SEVERITY_ORDER.indexOf(severity);
  return (
    <span className={cn("inline-flex w-fit shrink-0 items-center gap-1.5 rounded-md border px-2 py-0.5 text-xs font-medium whitespace-nowrap", s.cls)}>
      <span aria-hidden className="flex h-2.5 items-end gap-px">
        {[1, 2, 3, 4].map((i) => (
          <span key={i} className={cn("w-[2px] rounded-sm", i <= rank - 1 ? s.dot : "bg-current opacity-25")} style={{ height: `${i * 2 + 2}px` }} />
        ))}
      </span>
      {compact ? <span className="sr-only">{s.label}</span> : s.label}
    </span>
  );
}

const INCIDENT_STATUS: Record<IncidentStatus, { label: string; dot: string }> = {
  new: { label: "New", dot: "bg-accent" },
  open: { label: "Open", dot: "bg-info" },
  investigating: { label: "Investigating", dot: "bg-warn" },
  contained: { label: "Contained", dot: "bg-teal" },
  resolved: { label: "Resolved", dot: "bg-ok" },
  closed: { label: "Closed", dot: "bg-subtle" },
};

export function StatusDot({ className }: { className: string }) {
  return <span aria-hidden className={cn("inline-block size-1.5 shrink-0 rounded-full", className)} />;
}

export function IncidentStatusBadge({ status }: { status: IncidentStatus }) {
  const s = INCIDENT_STATUS[status];
  return (
    <span className="inline-flex w-fit shrink-0 items-center gap-1.5 rounded-md border border-line-strong px-2 py-0.5 text-xs font-medium whitespace-nowrap text-fg">
      <StatusDot className={s.dot} />
      {s.label}
    </span>
  );
}

const ALERT_STATUS: Record<AlertStatus, { label: string; dot: string }> = {
  new: { label: "New", dot: "bg-accent" },
  acknowledged: { label: "Acknowledged", dot: "bg-info" },
  escalated: { label: "Escalated", dot: "bg-warn" },
  closed: { label: "Closed", dot: "bg-subtle" },
};

export function AlertStatusBadge({ status }: { status: AlertStatus }) {
  const s = ALERT_STATUS[status];
  return (
    <span className="inline-flex w-fit shrink-0 items-center gap-1.5 rounded-md border border-line-strong px-2 py-0.5 text-xs font-medium whitespace-nowrap text-fg">
      <StatusDot className={s.dot} />
      {s.label}
    </span>
  );
}

const VERDICT: Record<Verdict, { label: string; cls: string }> = {
  true_positive: { label: "True positive", cls: "text-danger border-danger/30" },
  benign_positive: { label: "Benign positive", cls: "text-info border-info/30" },
  false_positive: { label: "False positive", cls: "text-muted border-line-strong" },
  undetermined: { label: "Undetermined", cls: "text-warn border-warn/30" },
};

export function VerdictBadge({ verdict }: { verdict: Verdict | null }) {
  if (!verdict) return <span className="text-xs text-subtle">Not set</span>;
  const v = VERDICT[verdict];
  return <span className={cn("inline-flex w-fit shrink-0 rounded-md border px-2 py-0.5 text-xs font-medium whitespace-nowrap", v.cls)}>{v.label}</span>;
}

export const VERDICT_OPTIONS: { value: Verdict; label: string; help: string }[] = [
  { value: "true_positive", label: "True positive", help: "Malicious or unauthorised activity occurred." },
  { value: "benign_positive", label: "Benign positive", help: "The rule fired correctly, but the activity is expected or authorised." },
  { value: "false_positive", label: "False positive", help: "The rule fired on activity that does not match its intent." },
  { value: "undetermined", label: "Undetermined", help: "Evidence is insufficient to decide." },
];

/** Confidence: how sure the detection is. Deliberately neutral-coloured so it is never confused with severity. */
export function ConfidenceMeter({ confidence }: { confidence: Confidence }) {
  const level = { low: 1, medium: 2, high: 3 }[confidence];
  return (
    <span className="inline-flex items-center gap-1.5 text-xs text-muted" title={`Detection confidence: ${confidence}`}>
      <span aria-hidden className="flex gap-0.5">
        {[1, 2, 3].map((i) => (
          <span key={i} className={cn("h-1.5 w-2.5 rounded-sm", i <= level ? "bg-muted" : "bg-line-strong")} />
        ))}
      </span>
      <span className="capitalize">{confidence}</span>
    </span>
  );
}

export function Tag({ children }: { children: ReactNode }) {
  return <span className="inline-flex items-center rounded-md border border-line-strong px-1.5 py-0.5 text-xs text-muted">{children}</span>;
}

export function SyntheticBadge() {
  return (
    <span className="inline-flex w-fit shrink-0 items-center gap-1 rounded-md border border-accent/30 bg-accent-soft px-1.5 py-0.5 text-xs font-medium text-accent" title="Generated demonstration data. Not a real event.">
      <FlaskConical className="size-3" aria-hidden />
      Synthetic
    </span>
  );
}

export function SimulatedBadge() {
  return <span className="inline-flex w-fit rounded-md border border-teal/30 bg-teal/10 px-2 py-0.5 text-xs font-medium text-teal">Simulated</span>;
}

const PROVIDER_VERDICT: Record<string, string> = {
  malicious: "text-danger border-danger/30 bg-danger/10",
  suspicious: "text-warn border-warn/30 bg-warn/10",
  harmless: "text-ok border-ok/30 bg-ok/10",
  benign: "text-ok border-ok/30 bg-ok/10",
  unknown: "text-muted border-line-strong",
};

export function IntelVerdictBadge({ verdict }: { verdict: string }) {
  return <span className={cn("inline-flex w-fit shrink-0 rounded-md border px-2 py-0.5 text-xs font-medium whitespace-nowrap capitalize", PROVIDER_VERDICT[verdict] ?? PROVIDER_VERDICT.unknown)}>{verdict}</span>;
}
