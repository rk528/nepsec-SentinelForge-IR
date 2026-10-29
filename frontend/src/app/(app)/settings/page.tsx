"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { BellRing, FlaskConical, KeyRound, Play } from "lucide-react";
import { useState } from "react";

import { ChangePasswordForm, PASSWORD_RULES } from "@/components/password-change";
import { StatusDot, SyntheticBadge } from "@/components/ui/badges";
import { ConfirmDialog, useToast } from "@/components/ui/overlays";
import { Button, EmptyState, ErrorState, KeyValue, PageHeader, Panel, Skeleton, cn } from "@/components/ui/primitives";
import { ApiError, api } from "@/lib/api";
import { formatDateTime, relativeTime } from "@/lib/format";
import { useCan, useMe } from "@/lib/hooks";
import type { DataSource, Me } from "@/lib/types";

interface SystemInfo {
  version: string;
  environment: string;
  demo_mode: boolean;
  migration_revision: string | null;
  organization: { name: string; is_demo: boolean };
  integrations: { name: string; configured: boolean }[];
  email: { provider: string; configured: boolean; sender: string };
  session: { ttl_hours: number; idle_minutes: number };
  limits: { max_body_bytes: number; max_ingest_body_bytes: number; login_rate_limit: string };
}
interface Scenario { id: string; name: string; description: string; expected_rules: string[]; expected_decision: string }

function errText(e: unknown) {
  return e instanceof ApiError ? e.detail : "Unexpected error";
}

function DataSources() {
  const q = useQuery({ queryKey: ["data-sources"], queryFn: () => api<DataSource[]>("/data-sources") });
  // Snapshot "now" once so health labels are stable between renders.
  const [now] = useState(() => Date.now());
  return (
    <Panel
      title="Data sources"
      description="Each source has its own ingest key. Health reflects the last event received. Sources, their keys and user accounts are managed in the admin console."
      bodyClassName="p-0"
      id="sources"
    >
      {q.isError ? <ErrorState error={q.error} onRetry={() => q.refetch()} /> : !q.data ? <Skeleton className="m-5 h-24" /> : q.data.length === 0 ? <EmptyState title="No data sources" description="An administrator adds sources in the admin console." /> : (
        <ul className="divide-y divide-line">
          {q.data.map((s) => {
            const healthy = !!s.last_event_at && now - new Date(s.last_event_at).getTime() < 86_400_000;
            return (
              <li key={s.id} className="px-5 py-4">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-sm font-medium text-fg">{s.name}</span>
                  {s.is_synthetic && <SyntheticBadge />}
                </div>
                <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-muted">
                  <span className="inline-flex items-center gap-1.5"><StatusDot className={healthy ? "bg-ok" : "bg-warn"} />{healthy ? "Reporting" : "Stale"}</span>
                  <span className="mono">{s.source_type}</span>
                  <span>{s.event_count.toLocaleString()} events</span>
                  <span>last {relativeTime(s.last_event_at)}</span>
                  <span className="mono">{s.has_ingest_key ? `key ${s.ingest_key_prefix}…` : "no ingest key"}</span>
                </div>
              </li>
            );
          })}
        </ul>
      )}
    </Panel>
  );
}

function Scenarios({ orgIsDemo }: { orgIsDemo: boolean }) {
  const canRun = useCan("analyst");
  const isAdmin = useCan("admin");
  const qc = useQueryClient();
  const toast = useToast();
  const [confirm, setConfirm] = useState<Scenario | null>(null);
  const q = useQuery({ queryKey: ["scenarios"], queryFn: () => api<Scenario[]>("/scenarios") });
  const run = useMutation({
    mutationFn: (id: string) => api<{ events_inserted: number; alerts_created: number }>(`/scenarios/${id}/run`, { method: "POST" }),
    onSuccess: (r) => { qc.invalidateQueries(); setConfirm(null); toast({ kind: "success", title: `Ingested ${r.events_inserted} synthetic events`, description: `${r.alerts_created} new alert(s) raised.` }); },
    onError: (e) => toast({ kind: "error", title: "Scenario not run", description: errText(e) }),
  });
  const allowed = canRun && (orgIsDemo || isAdmin);
  return (
    <Panel title={<span className="flex items-center gap-1.5"><FlaskConical className="size-3.5 text-accent" aria-hidden /> Synthetic scenarios</span>} description="Deterministic, clearly labelled synthetic telemetry for demonstrations and testing. Uses documentation IP ranges and reserved domains only." bodyClassName="p-0" id="scenarios">
      {!q.data ? <Skeleton className="m-4 h-24" /> : (
        <ul className="divide-y divide-line">
          {q.data.map((s) => (
            <li key={s.id} className="flex flex-col gap-2 px-4 py-3 md:flex-row md:items-start md:gap-4">
              <div className="min-w-0 flex-1">
                <p className="text-sm font-medium text-fg">{s.name}</p>
                <p className="mt-0.5 text-xs text-muted">{s.description}</p>
                <p className="mt-1 text-xs text-subtle">Expected: <span className="mono">{s.expected_rules.join(", ")}</span> · {s.expected_decision}</p>
              </div>
              {allowed && <Button size="sm" icon={<Play className="size-3" aria-hidden />} onClick={() => setConfirm(s)}>Inject</Button>}
            </li>
          ))}
        </ul>
      )}
      <ConfirmDialog open={!!confirm} onOpenChange={(o) => !o && setConfirm(null)} title={`Inject “${confirm?.name}”?`} description="Synthetic events are written with fresh timestamps and flagged as synthetic. Detection runs immediately." confirmLabel="Inject events" loading={run.isPending} onConfirm={() => confirm && run.mutate(confirm.id)} />
    </Panel>
  );
}

const ALERT_EMAIL_OPTIONS = [
  { value: "", label: "Off", hint: "No alert emails." },
  { value: "critical", label: "Critical only", hint: "Only the most urgent alerts, such as credential dumping." },
  { value: "high", label: "High and above", hint: "Recommended for responders: sign-in takeovers, new admins, persistence." },
  { value: "medium", label: "Medium and above", hint: "Adds lower-confidence detections." },
  { value: "low", label: "Everything", hint: "Every new alert, including low severity." },
] as const;

function AlertEmails({ emailConfigured }: { emailConfigured: boolean }) {
  const { data: me } = useMe();
  const qc = useQueryClient();
  const toast = useToast();
  const save = useMutation({
    mutationFn: (severity: string) => api<Me>("/auth/me/notifications", { method: "PATCH", body: { alert_email_severity: severity || null } }),
    onSuccess: (m) => {
      qc.setQueryData(["me"], (old: Me | undefined) => (old ? { ...old, alert_email_severity: m.alert_email_severity } : m));
      toast({ kind: "success", title: m.alert_email_severity ? "Alert emails on" : "Alert emails off" });
    },
    onError: (e) => toast({ kind: "error", title: "Not saved", description: errText(e) }),
  });
  const current = me?.alert_email_severity ?? "";
  return (
    <Panel
      title={<span className="flex items-center gap-1.5"><BellRing className="size-3.5 text-accent" aria-hidden /> Alert emails</span>}
      description={`New alerts are emailed to ${me?.email ?? "you"} as one digest, at most every 10 minutes, so a burst never floods your inbox.`}
      id="alert-emails"
    >
      {!emailConfigured && <p className="mb-3 rounded-md border border-warn/30 bg-warn/10 px-3 py-2 text-xs text-warn">Email is not configured on this deployment, so nothing will be sent until an administrator sets RESEND_API_KEY.</p>}
      <div role="radiogroup" aria-label="Alert emails" className="grid gap-2 sm:grid-cols-2 lg:grid-cols-5">
        {ALERT_EMAIL_OPTIONS.map((o) => (
          <button
            key={o.value}
            type="button"
            role="radio"
            aria-checked={current === o.value}
            disabled={save.isPending}
            onClick={() => current !== o.value && save.mutate(o.value)}
            className={cn("rounded-lg border p-3 text-left transition-colors disabled:opacity-60", current === o.value ? "border-accent/60 bg-accent/10" : "border-line hover:bg-raised")}
          >
            <span className={cn("block text-sm font-medium", current === o.value ? "text-accent" : "text-fg")}>{o.label}</span>
            <span className="mt-0.5 block text-xs text-muted">{o.hint}</span>
          </button>
        ))}
      </div>
    </Panel>
  );
}

function ChangePassword() {
  return (
    <Panel title={<span className="flex items-center gap-1.5"><KeyRound className="size-3.5 text-accent" aria-hidden /> Change password</span>} description={`${PASSWORD_RULES} Every other session of yours is signed out.`} id="password">
      <ChangePasswordForm />
    </Panel>
  );
}

export default function SettingsPage() {
  const { data: me } = useMe();
  const sys = useQuery({ queryKey: ["system"], queryFn: () => api<SystemInfo>("/system") });
  return (
    <>
      <PageHeader title="Settings" description="Workspace configuration, integrations and platform health. Secrets are never displayed." />
      <div className="space-y-4">
        <div className="grid gap-4 lg:grid-cols-2">
          <Panel title="Application" id="app">
            {!sys.data ? <Skeleton className="h-24" /> : (
              <KeyValue
                items={[
                  { label: "Organisation", value: sys.data.organization.name },
                  { label: "Environment", value: sys.data.environment },
                  { label: "API version", value: sys.data.version, mono: true },
                  { label: "Schema revision", value: sys.data.migration_revision ?? "unknown", mono: true },
                  { label: "Demo mode", value: sys.data.demo_mode ? "Enabled (synthetic data only)" : "Disabled" },
                  { label: "Sessions", value: `${sys.data.session.ttl_hours}h max, ${sys.data.session.idle_minutes}m idle` },
                  { label: "Login rate limit", value: sys.data.limits.login_rate_limit },
                  { label: "Max request body", value: `${Math.round(sys.data.limits.max_body_bytes / 1024)} KiB (ingest ${Math.round(sys.data.limits.max_ingest_body_bytes / 1024)} KiB)` },
                ]}
              />
            )}
          </Panel>
          <Panel title="Threat intelligence integrations" description="API keys are set as backend environment variables, never in the UI." id="intel">
            {!sys.data ? <Skeleton className="h-24" /> : (
              <ul className="space-y-2">
                {sys.data.integrations.map((i) => (
                  <li key={i.name} className="flex items-center justify-between text-sm">
                    <span className="text-fg">{i.name}</span>
                    <span className="inline-flex items-center gap-1.5 text-xs text-muted"><StatusDot className={i.configured ? "bg-ok" : "bg-subtle"} />{i.configured ? "Configured" : "Not configured"}</span>
                  </li>
                ))}
                <li className="flex items-center justify-between border-t border-line pt-2 text-sm">
                  <span className="text-fg">Email ({sys.data.email.provider})</span>
                  <span className="inline-flex items-center gap-1.5 text-xs text-muted"><StatusDot className={sys.data.email.configured ? "bg-ok" : "bg-subtle"} />{sys.data.email.configured ? `Sending as ${sys.data.email.sender}` : "Not configured"}</span>
                </li>
              </ul>
            )}
            <p className="mt-3 text-xs text-subtle">Unconfigured providers are reported as such; the platform never invents results. Last checked {formatDateTime(new Date().toISOString())}.</p>
          </Panel>
        </div>
        <DataSources />
        {sys.data && <Scenarios orgIsDemo={sys.data.organization.is_demo} />}
        {me && !me.is_demo && sys.data && <AlertEmails emailConfigured={sys.data.email.configured} />}
        {me && !me.is_demo && <ChangePassword />}
      </div>
    </>
  );
}
