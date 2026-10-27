"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Copy, FlaskConical, KeyRound, Play, Plus } from "lucide-react";
import { useState } from "react";

import { StatusDot, SyntheticBadge } from "@/components/ui/badges";
import { ConfirmDialog, Dialog, useToast } from "@/components/ui/overlays";
import { Button, EmptyState, ErrorState, Field, Input, KeyValue, PageHeader, Panel, Select, Skeleton } from "@/components/ui/primitives";
import { ApiError, api } from "@/lib/api";
import { formatDateTime, relativeTime } from "@/lib/format";
import { useCan, useMe } from "@/lib/hooks";
import type { DataSource, Role } from "@/lib/types";

interface SystemInfo {
  version: string;
  environment: string;
  demo_mode: boolean;
  migration_revision: string | null;
  organization: { name: string; is_demo: boolean };
  integrations: { name: string; configured: boolean }[];
  session: { ttl_hours: number; idle_minutes: number };
  limits: { max_body_bytes: number; max_ingest_body_bytes: number; login_rate_limit: string };
}
interface AdminUser { id: string; email: string; display_name: string; role: Role; is_active: boolean; is_demo: boolean; created_at: string; last_login_at: string | null }
interface Scenario { id: string; name: string; description: string; expected_rules: string[]; expected_decision: string }

function errText(e: unknown) {
  return e instanceof ApiError ? e.detail : "Unexpected error";
}

function OneTimeKey({ secret, onClose }: { secret: string | null; onClose: () => void }) {
  const toast = useToast();
  return (
    <Dialog open={!!secret} onOpenChange={(o) => !o && onClose()} title="Ingest key created" description="Copy it now. Only a hash is stored, so it cannot be shown again." footer={<Button variant="primary" onClick={onClose}>I have stored it</Button>}>
      <div className="flex gap-2">
        <Input readOnly value={secret ?? ""} className="mono" aria-label="Ingest key" onFocus={(e) => e.currentTarget.select()} />
        <Button icon={<Copy className="size-3.5" aria-hidden />} onClick={() => { navigator.clipboard?.writeText(secret ?? ""); toast({ kind: "info", title: "Copied to clipboard" }); }}>Copy</Button>
      </div>
      <p className="mt-3 text-xs text-muted">Send events with <span className="mono text-fg">Authorization: Bearer &lt;key&gt;</span> to <span className="mono text-fg">POST /api/v1/ingest/events</span>. See docs/api.md.</p>
    </Dialog>
  );
}

function DataSources() {
  const isAdmin = useCan("admin");
  const { data: me } = useMe();
  const qc = useQueryClient();
  const toast = useToast();
  const [creating, setCreating] = useState(false);
  const [name, setName] = useState("");
  const [type, setType] = useState("custom");
  const [secret, setSecret] = useState<string | null>(null);
  const q = useQuery({ queryKey: ["data-sources"], queryFn: () => api<DataSource[]>("/data-sources") });
  const create = useMutation({
    mutationFn: () => api<DataSource & { ingest_key: string }>("/data-sources", { method: "POST", body: { name, source_type: type } }),
    onSuccess: (s) => { qc.invalidateQueries({ queryKey: ["data-sources"] }); setCreating(false); setName(""); setSecret(s.ingest_key); },
    onError: (e) => toast({ kind: "error", title: "Not created", description: errText(e) }),
  });
  const rotate = useMutation({
    mutationFn: (id: string) => api<DataSource & { ingest_key: string }>(`/data-sources/${id}/rotate-key`, { method: "POST" }),
    onSuccess: (s) => { qc.invalidateQueries({ queryKey: ["data-sources"] }); setSecret(s.ingest_key); },
    onError: (e) => toast({ kind: "error", title: "Key not rotated", description: errText(e) }),
  });
  const canManage = isAdmin && !me?.is_demo;
  // Snapshot "now" once so health labels are stable between renders.
  const [now] = useState(() => Date.now());
  return (
    <Panel title="Data sources" description="Each source has its own ingest key. Health reflects the last event received." bodyClassName="p-0" id="sources" actions={canManage && <Button size="sm" icon={<Plus className="size-3" aria-hidden />} onClick={() => setCreating(true)}>Add source</Button>}>
      {q.isError ? <ErrorState error={q.error} onRetry={() => q.refetch()} /> : !q.data ? <Skeleton className="m-4 h-24" /> : q.data.length === 0 ? <EmptyState title="No data sources" /> : (
        <ul className="divide-y divide-line">
          {q.data.map((s) => {
            const healthy = !!s.last_event_at && now - new Date(s.last_event_at).getTime() < 86_400_000;
            return (
              <li key={s.id} className="flex flex-col gap-1.5 px-4 py-2.5 md:flex-row md:items-center md:gap-4">
                <span className="inline-flex w-24 items-center gap-1.5 text-xs text-muted"><StatusDot className={healthy ? "bg-ok" : "bg-warn"} />{healthy ? "Reporting" : "Stale"}</span>
                <span className="min-w-0 flex-1">
                  <span className="text-[13px] text-fg">{s.name}</span> {s.is_synthetic && <SyntheticBadge />}
                  <span className="block text-xs text-subtle">{s.source_type} · {s.event_count.toLocaleString()} events · last {relativeTime(s.last_event_at)}</span>
                </span>
                <span className="mono text-xs text-subtle">{s.has_ingest_key ? `${s.ingest_key_prefix}…` : "no ingest key"}</span>
                {canManage && s.has_ingest_key && <Button size="sm" variant="ghost" icon={<KeyRound className="size-3" aria-hidden />} loading={rotate.isPending && rotate.variables === s.id} onClick={() => rotate.mutate(s.id)}>Rotate key</Button>}
              </li>
            );
          })}
        </ul>
      )}
      <Dialog open={creating} onOpenChange={setCreating} title="Add data source" footer={<Button variant="primary" loading={create.isPending} disabled={name.trim().length < 2} onClick={() => create.mutate()}>Create and show key</Button>}>
        <div className="space-y-3">
          <Field label="Name" htmlFor="ds-name"><Input id="ds-name" value={name} onChange={(e) => setName(e.target.value)} maxLength={120} /></Field>
          <Field label="Type" htmlFor="ds-type">
            <Select id="ds-type" value={type} onChange={(e) => setType(e.target.value)}>
              {["windows_security", "sysmon", "microsoft_entra", "microsoft_defender", "linux_auditd", "firewall", "dns", "proxy", "email_gateway", "edr", "custom"].map((t) => <option key={t} value={t}>{t}</option>)}
            </Select>
          </Field>
        </div>
      </Dialog>
      <OneTimeKey secret={secret} onClose={() => setSecret(null)} />
    </Panel>
  );
}

function Users() {
  const qc = useQueryClient();
  const toast = useToast();
  const { data: me } = useMe();
  const [open, setOpen] = useState(false);
  const [form, setForm] = useState({ email: "", display_name: "", role: "analyst" as Role, password: "" });
  const q = useQuery({ queryKey: ["admin-users"], queryFn: () => api<AdminUser[]>("/admin/users") });
  const create = useMutation({
    mutationFn: () => api("/admin/users", { method: "POST", body: form }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["admin-users"] }); setOpen(false); setForm({ email: "", display_name: "", role: "analyst", password: "" }); toast({ kind: "success", title: "User created" }); },
    onError: (e) => toast({ kind: "error", title: "User not created", description: errText(e) }),
  });
  const update = useMutation({
    mutationFn: ({ id, body }: { id: string; body: object }) => api(`/admin/users/${id}`, { method: "PATCH", body }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["admin-users"] }); toast({ kind: "success", title: "User updated" }); },
    onError: (e) => toast({ kind: "error", title: "Not updated", description: errText(e) }),
  });
  const locked = !!me?.is_demo;
  return (
    <Panel title="Users and roles" description="Viewer (read-only), analyst (triage and investigate), lead (approve and reopen), admin (users and data sources)." bodyClassName="p-0" id="users" actions={!locked && <Button size="sm" icon={<Plus className="size-3" aria-hidden />} onClick={() => setOpen(true)}>Add user</Button>}>
      {locked && <p className="border-b border-line px-4 py-2 text-xs text-warn">User management is disabled for demo accounts.</p>}
      {q.isError ? <ErrorState error={q.error} onRetry={() => q.refetch()} /> : !q.data ? <Skeleton className="m-4 h-24" /> : (
        <ul className="divide-y divide-line">
          {q.data.map((u) => (
            <li key={u.id} className="flex flex-col gap-2 px-4 py-2.5 md:flex-row md:items-center md:gap-4">
              <span className="min-w-0 flex-1">
                <span className="text-[13px] text-fg">{u.display_name}</span>
                <span className="block text-xs text-subtle">{u.email} · last sign-in {relativeTime(u.last_login_at)}</span>
              </span>
              <label className="sr-only" htmlFor={`role-${u.id}`}>Role for {u.display_name}</label>
              <Select id={`role-${u.id}`} className="w-32" value={u.role} disabled={locked || u.id === me?.id} onChange={(e) => update.mutate({ id: u.id, body: { role: e.target.value } })}>
                {["viewer", "analyst", "lead", "admin"].map((r) => <option key={r} value={r}>{r}</option>)}
              </Select>
              <Button size="sm" variant={u.is_active ? "ghost" : "secondary"} disabled={locked || u.id === me?.id} onClick={() => update.mutate({ id: u.id, body: { is_active: !u.is_active } })}>
                {u.is_active ? "Deactivate" : "Reactivate"}
              </Button>
            </li>
          ))}
        </ul>
      )}
      <Dialog open={open} onOpenChange={setOpen} title="Add user" description="Passwords need 12+ characters with upper and lower case letters and a digit. Share them out of band." footer={<Button variant="primary" loading={create.isPending} onClick={() => create.mutate()}>Create user</Button>}>
        <div className="space-y-3">
          <Field label="Email" htmlFor="u-email"><Input id="u-email" type="email" value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} /></Field>
          <Field label="Display name" htmlFor="u-name"><Input id="u-name" value={form.display_name} onChange={(e) => setForm({ ...form, display_name: e.target.value })} /></Field>
          <Field label="Role" htmlFor="u-role">
            <Select id="u-role" value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value as Role })}>{["viewer", "analyst", "lead", "admin"].map((r) => <option key={r} value={r}>{r}</option>)}</Select>
          </Field>
          <Field label="Initial password" htmlFor="u-pw"><Input id="u-pw" type="password" autoComplete="new-password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} /></Field>
        </div>
      </Dialog>
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
                <p className="text-[13px] font-medium text-fg">{s.name}</p>
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

function ChangePassword() {
  const toast = useToast();
  const empty = { current_password: "", new_password: "", confirm: "" };
  const [form, setForm] = useState(empty);
  const mismatch = form.confirm.length > 0 && form.confirm !== form.new_password;
  const change = useMutation({
    mutationFn: () => api("/auth/password", { method: "POST", body: { current_password: form.current_password, new_password: form.new_password } }),
    onSuccess: () => { setForm(empty); toast({ kind: "success", title: "Password changed", description: "Your other sessions were signed out." }); },
    onError: (e) => toast({ kind: "error", title: "Password not changed", description: errText(e) }),
  });
  return (
    <Panel title={<span className="flex items-center gap-1.5"><KeyRound className="size-3.5 text-accent" aria-hidden /> Change password</span>} description="12+ characters with upper and lower case letters and a digit. Every other session of yours is signed out." id="password">
      <form
        className="grid gap-3 md:grid-cols-3"
        onSubmit={(e) => {
          e.preventDefault();
          if (!mismatch && form.new_password) change.mutate();
        }}
      >
        <Field label="Current password" htmlFor="pw-current"><Input id="pw-current" type="password" autoComplete="current-password" value={form.current_password} onChange={(e) => setForm({ ...form, current_password: e.target.value })} /></Field>
        <Field label="New password" htmlFor="pw-new"><Input id="pw-new" type="password" autoComplete="new-password" value={form.new_password} onChange={(e) => setForm({ ...form, new_password: e.target.value })} /></Field>
        <Field label="Repeat new password" htmlFor="pw-confirm" error={mismatch ? "Passwords do not match" : undefined}><Input id="pw-confirm" type="password" autoComplete="new-password" aria-invalid={mismatch} value={form.confirm} onChange={(e) => setForm({ ...form, confirm: e.target.value })} /></Field>
        <div className="md:col-span-3">
          <Button type="submit" variant="primary" loading={change.isPending} disabled={!form.current_password || !form.new_password || mismatch}>Change password</Button>
        </div>
      </form>
    </Panel>
  );
}

export default function SettingsPage() {
  const isAdmin = useCan("admin");
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
                  <li key={i.name} className="flex items-center justify-between text-[13px]">
                    <span className="text-fg">{i.name}</span>
                    <span className="inline-flex items-center gap-1.5 text-xs text-muted"><StatusDot className={i.configured ? "bg-ok" : "bg-subtle"} />{i.configured ? "Configured" : "Not configured"}</span>
                  </li>
                ))}
              </ul>
            )}
            <p className="mt-3 text-xs text-subtle">Unconfigured providers are reported as such; the platform never invents results. Last checked {formatDateTime(new Date().toISOString())}.</p>
          </Panel>
        </div>
        <DataSources />
        {sys.data && <Scenarios orgIsDemo={sys.data.organization.is_demo} />}
        {isAdmin && <Users />}
        {me && !me.is_demo && <ChangePassword />}
      </div>
    </>
  );
}
