"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Copy, FlaskConical, KeyRound, Mail, Play, Plus, Trash2 } from "lucide-react";
import { useState } from "react";

import { ChangePasswordForm, PASSWORD_RULES } from "@/components/password-change";
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
  email: { provider: string; configured: boolean; sender: string };
  session: { ttl_hours: number; idle_minutes: number };
  limits: { max_body_bytes: number; max_ingest_body_bytes: number; login_rate_limit: string };
}
interface AdminUser { id: string; email: string; display_name: string; role: Role; is_active: boolean; is_demo: boolean; created_at: string; last_login_at: string | null; must_change_password: boolean }
interface Delivery { email_sent: boolean; email_error: string | null; temporary_password?: string; password_link?: string }
interface Undelivered { title: string; email: string; error: string | null; temporaryPassword?: string; link?: string }
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
      <p className="mt-3 text-sm text-muted">
        Shippers send it as <span className="mono text-fg">Authorization: Bearer &lt;key&gt;</span>. Endpoints: <span className="mono text-fg">/api/v1/ingest/events</span> (normalised JSON),{" "}
        <span className="mono text-fg">/ingest/microsoft/…</span> (Entra ID, Defender, Windows), <span className="mono text-fg">/ingest/linux</span> (Ubuntu and other Linux) and <span className="mono text-fg">/ingest/fortigate</span> (FortiGate relay). See the connector guides in docs/.
      </p>
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
  const [confirm, setConfirm] = useState<{ kind: "revoke" | "delete"; source: DataSource } | null>(null);
  const q = useQuery({ queryKey: ["data-sources"], queryFn: () => api<DataSource[]>("/data-sources") });
  const refresh = () => qc.invalidateQueries({ queryKey: ["data-sources"] });
  const create = useMutation({
    mutationFn: () => api<DataSource & { ingest_key: string }>("/data-sources", { method: "POST", body: { name, source_type: type } }),
    onSuccess: (s) => { refresh(); setCreating(false); setName(""); setSecret(s.ingest_key); },
    onError: (e) => toast({ kind: "error", title: "Not created", description: errText(e) }),
  });
  const rotate = useMutation({
    mutationFn: (id: string) => api<DataSource & { ingest_key: string }>(`/data-sources/${id}/rotate-key`, { method: "POST" }),
    onSuccess: (s) => { refresh(); setSecret(s.ingest_key); },
    onError: (e) => toast({ kind: "error", title: "Key not issued", description: errText(e) }),
  });
  const remove = useMutation({
    mutationFn: ({ kind, source }: { kind: "revoke" | "delete"; source: DataSource }) =>
      kind === "revoke" ? api(`/data-sources/${source.id}/revoke-key`, { method: "POST" }) : api(`/data-sources/${source.id}`, { method: "DELETE" }),
    onSuccess: (_, v) => { refresh(); setConfirm(null); toast({ kind: "success", title: v.kind === "revoke" ? "Ingest key revoked" : "Data source deleted" }); },
    onError: (e) => { setConfirm(null); toast({ kind: "error", title: "Not changed", description: errText(e) }); },
  });
  const canManage = isAdmin && !me?.is_demo;
  // Snapshot "now" once so health labels are stable between renders.
  const [now] = useState(() => Date.now());
  return (
    <Panel title="Data sources" description="Each source has its own ingest key. Health reflects the last event received." bodyClassName="p-0" id="sources" actions={canManage && <Button size="sm" icon={<Plus className="size-3.5" aria-hidden />} onClick={() => setCreating(true)}>Add source</Button>}>
      {q.isError ? <ErrorState error={q.error} onRetry={() => q.refetch()} /> : !q.data ? <Skeleton className="m-5 h-24" /> : q.data.length === 0 ? <EmptyState title="No data sources" description="Add a source to get an ingest key for a log shipper or relay." /> : (
        <ul className="divide-y divide-line">
          {q.data.map((s) => {
            const healthy = !!s.last_event_at && now - new Date(s.last_event_at).getTime() < 86_400_000;
            return (
              <li key={s.id} className="flex flex-col gap-3 px-5 py-4 lg:flex-row lg:items-center lg:gap-6">
                <div className="min-w-0 flex-1">
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
                </div>
                {canManage && (
                  <div className="flex flex-wrap items-center gap-2">
                    <Button size="sm" icon={<KeyRound className="size-3.5" aria-hidden />} loading={rotate.isPending && rotate.variables === s.id} onClick={() => rotate.mutate(s.id)}>
                      {s.has_ingest_key ? "Rotate key" : "Issue key"}
                    </Button>
                    {s.has_ingest_key && <Button size="sm" variant="ghost" icon={<KeyRound className="size-3.5" aria-hidden />} onClick={() => setConfirm({ kind: "revoke", source: s })}>Revoke key</Button>}
                    {s.event_count === 0 && <Button size="sm" variant="danger" icon={<Trash2 className="size-3.5" aria-hidden />} onClick={() => setConfirm({ kind: "delete", source: s })}>Delete</Button>}
                  </div>
                )}
              </li>
            );
          })}
        </ul>
      )}
      <Dialog open={creating} onOpenChange={setCreating} title="Add data source" footer={<Button variant="primary" loading={create.isPending} disabled={name.trim().length < 2} onClick={() => create.mutate()}>Create and show key</Button>}>
        <div className="space-y-4">
          <Field label="Name" htmlFor="ds-name"><Input id="ds-name" value={name} onChange={(e) => setName(e.target.value)} maxLength={120} placeholder="e.g. FortiGate HQ" /></Field>
          <Field label="Type" htmlFor="ds-type">
            <Select id="ds-type" value={type} onChange={(e) => setType(e.target.value)}>
              {["windows_security", "sysmon", "microsoft_entra", "microsoft_defender", "fortigate", "linux", "linux_auditd", "firewall", "dns", "proxy", "email_gateway", "edr", "custom"].map((t) => <option key={t} value={t}>{t}</option>)}
            </Select>
          </Field>
        </div>
      </Dialog>
      <ConfirmDialog
        open={!!confirm}
        onOpenChange={(o) => !o && setConfirm(null)}
        destructive
        title={confirm?.kind === "revoke" ? `Revoke the key for “${confirm.source.name}”?` : `Delete “${confirm?.source.name}”?`}
        description={confirm?.kind === "revoke" ? "Shippers using this key are rejected immediately. Stored events are kept. You can issue a new key later." : "This source has no stored events, so nothing else is affected."}
        confirmLabel={confirm?.kind === "revoke" ? "Revoke key" : "Delete source"}
        loading={remove.isPending}
        onConfirm={() => confirm && remove.mutate(confirm)}
      />
      <OneTimeKey secret={secret} onClose={() => setSecret(null)} />
    </Panel>
  );
}

function Users() {
  const qc = useQueryClient();
  const toast = useToast();
  const { data: me } = useMe();
  const [open, setOpen] = useState(false);
  const [removing, setRemoving] = useState<AdminUser | null>(null);
  const [undelivered, setUndelivered] = useState<Undelivered | null>(null);
  const [form, setForm] = useState({ email: "", display_name: "", role: "analyst" as Role });
  const q = useQuery({ queryKey: ["admin-users"], queryFn: () => api<AdminUser[]>("/admin/users") });
  const refresh = () => qc.invalidateQueries({ queryKey: ["admin-users"] });
  const create = useMutation({
    mutationFn: () => api<Delivery & { id: string }>("/admin/users", { method: "POST", body: form }),
    onSuccess: (r) => {
      refresh();
      setOpen(false);
      if (r.email_sent) toast({ kind: "success", title: "User created", description: `Welcome email with a temporary password and set-password link sent to ${form.email}.` });
      else setUndelivered({ title: "User created, but the welcome email was not sent", email: form.email, error: r.email_error, temporaryPassword: r.temporary_password, link: r.password_link });
      setForm({ email: "", display_name: "", role: "analyst" });
    },
    onError: (e) => toast({ kind: "error", title: "User not created", description: errText(e) }),
  });
  const sendReset = useMutation({
    mutationFn: (u: AdminUser) => api<Delivery>(`/admin/users/${u.id}/send-reset`, { method: "POST" }),
    onSuccess: (r, u) => {
      if (r.email_sent) toast({ kind: "success", title: "Password reset email sent", description: `${u.email} can choose a new password with the link for the next 24 hours.` });
      else setUndelivered({ title: "Reset link created, but the email was not sent", email: u.email, error: r.email_error, link: r.password_link });
    },
    onError: (e) => toast({ kind: "error", title: "Reset not sent", description: errText(e) }),
  });
  const update = useMutation({
    mutationFn: ({ id, body }: { id: string; body: object }) => api(`/admin/users/${id}`, { method: "PATCH", body }),
    onSuccess: () => { refresh(); toast({ kind: "success", title: "User updated" }); },
    onError: (e) => toast({ kind: "error", title: "Not updated", description: errText(e) }),
  });
  const remove = useMutation({
    mutationFn: (id: string) => api(`/admin/users/${id}`, { method: "DELETE" }),
    onSuccess: () => { refresh(); setRemoving(null); toast({ kind: "success", title: "User removed", description: "They were signed out everywhere and can no longer sign in." }); },
    onError: (e) => { setRemoving(null); toast({ kind: "error", title: "User not removed", description: errText(e) }); },
  });
  const locked = !!me?.is_demo;
  return (
    <Panel title="Users and roles" description="Viewer (read-only), analyst (triage and investigate), lead (approve and reopen), admin (users and data sources)." bodyClassName="p-0" id="users" actions={!locked && <Button size="sm" icon={<Plus className="size-3.5" aria-hidden />} onClick={() => setOpen(true)}>Add user</Button>}>
      {locked && <p className="border-b border-line px-5 py-2.5 text-sm text-warn">User management is disabled for demo accounts.</p>}
      {q.isError ? <ErrorState error={q.error} onRetry={() => q.refetch()} /> : !q.data ? <Skeleton className="m-5 h-24" /> : (
        <ul className="divide-y divide-line">
          {q.data.map((u) => {
            const self = u.id === me?.id;
            const initials = u.display_name.split(/\s+/).map((p) => p[0]).slice(0, 2).join("").toUpperCase();
            return (
              <li key={u.id} className="flex flex-col gap-3 px-5 py-4 md:flex-row md:items-center md:gap-4">
                <div className="flex min-w-0 flex-1 items-center gap-3">
                  <span className="grid size-9 shrink-0 place-items-center rounded-lg bg-accent-soft text-xs font-semibold text-accent">{initials}</span>
                  <div className="min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="truncate text-sm font-medium text-fg">{u.display_name}</span>
                      {self && <span className="rounded-md border border-line-strong px-1.5 py-0.5 text-xs text-muted">You</span>}
                      {!u.is_active && <span className="rounded-md border border-warn/40 bg-warn/10 px-1.5 py-0.5 text-xs text-warn">Deactivated</span>}
                      {u.is_active && u.must_change_password && <span className="rounded-md border border-line-strong px-1.5 py-0.5 text-xs text-muted">Awaiting first sign-in</span>}
                    </div>
                    <p className="truncate text-xs text-muted">{u.email}</p>
                    <p className="text-xs text-muted">Last sign-in {relativeTime(u.last_login_at)}</p>
                  </div>
                </div>
                <div className="flex flex-wrap items-center gap-2 md:shrink-0">
                  <label className="sr-only" htmlFor={`role-${u.id}`}>Role for {u.display_name}</label>
                  <Select id={`role-${u.id}`} className="h-8 w-32 text-sm" value={u.role} disabled={locked || self} onChange={(e) => update.mutate({ id: u.id, body: { role: e.target.value } })}>
                    {["viewer", "analyst", "lead", "admin"].map((r) => <option key={r} value={r}>{r}</option>)}
                  </Select>
                  <Button size="sm" variant="secondary" className="w-28" disabled={locked || self} onClick={() => update.mutate({ id: u.id, body: { is_active: !u.is_active } })}>
                    {u.is_active ? "Deactivate" : "Reactivate"}
                  </Button>
                  <Button size="sm" variant="ghost" icon={<Mail className="size-3.5" aria-hidden />} disabled={locked || !u.is_active || u.is_demo} loading={sendReset.isPending && sendReset.variables?.id === u.id} onClick={() => sendReset.mutate(u)} aria-label={`Send password reset email to ${u.display_name}`}>
                    Reset password
                  </Button>
                  <Button size="sm" variant="danger" icon={<Trash2 className="size-3.5" aria-hidden />} disabled={locked || self} onClick={() => setRemoving(u)} aria-label={`Remove ${u.display_name}`}>
                    Remove
                  </Button>
                </div>
              </li>
            );
          })}
        </ul>
      )}
      <Dialog open={open} onOpenChange={setOpen} title="Add user" description="SentinelForge generates a temporary password and emails it with a one-time link to set their own password (valid 24 hours), their role and workspace details." footer={<Button variant="primary" loading={create.isPending} onClick={() => create.mutate()}>Create and send welcome email</Button>}>
        <div className="space-y-4">
          <Field label="Email" htmlFor="u-email"><Input id="u-email" type="email" value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} /></Field>
          <Field label="Display name" htmlFor="u-name"><Input id="u-name" value={form.display_name} onChange={(e) => setForm({ ...form, display_name: e.target.value })} /></Field>
          <Field label="Role" htmlFor="u-role">
            <Select id="u-role" value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value as Role })}>{["viewer", "analyst", "lead", "admin"].map((r) => <option key={r} value={r}>{r}</option>)}</Select>
          </Field>
        </div>
      </Dialog>
      <ConfirmDialog
        open={!!removing}
        onOpenChange={(o) => !o && setRemoving(null)}
        destructive
        title={`Remove ${removing?.display_name}?`}
        description="They are signed out everywhere and can no longer sign in. Their past notes, approvals and audit entries are kept. The email address can be used for a new account."
        confirmLabel="Remove user"
        loading={remove.isPending}
        onConfirm={() => removing && remove.mutate(removing.id)}
      />
      <UndeliveredDialog value={undelivered} onClose={() => setUndelivered(null)} />
    </Panel>
  );
}

function UndeliveredDialog({ value, onClose }: { value: Undelivered | null; onClose: () => void }) {
  const toast = useToast();
  const copy = (text: string) => { navigator.clipboard?.writeText(text); toast({ kind: "info", title: "Copied to clipboard" }); };
  return (
    <Dialog open={!!value} onOpenChange={(o) => !o && onClose()} title={value?.title ?? ""} description={`Share these with ${value?.email ?? "the user"} over a trusted channel. They are shown only once.`} footer={<Button variant="primary" onClick={onClose}>Done</Button>}>
      {value?.error && <p className="mb-4 rounded-md border border-warn/30 bg-warn/10 px-3 py-2 text-sm text-warn">{value.error}</p>}
      <div className="space-y-4">
        {value?.temporaryPassword && (
          <Field label="Temporary password (must be changed at first sign-in)" htmlFor="u-temp">
            <div className="flex gap-2">
              <Input id="u-temp" readOnly value={value.temporaryPassword} className="mono" onFocus={(e) => e.currentTarget.select()} />
              <Button icon={<Copy className="size-3.5" aria-hidden />} onClick={() => copy(value.temporaryPassword ?? "")}>Copy</Button>
            </div>
          </Field>
        )}
        {value?.link && (
          <Field label="One-time set-password link (24 hours)" htmlFor="u-link">
            <div className="flex gap-2">
              <Input id="u-link" readOnly value={value.link} className="mono" onFocus={(e) => e.currentTarget.select()} />
              <Button icon={<Copy className="size-3.5" aria-hidden />} onClick={() => copy(value.link ?? "")}>Copy</Button>
            </div>
          </Field>
        )}
      </div>
    </Dialog>
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

function ChangePassword() {
  return (
    <Panel title={<span className="flex items-center gap-1.5"><KeyRound className="size-3.5 text-accent" aria-hidden /> Change password</span>} description={`${PASSWORD_RULES} Every other session of yours is signed out.`} id="password">
      <ChangePasswordForm />
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
        {isAdmin && <Users />}
        {me && !me.is_demo && <ChangePassword />}
      </div>
    </>
  );
}
