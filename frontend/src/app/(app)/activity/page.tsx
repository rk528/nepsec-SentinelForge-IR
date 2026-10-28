"use client";

import { useQuery } from "@tanstack/react-query";
import { KeyRound, LogIn, LogOut, ScrollText, ShieldAlert, SquareTerminal, Usb, UserCog, UserSearch, type LucideIcon } from "lucide-react";
import { Suspense, useState } from "react";

import { EventDialog } from "@/components/investigation";
import { Pagination } from "@/components/ui/data-table";
import { SearchBox } from "@/components/ui/filters";
import { EmptyState, ErrorState, PageHeader, Panel, Segmented, Select, Skeleton, SkeletonRows, cn } from "@/components/ui/primitives";
import { api } from "@/lib/api";
import { formatTime, plural, relativeTime, utcTitle } from "@/lib/format";
import { useUrlState } from "@/lib/hooks";
import type { EventRecord, Page } from "@/lib/types";

interface ActiveUser {
  user: string;
  events: number;
  commands: number;
  sign_ins: number;
  failures: number;
  account_changes: number;
  devices: number;
  last_seen: string;
  hosts: string[];
}

const RANGES = [
  { value: "24", label: "24h" },
  { value: "168", label: "7d" },
  { value: "720", label: "30d" },
];

// What each filter shows. "All activity" leaves out raw log lines, which have their own filter.
const KINDS: { value: string; label: string; types: string[] }[] = [
  {
    value: "",
    label: "All activity",
    types: ["auth.success", "auth.failure", "session.ended", "process.start", "iam.user_created", "iam.group_member_added", "device.connected", "service.stopped", "log.cleared", "task.created", "registry.set", "process.access", "network.connection", "dns.query", "proxy.request", "file.created", "security.alert", "email.delivered"],
  },
  { value: "sessions", label: "Sign-ins", types: ["auth.success", "auth.failure", "session.ended"] },
  { value: "commands", label: "Commands", types: ["process.start"] },
  { value: "changes", label: "System changes", types: ["iam.user_created", "iam.group_member_added", "service.stopped", "log.cleared", "task.created", "registry.set"] },
  { value: "devices", label: "Devices", types: ["device.connected"] },
  { value: "logs", label: "Log lines", types: ["system.log"] },
];

const ICONS: Record<string, { icon: LucideIcon; tone: string }> = {
  "auth.success": { icon: LogIn, tone: "text-ok" },
  "auth.failure": { icon: KeyRound, tone: "text-danger" },
  "session.ended": { icon: LogOut, tone: "text-muted" },
  "process.start": { icon: SquareTerminal, tone: "text-accent" },
  "iam.user_created": { icon: UserCog, tone: "text-warn" },
  "iam.group_member_added": { icon: UserCog, tone: "text-warn" },
  "device.connected": { icon: Usb, tone: "text-warn" },
  "system.log": { icon: ScrollText, tone: "text-subtle" },
};

function str(raw: Record<string, unknown> | null, key: string): string | null {
  const v = raw?.[key];
  return typeof v === "string" && v ? v : null;
}

/** One plain sentence per event, as an analyst would read it out. */
function describe(e: EventRecord, user: string): { text: string; code?: string; context?: string } {
  const where = e.host ? ` on ${e.host}` : "";
  switch (e.event_type) {
    case "process.start": {
      const asOther = e.target_user && e.target_user !== user ? ` as ${e.target_user}` : "";
      const cwd = str(e.raw, "cwd");
      const via = e.parent_process === "sudo" ? " with sudo" : "";
      return { text: `Ran${asOther}${via}`, code: e.command_line ?? e.process_name ?? "", context: [cwd && `in ${cwd}`, e.host].filter(Boolean).join(" · ") };
    }
    case "auth.success": {
      const how = str(e.raw, "logon") ?? str(e.raw, "pam_service");
      if (e.target_user && e.user_name === user && e.target_user !== user) return { text: `Switched to ${e.target_user}${where}` };
      return { text: `Signed in${how ? ` (${how})` : ""}${e.src_ip ? ` from ${e.src_ip}` : ""}${where}` };
    }
    case "auth.failure":
      return { text: `${e.outcome === "denied" ? "Was denied" : "Failed to sign in"}${e.src_ip ? ` from ${e.src_ip}` : ""}${where}`, context: str(e.raw, "pam_service") ?? undefined };
    case "session.ended":
      return { text: `Signed out${where}` };
    case "iam.user_created":
      return { text: e.user_name === user ? `Created account ${e.target_user ?? "?"}${where}` : `Account created${where}` };
    case "iam.group_member_added":
      return { text: e.user_name === user ? `Added ${e.target_user ?? "?"} to ${e.group_name ?? "a group"}${where}` : `Added to ${e.group_name ?? "a group"}${where}` };
    case "device.connected":
      return { text: `USB device connected${where}`, context: [str(e.raw, "vendor_id") && `vendor ${str(e.raw, "vendor_id")}`, str(e.raw, "product_id") && `product ${str(e.raw, "product_id")}`].filter(Boolean).join(", ") };
    case "system.log":
      return { text: e.process_name ?? "log", code: e.message ?? "", context: e.host ?? undefined };
    default:
      return { text: `${e.event_type}${where}`, code: e.command_line ?? e.message ?? undefined };
  }
}

function dayLabel(iso: string) {
  return new Date(iso).toLocaleDateString(undefined, { weekday: "long", day: "numeric", month: "long" });
}

function UserList({ users, selected, onSelect }: { users: ActiveUser[]; selected: string; onSelect: (u: string) => void }) {
  return (
    <ul className="divide-y divide-line" aria-label="People seen">
      {users.map((u) => (
        <li key={u.user}>
          <button
            type="button"
            onClick={() => onSelect(u.user)}
            aria-current={u.user === selected ? "true" : undefined}
            className={cn("block w-full px-4 py-2.5 text-left transition-colors hover:bg-raised/60", u.user === selected && "bg-accent/10")}
          >
            <span className="flex items-center justify-between gap-2">
              <span className={cn("mono truncate text-sm", u.user === selected ? "text-accent" : "text-fg")}>{u.user}</span>
              <span className="shrink-0 text-xs text-subtle" title={utcTitle(u.last_seen)}>{relativeTime(u.last_seen)}</span>
            </span>
            <span className="mt-0.5 flex flex-wrap gap-x-3 text-xs text-muted">
              {u.commands > 0 && <span>{plural(u.commands, "command")}</span>}
              {u.sign_ins > 0 && <span>{plural(u.sign_ins, "sign-in")}</span>}
              {u.failures > 0 && <span className="text-danger">{plural(u.failures, "failure")}</span>}
              {u.account_changes > 0 && <span className="text-warn">{plural(u.account_changes, "account change")}</span>}
              {u.commands + u.sign_ins + u.failures + u.account_changes === 0 && <span>{plural(u.events, "event")}</span>}
            </span>
            {u.hosts.length > 0 && <span className="mono mt-0.5 block truncate text-xs text-subtle">{u.hosts.join(", ")}</span>}
          </button>
        </li>
      ))}
    </ul>
  );
}

function Timeline({ user, hours, kind, host, page, onPage, onOpen }: { user: string; hours: string; kind: string; host: string; page: number; onPage: (p: number) => void; onOpen: (e: EventRecord) => void }) {
  const types = (KINDS.find((k) => k.value === kind) ?? KINDS[0]).types;
  const q = useQuery({
    queryKey: ["activity", { user, hours, kind, host, page }],
    queryFn: ({ signal }) => api<Page<EventRecord>>("/events", { query: { user, hours, host: host || undefined, event_type: types, page, page_size: 100 }, signal }),
    placeholderData: (prev) => prev,
  });
  if (q.isError) return <ErrorState error={q.error} onRetry={() => q.refetch()} />;
  if (!q.data) return <SkeletonRows rows={8} />;
  if (q.data.items.length === 0)
    return <EmptyState title="Nothing in this view" description={kind === "commands" ? "Commands appear when the machine ships with full capture (install.sh --capture all, or -CaptureAll on Windows)." : "Widen the time range or choose another filter."} />;

  const groups: { day: string; items: EventRecord[] }[] = [];
  for (const e of q.data.items) {
    const day = dayLabel(e.event_time);
    if (groups.at(-1)?.day !== day) groups.push({ day, items: [] });
    groups.at(-1)!.items.push(e);
  }
  return (
    <>
      {groups.map((g) => (
        <section key={g.day} aria-label={g.day}>
          <h3 className="sticky top-0 z-[1] border-b border-line bg-surface/95 px-5 py-2 text-xs font-medium tracking-wide text-subtle uppercase backdrop-blur">{g.day}</h3>
          <ol className="divide-y divide-line/70">
            {g.items.map((e) => {
              const d = describe(e, user);
              const { icon: Icon, tone } = ICONS[e.event_type] ?? { icon: ShieldAlert, tone: "text-muted" };
              return (
                <li key={e.id}>
                  <button type="button" onClick={() => onOpen(e)} className="flex w-full items-start gap-3 px-5 py-2 text-left hover:bg-raised/40">
                    <span className="mono w-20 shrink-0 pt-0.5 text-xs whitespace-nowrap text-subtle" title={utcTitle(e.event_time)}>{formatTime(e.event_time)}</span>
                    <Icon className={cn("mt-0.5 size-4 shrink-0", tone)} aria-hidden />
                    <span className="min-w-0 flex-1">
                      <span className="text-sm text-fg">{d.text}</span>
                      {d.code && <code className="mono ml-2 inline-block max-w-full truncate rounded bg-raised px-1.5 py-px align-bottom text-xs text-fg" title={d.code}>{d.code}</code>}
                      {d.context && <span className="mono block truncate text-xs text-subtle">{d.context}</span>}
                    </span>
                  </button>
                </li>
              );
            })}
          </ol>
        </section>
      ))}
      <Pagination page={page} pageSize={100} total={q.data.total} onPage={onPage} />
    </>
  );
}

function Activity() {
  const url = useUrlState();
  const hours = url.get("hours", "24");
  const search = url.get("q");
  const kind = url.get("kind");
  const host = url.get("host");
  const page = Number(url.get("page", "1")) || 1;
  const [open, setOpen] = useState<EventRecord | null>(null);

  const users = useQuery({ queryKey: ["activity-users", { hours, search }], queryFn: () => api<ActiveUser[]>("/events/users", { query: { hours, q: search || undefined } }), placeholderData: (prev) => prev });
  const selected = url.get("user") || users.data?.[0]?.user || "";
  const current = users.data?.find((u) => u.user === selected);

  return (
    <>
      <PageHeader
        title="User activity"
        description="Everything one person did, in order: sign-ins, commands, privilege use, devices and sign-outs. Select an entry for the full event."
        actions={<Segmented label="Time range" value={hours} options={RANGES} onChange={(v) => url.set({ hours: v })} />}
      />
      <div className="grid gap-4 lg:grid-cols-[18rem_minmax(0,1fr)]">
        <Panel bodyClassName="p-0" className="self-start lg:sticky lg:top-20">
          <div className="border-b border-line p-3">
            <SearchBox label="Find a person" placeholder="Find a user" className="sm:w-full" value={search} onChange={(v) => url.set({ q: v })} />
          </div>
          {users.isError ? (
            <ErrorState error={users.error} onRetry={() => users.refetch()} />
          ) : !users.data ? (
            <Skeleton className="m-3 h-40" />
          ) : users.data.length === 0 ? (
            <EmptyState icon={<UserSearch className="size-5" aria-hidden />} title="No one seen" description="No events with a user in this time range." />
          ) : (
            <div className="max-h-[70vh] overflow-y-auto">
              <UserList users={users.data} selected={selected} onSelect={(u) => url.set({ user: u, host: null })} />
            </div>
          )}
        </Panel>

        <Panel
          bodyClassName="p-0"
          title={selected ? <span className="mono">{selected}</span> : "Activity"}
          description={current ? `${plural(current.events, "event")} on ${plural(current.hosts.length, "machine")} · last seen ${relativeTime(current.last_seen)}` : undefined}
          actions={
            current && current.hosts.length > 1 ? (
              <>
                <label htmlFor="act-host" className="sr-only">Machine</label>
                <Select id="act-host" className="w-48" value={host} onChange={(e) => url.set({ host: e.target.value || null })}>
                  <option value="">All machines</option>
                  {current.hosts.map((h) => <option key={h} value={h}>{h}</option>)}
                </Select>
              </>
            ) : undefined
          }
        >
          <div className="flex flex-wrap gap-1.5 border-b border-line px-5 py-3" role="radiogroup" aria-label="Show">
            {KINDS.map((k) => (
              <button
                key={k.value}
                type="button"
                role="radio"
                aria-checked={kind === k.value}
                onClick={() => url.set({ kind: k.value || null })}
                className={cn("rounded-md border px-2.5 py-1 text-xs transition-colors", kind === k.value ? "border-accent/50 bg-accent/15 text-accent" : "border-line text-muted hover:bg-raised hover:text-fg")}
              >
                {k.label}
              </button>
            ))}
          </div>
          {selected ? (
            <Timeline user={selected} hours={hours} kind={kind} host={host} page={page} onPage={(p) => url.set({ page: p }, { resetPage: false })} onOpen={setOpen} />
          ) : (
            <EmptyState title="Choose a person" description="Pick someone from the list to see what they did." />
          )}
        </Panel>
      </div>
      <EventDialog event={open} onClose={() => setOpen(null)} />
    </>
  );
}

export default function ActivityPage() {
  return (
    <Suspense>
      <Activity />
    </Suspense>
  );
}
