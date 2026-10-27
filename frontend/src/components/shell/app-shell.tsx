"use client";

import * as DropdownMenu from "@radix-ui/react-dropdown-menu";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Command } from "cmdk";
import { ChevronsLeft, ChevronsRight, CornerDownLeft, FlaskConical, LogOut, Menu, Search, Siren, X } from "lucide-react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useEffect, useState, useSyncExternalStore, type ReactNode } from "react";

import { api } from "@/lib/api";
import { useMe } from "@/lib/hooks";
import type { Incident, Page } from "@/lib/types";

import { SeverityBadge } from "../ui/badges";
import { Kbd, Spinner, cn } from "../ui/primitives";
import { Logo } from "./logo";
import { NAV } from "./nav";

function Sidebar({ collapsed, onNavigate }: { collapsed: boolean; onNavigate?: () => void }) {
  const pathname = usePathname();
  return (
    <nav aria-label="Primary" className="flex-1 space-y-5 overflow-y-auto px-2 py-4">
      {NAV.map((group) => (
        <div key={group.section}>
          {!collapsed && <p className="mb-1.5 px-2.5 text-[10px] font-semibold tracking-[0.12em] text-subtle uppercase">{group.section}</p>}
          <ul className="space-y-0.5">
            {group.items.map((item) => {
              const active = pathname === item.href || pathname.startsWith(`${item.href}/`);
              const Icon = item.icon;
              return (
                <li key={item.href}>
                  <Link
                    href={item.href}
                    onClick={onNavigate}
                    aria-current={active ? "page" : undefined}
                    title={collapsed ? item.label : undefined}
                    className={cn(
                      "group flex h-8 items-center gap-2.5 rounded-md px-2.5 text-[13px] transition-colors",
                      active ? "bg-raised text-fg shadow-[inset_2px_0_0_var(--color-accent)]" : "text-muted hover:bg-raised/60 hover:text-fg",
                      collapsed && "justify-center px-0",
                    )}
                  >
                    <Icon className={cn("size-4 shrink-0", active ? "text-accent" : "text-subtle group-hover:text-muted")} aria-hidden />
                    {!collapsed && <span className="truncate">{item.label}</span>}
                  </Link>
                </li>
              );
            })}
          </ul>
        </div>
      ))}
    </nav>
  );
}

function UserMenu() {
  const { data: me } = useMe();
  const qc = useQueryClient();
  const router = useRouter();
  const [busy, setBusy] = useState(false);
  if (!me) return <div className="skeleton size-7 rounded-full" aria-hidden />;
  const initials = me.display_name
    .split(/\s+/)
    .map((p) => p[0])
    .slice(0, 2)
    .join("")
    .toUpperCase();
  async function logout() {
    setBusy(true);
    try {
      await api("/auth/logout", { method: "POST" });
    } finally {
      qc.clear();
      router.replace("/login");
    }
  }
  return (
    <DropdownMenu.Root>
      <DropdownMenu.Trigger className="flex items-center gap-2 rounded-md px-1.5 py-1 hover:bg-raised" aria-label="Account menu">
        <span className="grid size-7 place-items-center rounded-full bg-accent-soft text-[11px] font-semibold text-accent">{initials}</span>
        <span className="hidden text-left leading-tight lg:block">
          <span className="block text-xs text-fg">{me.display_name}</span>
          <span className="block text-[11px] text-subtle capitalize">{me.role}</span>
        </span>
      </DropdownMenu.Trigger>
      <DropdownMenu.Portal>
        <DropdownMenu.Content align="end" sideOffset={6} className="z-50 min-w-56 rounded-lg border border-line-strong bg-overlay p-1 shadow-xl">
          <div className="px-2.5 py-2">
            <p className="text-xs font-medium text-fg">{me.display_name}</p>
            <p className="truncate text-[11px] text-subtle">{me.email}</p>
            <p className="mt-1 text-[11px] text-muted">
              {me.org_name} · <span className="capitalize">{me.role}</span>
            </p>
          </div>
          <DropdownMenu.Separator className="my-1 h-px bg-line" />
          <DropdownMenu.Item onSelect={logout} disabled={busy} className="flex cursor-pointer items-center gap-2 rounded-md px-2.5 py-1.5 text-xs text-fg outline-none data-[highlighted]:bg-raised">
            <LogOut className="size-3.5" aria-hidden />
            Sign out
          </DropdownMenu.Item>
        </DropdownMenu.Content>
      </DropdownMenu.Portal>
    </DropdownMenu.Root>
  );
}

function CommandPalette({ open, setOpen }: { open: boolean; setOpen: (o: boolean) => void }) {
  const router = useRouter();
  const [query, setQuery] = useState("");
  const trimmed = query.trim();
  const { data, isFetching } = useQuery({
    queryKey: ["palette-incidents", trimmed],
    queryFn: ({ signal }) => api<Page<Incident>>("/incidents", { query: { q: trimmed, page_size: 6 }, signal }),
    enabled: open && trimmed.length >= 2,
  });
  function go(href: string) {
    setOpen(false);
    setQuery("");
    router.push(href);
  }
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center bg-black/60 px-4 pt-[12vh] animate-fade-in" onMouseDown={() => setOpen(false)}>
      <Command
        label="Command palette"
        loop
        shouldFilter={true}
        onMouseDown={(e) => e.stopPropagation()}
        onKeyDown={(e) => e.key === "Escape" && setOpen(false)}
        className="w-full max-w-xl overflow-hidden rounded-xl border border-line-strong bg-raised shadow-2xl animate-slide-up"
      >
        <div className="flex items-center gap-2 border-b border-line px-3.5">
          <Search className="size-4 text-subtle" aria-hidden />
          <Command.Input autoFocus value={query} onValueChange={setQuery} placeholder="Jump to a page or search incidents (e.g. INC-0003, phishing)" className="h-11 flex-1 bg-transparent text-[13px] text-fg placeholder:text-subtle focus:outline-none" />
          {isFetching && <Spinner label="" />}
        </div>
        <Command.List className="max-h-[50vh] overflow-y-auto p-1.5">
          <Command.Empty className="px-3 py-6 text-center text-xs text-muted">No matches.</Command.Empty>
          {data && data.items.length > 0 && (
            <Command.Group heading="Incidents" className="[&_[cmdk-group-heading]]:px-2 [&_[cmdk-group-heading]]:py-1.5 [&_[cmdk-group-heading]]:text-[10px] [&_[cmdk-group-heading]]:tracking-[0.12em] [&_[cmdk-group-heading]]:text-subtle [&_[cmdk-group-heading]]:uppercase">
              {data.items.map((inc) => (
                <Command.Item key={inc.id} value={`${inc.reference} ${inc.title} ${trimmed}`} onSelect={() => go(`/incidents/${inc.id}`)} className="flex cursor-pointer items-center gap-2.5 rounded-md px-2.5 py-2 text-[13px] text-fg data-[selected=true]:bg-overlay">
                  <Siren className="size-4 text-subtle" aria-hidden />
                  <span className="mono text-xs text-muted">{inc.reference}</span>
                  <span className="flex-1 truncate">{inc.title}</span>
                  <SeverityBadge severity={inc.severity} compact />
                </Command.Item>
              ))}
            </Command.Group>
          )}
          {NAV.map((group) => (
            <Command.Group key={group.section} heading={group.section} className="[&_[cmdk-group-heading]]:px-2 [&_[cmdk-group-heading]]:py-1.5 [&_[cmdk-group-heading]]:text-[10px] [&_[cmdk-group-heading]]:tracking-[0.12em] [&_[cmdk-group-heading]]:text-subtle [&_[cmdk-group-heading]]:uppercase">
              {group.items.map((item) => (
                <Command.Item key={item.href} value={`${item.label} ${item.keywords ?? ""}`} onSelect={() => go(item.href)} className="flex cursor-pointer items-center gap-2.5 rounded-md px-2.5 py-2 text-[13px] text-fg data-[selected=true]:bg-overlay">
                  <item.icon className="size-4 text-subtle" aria-hidden />
                  <span className="flex-1">{item.label}</span>
                  <CornerDownLeft className="size-3 text-subtle opacity-0 [[data-selected=true]_&]:opacity-100" aria-hidden />
                </Command.Item>
              ))}
            </Command.Group>
          ))}
        </Command.List>
      </Command>
    </div>
  );
}

function SyntheticBanner() {
  return (
    <div className="flex items-center justify-center gap-2 border-b border-accent/20 bg-accent-soft px-4 py-1.5 text-center text-xs text-accent">
      <FlaskConical className="size-3.5 shrink-0" aria-hidden />
      <span>
        Demo workspace. All events, alerts and incidents are <strong className="font-semibold">synthetic</strong>; response actions are simulated.
      </span>
    </div>
  );
}

const SIDEBAR_KEY = "sf.sidebar";
const sidebarListeners = new Set<() => void>();

function readSidebar(): boolean {
  try {
    return localStorage.getItem(SIDEBAR_KEY) === "collapsed";
  } catch {
    return false; // storage unavailable (private mode, blocked site data)
  }
}

function writeSidebar(collapsed: boolean) {
  try {
    localStorage.setItem(SIDEBAR_KEY, collapsed ? "collapsed" : "expanded");
  } catch {
    /* ignore */
  }
  sidebarListeners.forEach((l) => l());
}

function subscribeSidebar(listener: () => void) {
  sidebarListeners.add(listener);
  return () => sidebarListeners.delete(listener);
}

export function AppShell({ children }: { children: ReactNode }) {
  const collapsed = useSyncExternalStore(subscribeSidebar, readSidebar, () => false);
  const [mobileOpen, setMobileOpen] = useState(false);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const { data: me, isPending } = useMe();

  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setPaletteOpen((o) => !o);
      }
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  function toggleCollapsed() {
    writeSidebar(!collapsed);
  }

  return (
    <div className="flex min-h-dvh">
      <a href="#main" className="sr-only z-50 rounded bg-accent px-3 py-2 text-accent-fg focus:not-sr-only focus:fixed focus:top-2 focus:left-2">
        Skip to content
      </a>
      {/* Desktop sidebar */}
      <aside className={cn("no-print sticky top-0 hidden h-dvh shrink-0 flex-col border-r border-line bg-surface transition-[width] duration-200 md:flex", collapsed ? "w-14" : "w-60")}>
        <div className={cn("flex h-14 items-center border-b border-line", collapsed ? "justify-center" : "px-4")}>
          <Link href="/dashboard" aria-label="SentinelForge IR overview">
            <Logo collapsed={collapsed} />
          </Link>
        </div>
        <Sidebar collapsed={collapsed} />
        <button type="button" onClick={toggleCollapsed} className="flex h-10 items-center justify-center gap-2 border-t border-line text-xs text-subtle hover:text-fg" aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}>
          {collapsed ? <ChevronsRight className="size-4" aria-hidden /> : <ChevronsLeft className="size-4" aria-hidden />}
          {!collapsed && "Collapse"}
        </button>
      </aside>

      {/* Mobile drawer */}
      {mobileOpen && (
        <div className="fixed inset-0 z-40 md:hidden" role="dialog" aria-modal="true" aria-label="Navigation">
          <div className="absolute inset-0 bg-black/60" onClick={() => setMobileOpen(false)} />
          <aside className="absolute inset-y-0 left-0 flex w-64 flex-col border-r border-line bg-surface animate-slide-up">
            <div className="flex h-14 items-center justify-between border-b border-line px-4">
              <Logo />
              <button type="button" onClick={() => setMobileOpen(false)} className="rounded p-1 text-subtle hover:text-fg" aria-label="Close navigation">
                <X className="size-4" aria-hidden />
              </button>
            </div>
            <Sidebar collapsed={false} onNavigate={() => setMobileOpen(false)} />
          </aside>
        </div>
      )}

      <div className="flex min-w-0 flex-1 flex-col">
        {me?.is_demo && <SyntheticBanner />}
        <header className="no-print sticky top-0 z-30 flex h-14 items-center gap-3 border-b border-line bg-canvas/85 px-4 backdrop-blur md:px-6">
          <button type="button" onClick={() => setMobileOpen(true)} className="rounded p-1.5 text-muted hover:bg-raised hover:text-fg md:hidden" aria-label="Open navigation">
            <Menu className="size-5" aria-hidden />
          </button>
          <button
            type="button"
            onClick={() => setPaletteOpen(true)}
            className="flex h-8 w-full max-w-md items-center gap-2 rounded-md border border-line-strong bg-surface px-2.5 text-left text-[13px] text-subtle transition-colors hover:border-subtle/60"
            aria-label="Search and jump (Ctrl+K)"
          >
            <Search className="size-3.5" aria-hidden />
            <span className="flex-1 truncate">Search incidents or jump to…</span>
            <span className="hidden sm:inline">
              <Kbd>Ctrl K</Kbd>
            </span>
          </button>
          <div className="ml-auto flex items-center gap-2">
            {me && <span className="hidden max-w-48 truncate text-xs text-subtle xl:inline">{me.org_name}</span>}
            <UserMenu />
          </div>
        </header>
        <main id="main" className="mx-auto w-full max-w-[1440px] flex-1 px-4 py-6 md:px-6">
          {isPending ? (
            <div className="grid place-items-center py-24">
              <Spinner label="Loading workspace" />
            </div>
          ) : (
            children
          )}
        </main>
      </div>
      <CommandPalette open={paletteOpen} setOpen={setPaletteOpen} />
    </div>
  );
}
