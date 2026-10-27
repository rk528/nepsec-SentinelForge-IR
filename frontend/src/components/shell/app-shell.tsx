"use client";

import * as DropdownMenu from "@radix-ui/react-dropdown-menu";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Command } from "cmdk";
import { ChevronsUpDown, CornerDownLeft, FlaskConical, LogOut, Menu, PanelLeft, Search, Siren, X } from "lucide-react";
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
import { ThemeToggle } from "./theme-toggle";

function Sidebar({ collapsed, onNavigate }: { collapsed: boolean; onNavigate?: () => void }) {
  const pathname = usePathname();
  return (
    <nav aria-label="Primary" className="flex-1 space-y-2 overflow-y-auto px-2 py-2">
      {NAV.map((group) => (
        <div key={group.section}>
          {!collapsed && <p className="flex h-8 items-center px-2 text-xs font-medium text-muted">{group.section}</p>}
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
                      "group flex h-8 items-center gap-2 rounded-md px-2 text-sm transition-colors",
                      active ? "bg-raised font-medium text-fg" : "text-muted hover:bg-raised/70 hover:text-fg",
                      collapsed && "justify-center px-0",
                    )}
                  >
                    <Icon className={cn("size-4 shrink-0", active ? "text-accent" : "text-muted group-hover:text-fg")} aria-hidden />
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

function UserMenu({ variant = "sidebar", collapsed = false }: { variant?: "sidebar" | "header"; collapsed?: boolean }) {
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
      <DropdownMenu.Trigger
        className={cn(
          "flex items-center gap-2 rounded-md text-left outline-none hover:bg-raised focus-visible:ring-2 focus-visible:ring-accent/40 data-[state=open]:bg-raised",
          variant === "sidebar" ? "h-12 w-full p-2" : "p-1",
          collapsed && "justify-center",
        )}
        aria-label="Account menu"
      >
        <span className="grid size-8 shrink-0 place-items-center rounded-lg bg-accent-soft text-xs font-semibold text-accent">{initials}</span>
        {variant === "sidebar" && !collapsed && (
          <>
            <span className="grid min-w-0 flex-1 text-sm leading-tight">
              <span className="truncate font-medium text-fg">{me.display_name}</span>
              <span className="truncate text-xs text-muted capitalize">{me.role}</span>
            </span>
            <ChevronsUpDown className="size-4 shrink-0 text-muted" aria-hidden />
          </>
        )}
      </DropdownMenu.Trigger>
      <DropdownMenu.Portal>
        <DropdownMenu.Content side={variant === "sidebar" ? "right" : "bottom"} align="end" sideOffset={8} className="z-50 min-w-56 rounded-lg border border-line-strong bg-overlay p-1 shadow-xl">
          <div className="flex items-center gap-2 px-2 py-1.5">
            <span className="grid size-8 shrink-0 place-items-center rounded-lg bg-accent-soft text-xs font-semibold text-accent">{initials}</span>
            <div className="grid min-w-0 text-sm leading-tight">
              <span className="truncate font-medium text-fg">{me.display_name}</span>
              <span className="truncate text-xs text-muted">{me.email}</span>
            </div>
          </div>
          <div className="px-2 pb-1.5">
            <p className="text-xs text-muted">
              {me.org_name} · <span className="capitalize">{me.role}</span>
            </p>
          </div>
          <DropdownMenu.Separator className="my-1 h-px bg-line" />
          <DropdownMenu.Item onSelect={logout} disabled={busy} className="flex cursor-pointer items-center gap-2 rounded-md px-2 py-1.5 text-sm text-fg outline-none data-[highlighted]:bg-raised">
            <LogOut className="size-4" aria-hidden />
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
          <Command.Input autoFocus value={query} onValueChange={setQuery} placeholder="Jump to a page or search incidents (e.g. INC-0003, phishing)" className="h-11 flex-1 bg-transparent text-sm text-fg placeholder:text-subtle focus:outline-none" />
          {isFetching && <Spinner label="" />}
        </div>
        <Command.List className="max-h-[50vh] overflow-y-auto p-1.5">
          <Command.Empty className="px-3 py-6 text-center text-xs text-muted">No matches.</Command.Empty>
          {data && data.items.length > 0 && (
            <Command.Group heading="Incidents" className="[&_[cmdk-group-heading]]:px-2 [&_[cmdk-group-heading]]:py-1.5 [&_[cmdk-group-heading]]:text-[10px] [&_[cmdk-group-heading]]:tracking-[0.12em] [&_[cmdk-group-heading]]:text-subtle [&_[cmdk-group-heading]]:uppercase">
              {data.items.map((inc) => (
                <Command.Item key={inc.id} value={`${inc.reference} ${inc.title} ${trimmed}`} onSelect={() => go(`/incidents/${inc.id}`)} className="flex cursor-pointer items-center gap-2.5 rounded-md px-2.5 py-2 text-sm text-fg data-[selected=true]:bg-overlay">
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
                <Command.Item key={item.href} value={`${item.label} ${item.keywords ?? ""}`} onSelect={() => go(item.href)} className="flex cursor-pointer items-center gap-2.5 rounded-md px-2.5 py-2 text-sm text-fg data-[selected=true]:bg-overlay">
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
    <div className="flex items-center justify-center gap-2 border-b border-accent/20 bg-accent-soft px-4 py-1.5 text-center text-xs text-accent md:rounded-t-xl">
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
    <div className="flex min-h-dvh bg-shell">
      <a href="#main" className="sr-only z-50 rounded bg-accent px-3 py-2 text-accent-fg focus:not-sr-only focus:fixed focus:top-2 focus:left-2">
        Skip to content
      </a>
      {/* Desktop sidebar (shadcn/ui Sidebar, variant "inset") */}
      <aside className={cn("no-print sticky top-0 hidden h-dvh shrink-0 flex-col bg-shell transition-[width] duration-200 md:flex", collapsed ? "w-16" : "w-64")}>
        <div className={cn("flex h-14 items-center p-2", collapsed ? "justify-center" : "px-3")}>
          <Link href="/dashboard" aria-label="SentinelForge IR overview" className="rounded-md p-1.5 hover:bg-raised/70">
            <Logo collapsed={collapsed} />
          </Link>
        </div>
        <Sidebar collapsed={collapsed} />
        <div className="p-2">
          <UserMenu collapsed={collapsed} />
        </div>
      </aside>

      {/* Mobile drawer (shadcn/ui Sheet) */}
      {mobileOpen && (
        <div className="fixed inset-0 z-40 md:hidden" role="dialog" aria-modal="true" aria-label="Navigation">
          <div className="absolute inset-0 bg-black/60" onClick={() => setMobileOpen(false)} />
          <aside className="absolute inset-y-0 left-0 flex w-72 flex-col border-r border-line bg-shell animate-slide-up">
            <div className="flex h-14 items-center justify-between px-4">
              <Logo />
              <button type="button" onClick={() => setMobileOpen(false)} className="rounded-md p-1.5 text-muted hover:bg-raised hover:text-fg" aria-label="Close navigation">
                <X className="size-4" aria-hidden />
              </button>
            </div>
            <Sidebar collapsed={false} onNavigate={() => setMobileOpen(false)} />
            <div className="p-2">
              <UserMenu />
            </div>
          </aside>
        </div>
      )}

      {/* Main area (shadcn/ui SidebarInset) */}
      <div className="flex min-w-0 flex-1 flex-col bg-canvas md:my-2 md:mr-2 md:rounded-xl md:border md:border-line md:shadow-sm">
        {me?.is_demo && <SyntheticBanner />}
        <header className="no-print sticky top-0 z-30 flex h-14 shrink-0 items-center gap-2 border-b border-line bg-canvas/90 px-4 backdrop-blur md:px-6">
          <button type="button" onClick={() => setMobileOpen(true)} className="-ml-1 rounded-md p-1.5 text-muted hover:bg-raised hover:text-fg md:hidden" aria-label="Open navigation">
            <Menu className="size-5" aria-hidden />
          </button>
          <button type="button" onClick={toggleCollapsed} className="-ml-1.5 hidden rounded-md p-1.5 text-muted hover:bg-raised hover:text-fg md:inline-flex" aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}>
            <PanelLeft className="size-4" aria-hidden />
          </button>
          <span aria-hidden className="mx-1 hidden h-4 w-px bg-line-strong md:block" />
          <button
            type="button"
            onClick={() => setPaletteOpen(true)}
            className="flex h-9 w-full max-w-sm items-center gap-2 rounded-md border border-line-strong bg-surface/60 px-3 text-left text-sm text-muted shadow-xs transition-colors hover:bg-raised hover:text-fg"
            aria-label="Search and jump (Ctrl+K)"
          >
            <Search className="size-4" aria-hidden />
            <span className="flex-1 truncate">Search incidents or jump to…</span>
            <span className="hidden sm:inline">
              <Kbd>Ctrl K</Kbd>
            </span>
          </button>
          <div className="ml-auto flex items-center gap-2">
            {me && <span className="mr-1 hidden max-w-56 truncate text-sm text-muted xl:inline">{me.org_name}</span>}
            <ThemeToggle />
            <div className="md:hidden">
              <UserMenu variant="header" />
            </div>
          </div>
        </header>
        <main id="main" className="mx-auto w-full max-w-[1400px] flex-1 px-4 py-6 md:px-8 md:py-8">
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
