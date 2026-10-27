export function LogoMark({ className = "size-6" }: { className?: string }) {
  // Original mark: a hexagonal "forge" outline with an inner chevron.
  return (
    <svg viewBox="0 0 32 32" className={className} aria-hidden fill="none">
      <path d="M16 2.5 27.7 9.25v13.5L16 29.5 4.3 22.75V9.25L16 2.5Z" stroke="currentColor" strokeWidth="2.2" strokeLinejoin="round" />
      <path d="m10.5 13.5 5.5 5 5.5-5" stroke="currentColor" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round" />
      <path d="M16 18.5V24" stroke="currentColor" strokeWidth="2.4" strokeLinecap="round" opacity=".55" />
    </svg>
  );
}

export function Logo({ collapsed }: { collapsed?: boolean }) {
  // Laid out like the shadcn/ui sidebar "team switcher" header.
  return (
    <span className="flex items-center gap-2">
      <span className="grid size-8 shrink-0 place-items-center rounded-lg bg-accent text-accent-fg">
        <LogoMark className="size-5" />
      </span>
      {!collapsed && (
        <span className="grid text-left leading-tight">
          <span className="truncate text-sm font-semibold text-fg">SentinelForge</span>
          <span className="truncate text-xs text-muted">Incident response</span>
        </span>
      )}
    </span>
  );
}
