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
  return (
    <span className="flex items-center gap-2.5">
      <span className="text-accent">
        <LogoMark />
      </span>
      {!collapsed && (
        <span className="leading-none">
          <span className="block text-[13px] font-semibold tracking-tight text-fg">SentinelForge</span>
          <span className="block text-[10px] font-medium tracking-[0.14em] text-subtle uppercase">Incident Response</span>
        </span>
      )}
    </span>
  );
}
