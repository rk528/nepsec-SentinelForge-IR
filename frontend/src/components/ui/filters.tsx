"use client";

import { Search, X } from "lucide-react";
import { useEffect, useState } from "react";

import { cn } from "./primitives";

export function SearchBox({ value, onChange, placeholder, label, delay = 300, className }: { value: string; onChange: (v: string) => void; placeholder: string; label: string; delay?: number; className?: string }) {
  const [draft, setDraft] = useState(value);
  // Resync when the URL value changes from outside (e.g. "Clear filters").
  const [synced, setSynced] = useState(value);
  if (value !== synced) {
    setSynced(value);
    setDraft(value);
  }
  useEffect(() => {
    if (draft === value) return;
    const t = setTimeout(() => onChange(draft), delay);
    return () => clearTimeout(t);
  }, [draft, value, onChange, delay]);
  return (
    <div className={cn("relative w-full sm:w-80", className)}>
      <Search className="pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2 text-subtle" aria-hidden />
      <input
        type="search"
        aria-label={label}
        value={draft}
        onChange={(e) => setDraft(e.target.value)}
        placeholder={placeholder}
        maxLength={200}
        className="h-9 w-full rounded-md border border-line-strong bg-canvas/40 pr-8 pl-9 text-sm text-fg shadow-xs placeholder:text-subtle outline-none focus-visible:border-accent/70 focus-visible:ring-[3px] focus-visible:ring-accent/25 [&::-webkit-search-cancel-button]:hidden"
      />
      {draft && (
        <button type="button" onClick={() => setDraft("")} className="absolute top-1/2 right-1.5 -translate-y-1/2 rounded p-0.5 text-subtle hover:text-fg" aria-label="Clear search">
          <X className="size-3.5" aria-hidden />
        </button>
      )}
    </div>
  );
}

/** Multi-select toggle chips; selection lives in the URL via the parent. */
export function FilterChips<T extends string>({ label, options, selected, onChange }: { label: string; options: { value: T; label: string }[]; selected: string[]; onChange: (v: string[]) => void }) {
  return (
    <div role="group" aria-label={label} className="flex flex-wrap items-center gap-2">
      <span className="text-sm text-muted">{label}</span>
      {/* shadcn/ui ToggleGroup, outline variant */}
      <div className="inline-flex flex-wrap overflow-hidden rounded-md border border-line-strong shadow-xs">
      {options.map((o) => {
        const on = selected.includes(o.value);
        return (
          <button
            key={o.value}
            type="button"
            aria-pressed={on}
            onClick={() => onChange(on ? selected.filter((s) => s !== o.value) : [...selected, o.value])}
            className={cn("h-8 border-l border-line-strong px-3 text-sm transition-colors first:border-l-0", on ? "bg-accent-soft font-medium text-accent" : "text-muted hover:bg-raised/60 hover:text-fg")}
          >
            {o.label}
          </button>
        );
      })}
      </div>
      {selected.length > 0 && (
        <button type="button" onClick={() => onChange([])} className="text-sm text-muted underline-offset-2 hover:text-fg hover:underline">
          Clear
        </button>
      )}
    </div>
  );
}

export function Toolbar({ children }: { children: React.ReactNode }) {
  return <div className="flex flex-col gap-3 border-b border-line px-5 py-4 lg:flex-row lg:flex-wrap lg:items-center lg:gap-x-5">{children}</div>;
}
