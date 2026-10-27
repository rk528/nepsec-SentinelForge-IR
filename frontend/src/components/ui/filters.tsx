"use client";

import { Search, X } from "lucide-react";
import { useEffect, useState } from "react";

import { cn } from "./primitives";

export function SearchBox({ value, onChange, placeholder, label, delay = 300 }: { value: string; onChange: (v: string) => void; placeholder: string; label: string; delay?: number }) {
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
    <div className="relative w-full sm:w-72">
      <Search className="pointer-events-none absolute top-1/2 left-2.5 size-3.5 -translate-y-1/2 text-subtle" aria-hidden />
      <input
        type="search"
        aria-label={label}
        value={draft}
        onChange={(e) => setDraft(e.target.value)}
        placeholder={placeholder}
        maxLength={200}
        className="h-8 w-full rounded-md border border-line-strong bg-surface pr-7 pl-8 text-[13px] text-fg placeholder:text-subtle hover:border-subtle/60 focus:border-accent focus:outline-none [&::-webkit-search-cancel-button]:hidden"
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
    <div role="group" aria-label={label} className="flex flex-wrap items-center gap-1">
      <span className="mr-1 text-[11px] font-medium tracking-wide text-subtle uppercase">{label}</span>
      {options.map((o) => {
        const on = selected.includes(o.value);
        return (
          <button
            key={o.value}
            type="button"
            aria-pressed={on}
            onClick={() => onChange(on ? selected.filter((s) => s !== o.value) : [...selected, o.value])}
            className={cn("h-6 rounded-md border px-2 text-xs transition-colors", on ? "border-accent/50 bg-accent-soft text-fg" : "border-line-strong text-muted hover:text-fg")}
          >
            {o.label}
          </button>
        );
      })}
      {selected.length > 0 && (
        <button type="button" onClick={() => onChange([])} className="ml-1 text-xs text-subtle underline-offset-2 hover:text-fg hover:underline">
          Clear
        </button>
      )}
    </div>
  );
}

export function Toolbar({ children }: { children: React.ReactNode }) {
  return <div className="flex flex-col gap-3 border-b border-line px-4 py-3 lg:flex-row lg:flex-wrap lg:items-center">{children}</div>;
}
