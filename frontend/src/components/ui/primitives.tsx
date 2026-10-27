"use client";

import { clsx } from "clsx";
import { AlertTriangle, Inbox, Loader2, RotateCw } from "lucide-react";
import Link from "next/link";
import { forwardRef, type ButtonHTMLAttributes, type InputHTMLAttributes, type ReactNode, type SelectHTMLAttributes, type TextareaHTMLAttributes } from "react";

export const cn = clsx;

// --- Button -------------------------------------------------------------------------

type Variant = "primary" | "secondary" | "ghost" | "danger";
type Size = "sm" | "md";

const variants: Record<Variant, string> = {
  primary: "bg-accent text-accent-fg shadow-xs hover:bg-accent-hover",
  secondary: "border border-line-strong bg-canvas/40 text-fg shadow-xs hover:bg-raised",
  ghost: "text-muted hover:bg-raised hover:text-fg",
  danger: "border border-danger/40 bg-danger/10 text-danger shadow-xs hover:bg-danger/20",
};
// shadcn/ui button sizes: sm h-8, default h-9.
const sizes: Record<Size, string> = { sm: "h-8 px-3 text-xs gap-1.5 [&_svg]:size-3.5", md: "h-9 px-4 text-sm gap-2 [&_svg]:size-4" };

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
  size?: Size;
  loading?: boolean;
  icon?: ReactNode;
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  { variant = "secondary", size = "md", loading, icon, className, children, disabled, type = "button", ...rest },
  ref,
) {
  return (
    <button
      ref={ref}
      type={type}
      disabled={disabled || loading}
      aria-busy={loading || undefined}
      className={cn(
        "inline-flex shrink-0 items-center justify-center rounded-md font-medium whitespace-nowrap transition-[color,background-color,box-shadow] outline-none focus-visible:ring-[3px] focus-visible:ring-accent/40 disabled:pointer-events-none disabled:opacity-50",
        variants[variant],
        sizes[size],
        className,
      )}
      {...rest}
    >
      {loading ? <Loader2 className="size-3.5 animate-spin" aria-hidden /> : icon}
      {children}
    </button>
  );
});

export function ButtonLink({ href, children, variant = "secondary", size = "md", icon, className }: { href: string; children: ReactNode; variant?: Variant; size?: Size; icon?: ReactNode; className?: string }) {
  return (
    <Link href={href} className={cn("inline-flex items-center justify-center rounded-md font-medium whitespace-nowrap transition-colors", variants[variant], sizes[size], className)}>
      {icon}
      {children}
    </Link>
  );
}

// --- Form controls ---------------------------------------------------------------------

const field = "w-full min-w-0 rounded-md border border-line-strong bg-canvas/40 px-3 text-sm text-fg shadow-xs placeholder:text-subtle transition-[color,box-shadow,border-color] outline-none focus-visible:border-accent/70 focus-visible:ring-[3px] focus-visible:ring-accent/25 aria-invalid:border-danger disabled:opacity-50";

export const Input = forwardRef<HTMLInputElement, InputHTMLAttributes<HTMLInputElement>>(function Input({ className, ...rest }, ref) {
  return <input ref={ref} className={cn(field, "h-9", className)} {...rest} />;
});

export const Textarea = forwardRef<HTMLTextAreaElement, TextareaHTMLAttributes<HTMLTextAreaElement>>(function Textarea({ className, ...rest }, ref) {
  return <textarea ref={ref} className={cn(field, "min-h-20 py-2 leading-relaxed", className)} {...rest} />;
});

export const Select = forwardRef<HTMLSelectElement, SelectHTMLAttributes<HTMLSelectElement>>(function Select({ className, children, ...rest }, ref) {
  return (
    <select ref={ref} className={cn(field, "h-9 pr-8", className)} {...rest}>
      {children}
    </select>
  );
});

export function Field({ label, htmlFor, hint, error, children, className }: { label: string; htmlFor: string; hint?: string; error?: string; children: ReactNode; className?: string }) {
  return (
    <div className={cn("space-y-1.5", className)}>
      <label htmlFor={htmlFor} className="block text-sm font-medium text-fg">
        {label}
      </label>
      {children}
      {error ? (
        <p role="alert" className="text-xs text-danger">
          {error}
        </p>
      ) : hint ? (
        <p className="text-xs text-subtle">{hint}</p>
      ) : null}
    </div>
  );
}

// --- Surfaces -------------------------------------------------------------------------------

export function Panel({ title, description, actions, children, className, bodyClassName, id }: { title?: ReactNode; description?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string; bodyClassName?: string; id?: string }) {
  return (
    <section aria-labelledby={title && id ? `${id}-title` : undefined} className={cn("flex min-w-0 flex-col rounded-xl border border-line bg-surface shadow-sm", className)}>
      {(title || actions) && (
        <header className="flex items-start justify-between gap-3 border-b border-line px-5 py-4">
          <div className="min-w-0 space-y-1.5">
            {title && (
              <h2 id={id ? `${id}-title` : undefined} className="text-sm leading-none font-semibold text-fg">
                {title}
              </h2>
            )}
            {description && <p className="text-sm text-muted">{description}</p>}
          </div>
          {actions && <div className="flex shrink-0 items-center gap-2">{actions}</div>}
        </header>
      )}
      {/* bodyClassName replaces the default padding (clsx does not merge conflicting Tailwind classes). */}
      <div className={cn("min-w-0 flex-1", bodyClassName ?? "p-5")}>{children}</div>
    </section>
  );
}

export function KeyValue({ items, columns = 2 }: { items: { label: string; value: ReactNode; mono?: boolean }[]; columns?: 1 | 2 | 3 }) {
  return (
    <dl className={cn("grid gap-x-6 gap-y-3", columns === 1 ? "grid-cols-1" : columns === 2 ? "grid-cols-1 sm:grid-cols-2" : "grid-cols-1 sm:grid-cols-2 lg:grid-cols-3")}>
      {items.map((item) => (
        <div key={item.label} className="min-w-0">
          <dt className="text-xs text-muted">{item.label}</dt>
          <dd className={cn("mt-1 truncate text-sm font-medium text-fg", item.mono && "mono")} title={typeof item.value === "string" ? item.value : undefined}>
            {item.value ?? "—"}
          </dd>
        </div>
      ))}
    </dl>
  );
}

export function Kbd({ children }: { children: ReactNode }) {
  return <kbd className="rounded border border-line-strong bg-raised px-1.5 py-0.5 font-mono text-[10px] text-muted">{children}</kbd>;
}

// --- States --------------------------------------------------------------------------------

export function Skeleton({ className }: { className?: string }) {
  return <div aria-hidden className={cn("skeleton h-4", className)} />;
}

export function SkeletonRows({ rows = 6, cols = 5 }: { rows?: number; cols?: number }) {
  return (
    <div role="status" aria-label="Loading" className="divide-y divide-line">
      {Array.from({ length: rows }).map((_, r) => (
        <div key={r} className="flex items-center gap-4 px-4 py-3">
          {Array.from({ length: cols }).map((__, c) => (
            <Skeleton key={c} className={cn("h-3.5", c === 1 ? "flex-[3]" : "flex-1")} />
          ))}
        </div>
      ))}
    </div>
  );
}

export function EmptyState({ title, description, action, icon }: { title: string; description?: ReactNode; action?: ReactNode; icon?: ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center px-6 py-12 text-center">
      <div className="mb-3 rounded-lg border border-line bg-raised p-2.5 text-muted">{icon ?? <Inbox className="size-5" aria-hidden />}</div>
      <p className="text-sm font-medium text-fg">{title}</p>
      {description && <p className="mt-1 max-w-sm text-xs text-muted">{description}</p>}
      {action && <div className="mt-4">{action}</div>}
    </div>
  );
}

export function ErrorState({ error, onRetry, title = "Could not load this data" }: { error: unknown; onRetry?: () => void; title?: string }) {
  const message = error instanceof Error ? error.message : "Unexpected error";
  const requestId = (error as { requestId?: string } | null)?.requestId;
  return (
    <div role="alert" className="flex flex-col items-center justify-center px-6 py-10 text-center">
      <div className="mb-3 rounded-full border border-danger/30 bg-danger/10 p-2.5 text-danger">
        <AlertTriangle className="size-5" aria-hidden />
      </div>
      <p className="text-sm font-medium text-fg">{title}</p>
      <p className="mt-1 max-w-md text-xs text-muted">{message}</p>
      {requestId && <p className="mono mt-1 text-xs text-subtle">Request ID {requestId}</p>}
      {onRetry && (
        <Button className="mt-4" size="sm" icon={<RotateCw className="size-3.5" aria-hidden />} onClick={onRetry}>
          Retry
        </Button>
      )}
    </div>
  );
}

export function Spinner({ label = "Loading" }: { label?: string }) {
  return (
    <span role="status" className="inline-flex items-center gap-2 text-xs text-muted">
      <Loader2 className="size-3.5 animate-spin" aria-hidden />
      {label}
    </span>
  );
}

// --- Segmented control -------------------------------------------------------------------------

export function Segmented<T extends string | number>({ value, options, onChange, label }: { value: T; options: { value: T; label: string }[]; onChange: (v: T) => void; label: string }) {
  return (
    <div role="radiogroup" aria-label={label} className="inline-flex overflow-hidden rounded-md border border-line-strong shadow-xs">
      {options.map((o) => {
        const active = o.value === value;
        return (
          <button
            key={String(o.value)}
            type="button"
            role="radio"
            aria-checked={active}
            onClick={() => onChange(o.value)}
            className={cn("h-8 min-w-10 border-l border-line-strong px-3 text-sm transition-colors first:border-l-0", active ? "bg-raised font-medium text-fg" : "text-muted hover:bg-raised/60 hover:text-fg")}
          >
            {o.label}
          </button>
        );
      })}
    </div>
  );
}

// --- Page header ----------------------------------------------------------------------------------

export function PageHeader({ title, description, actions, breadcrumbs, meta }: { title: ReactNode; description?: ReactNode; actions?: ReactNode; breadcrumbs?: { label: string; href?: string }[]; meta?: ReactNode }) {
  return (
    <div className="mb-6">
      {breadcrumbs && (
        <nav aria-label="Breadcrumb" className="mb-2">
          <ol className="flex flex-wrap items-center gap-1.5 text-sm text-muted">
            {breadcrumbs.map((b, i) => (
              <li key={b.label} className="flex items-center gap-1.5">
                {i > 0 && <span aria-hidden>/</span>}
                {b.href ? (
                  <Link href={b.href} className="hover:text-fg">
                    {b.label}
                  </Link>
                ) : (
                  <span aria-current="page" className="text-fg">
                    {b.label}
                  </span>
                )}
              </li>
            ))}
          </ol>
        </nav>
      )}
      <div className="flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
        <div className="min-w-0">
          <h1 className="text-2xl font-semibold tracking-tight text-fg">{title}</h1>
          {description && <p className="mt-1.5 max-w-3xl text-sm text-muted">{description}</p>}
          {meta && <div className="mt-2 flex flex-wrap items-center gap-2">{meta}</div>}
        </div>
        {actions && <div className="flex flex-wrap items-center gap-2 xl:shrink-0 xl:flex-nowrap">{actions}</div>}
      </div>
    </div>
  );
}
