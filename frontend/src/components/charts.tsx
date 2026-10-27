"use client";

import Link from "next/link";
import { Bar, BarChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

import { formatDay } from "@/lib/format";
import type { Severity } from "@/lib/types";

import { SEVERITY_COLOR, SEVERITY_ORDER } from "./ui/badges";
import { EmptyState } from "./ui/primitives";

type Row = { date: string } & Partial<Record<Severity, number>>;

const LABEL: Record<Severity, string> = { critical: "Critical", high: "High", medium: "Medium", low: "Low", informational: "Info" };

function ChartTooltip({ active, payload, label }: { active?: boolean; payload?: { name: string; value: number; color: string }[]; label?: string }) {
  if (!active || !payload?.length) return null;
  const total = payload.reduce((s, p) => s + (p.value || 0), 0);
  return (
    <div className="rounded-md border border-line-strong bg-overlay px-3 py-2 text-xs shadow-lg">
      <p className="mb-1 font-medium text-fg">{label ? formatDay(label) : ""}</p>
      {payload
        .filter((p) => p.value > 0)
        .reverse()
        .map((p) => (
          <p key={p.name} className="flex items-center justify-between gap-4 text-muted">
            <span className="flex items-center gap-1.5">
              <span className="size-2 rounded-sm" style={{ background: p.color }} />
              {p.name}
            </span>
            <span className="text-fg tabular-nums">{p.value}</span>
          </p>
        ))}
      <p className="mt-1 flex justify-between gap-4 border-t border-line pt-1 text-muted">
        Total <span className="text-fg tabular-nums">{total}</span>
      </p>
    </div>
  );
}

/** Stacked daily counts by severity. Accessible summary is provided as a visually hidden table. */
export function SeverityTrendChart({ data, label, emptyText }: { data: Row[]; label: string; emptyText: string }) {
  const total = data.reduce((s, r) => s + SEVERITY_ORDER.reduce((a, k) => a + (r[k] ?? 0), 0), 0);
  if (total === 0) return <EmptyState title="No activity in this range" description={emptyText} />;
  const present = [...SEVERITY_ORDER].reverse().filter((s) => data.some((r) => (r[s] ?? 0) > 0));
  return (
    <figure aria-label={label}>
      <div className="h-56 w-full">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={data} margin={{ top: 4, right: 4, left: -18, bottom: 0 }} barCategoryGap="22%">
            <CartesianGrid vertical={false} stroke="#232836" />
            <XAxis dataKey="date" tickFormatter={formatDay} tick={{ fill: "#858ca2", fontSize: 11 }} axisLine={false} tickLine={false} minTickGap={16} />
            <YAxis allowDecimals={false} tick={{ fill: "#858ca2", fontSize: 11 }} axisLine={false} tickLine={false} width={40} />
            <Tooltip content={<ChartTooltip />} cursor={{ fill: "color-mix(in srgb, var(--color-fg) 5%, transparent)" }} />
            <Legend iconType="square" iconSize={8} wrapperStyle={{ fontSize: 12, color: "var(--color-muted)", paddingTop: 8 }} />
            {present.map((s, i) => (
              <Bar key={s} dataKey={s} name={LABEL[s]} stackId="sev" fill={SEVERITY_COLOR[s]} radius={i === present.length - 1 ? [2, 2, 0, 0] : 0} isAnimationActive={false} />
            ))}
          </BarChart>
        </ResponsiveContainer>
      </div>
      <table className="sr-only">
        <caption>{label}</caption>
        <thead>
          <tr>
            <th>Date</th>
            {present.map((s) => (
              <th key={s}>{LABEL[s]}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {data.map((r) => (
            <tr key={r.date}>
              <td>{r.date}</td>
              {present.map((s) => (
                <td key={s}>{r[s] ?? 0}</td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </figure>
  );
}

/** Ranked horizontal bars. Each row can link to the filtered records behind it. */
export function BarList({ items, emptyText }: { items: { key: string; label: React.ReactNode; value: number; href?: string; color?: string }[]; emptyText: string }) {
  const max = Math.max(1, ...items.map((i) => i.value));
  if (items.length === 0 || items.every((i) => i.value === 0)) return <EmptyState title="Nothing to show" description={emptyText} />;
  return (
    <ul className="space-y-3">
      {items.map((item) => {
        const content = (
          <>
            <div className="flex items-start justify-between gap-3 text-sm">
              <span className="min-w-0 leading-snug text-fg">{item.label}</span>
              <span className="shrink-0 font-medium text-fg tabular-nums">{item.value.toLocaleString()}</span>
            </div>
            <div className="mt-1.5 h-2 overflow-hidden rounded-full bg-raised">
              <div className="h-2 rounded-full" style={{ width: `${(item.value / max) * 100}%`, background: item.color ?? "var(--color-accent)" }} />
            </div>
          </>
        );
        return (
          <li key={item.key}>
            {item.href ? (
              <Link href={item.href} className="-m-1.5 block rounded-md p-1.5 hover:bg-raised/60">
                {content}
              </Link>
            ) : (
              content
            )}
          </li>
        );
      })}
    </ul>
  );
}
