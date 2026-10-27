"use client";

import { ArrowDown, ArrowUp, ChevronLeft, ChevronRight } from "lucide-react";
import { useRouter } from "next/navigation";
import type { ReactNode } from "react";

import { Button, cn } from "./primitives";

export interface Column<T> {
  key: string;
  header: string;
  render: (row: T) => ReactNode;
  sortKey?: string;
  className?: string;
  headerClassName?: string;
  hideBelow?: "sm" | "md" | "lg" | "xl";
}

const hide = { sm: "hidden sm:table-cell", md: "hidden md:table-cell", lg: "hidden lg:table-cell", xl: "hidden xl:table-cell" };

export function DataTable<T>({
  columns,
  rows,
  rowKey,
  rowHref,
  sort,
  order,
  onSort,
  caption,
}: {
  columns: Column<T>[];
  rows: T[];
  rowKey: (row: T) => string;
  rowHref?: (row: T) => string;
  sort?: string;
  order?: "asc" | "desc";
  onSort?: (key: string) => void;
  caption: string;
}) {
  const router = useRouter();
  return (
    <div className="overflow-x-auto">
      <table className="w-full border-collapse text-left text-sm">
        <caption className="sr-only">{caption}</caption>
        <thead className="bg-raised/60">
          <tr className="border-b border-line">
            {columns.map((c) => {
              const active = c.sortKey && sort === c.sortKey;
              return (
                <th
                  key={c.key}
                  scope="col"
                  aria-sort={active ? (order === "asc" ? "ascending" : "descending") : undefined}
                  className={cn("h-10 px-3 text-xs font-medium whitespace-nowrap text-muted first:pl-5 last:pr-5", c.hideBelow && hide[c.hideBelow], c.headerClassName)}
                >
                  {c.sortKey && onSort ? (
                    <button type="button" onClick={() => onSort(c.sortKey!)} className="inline-flex items-center gap-1 hover:text-fg">
                      {c.header}
                      {active && (order === "asc" ? <ArrowUp className="size-3" aria-hidden /> : <ArrowDown className="size-3" aria-hidden />)}
                    </button>
                  ) : (
                    c.header
                  )}
                </th>
              );
            })}
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => {
            const href = rowHref?.(row);
            return (
              <tr
                key={rowKey(row)}
                onClick={
                  href
                    ? (e) => {
                        // Ignore clicks on inner links/buttons and text selection.
                        if ((e.target as HTMLElement).closest("a,button,input,select") || window.getSelection()?.toString()) return;
                        router.push(href);
                      }
                    : undefined
                }
                className={cn("border-b border-line/80 transition-colors last:border-b-0 hover:bg-raised/40", href && "cursor-pointer")}
              >
                {columns.map((c) => (
                  <td key={c.key} className={cn("px-3 py-3 align-middle first:pl-5 last:pr-5", c.hideBelow && hide[c.hideBelow], c.className)}>
                    {c.render(row)}
                  </td>
                ))}
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

export function Pagination({ page, pageSize, total, onPage }: { page: number; pageSize: number; total: number; onPage: (p: number) => void }) {
  const pages = Math.max(1, Math.ceil(total / pageSize));
  const from = total === 0 ? 0 : (page - 1) * pageSize + 1;
  const to = Math.min(total, page * pageSize);
  return (
    <nav aria-label="Pagination" className="flex items-center justify-between gap-3 border-t border-line px-5 py-3 text-sm text-muted">
      <span>
        {from.toLocaleString()}–{to.toLocaleString()} of {total.toLocaleString()}
      </span>
      <div className="flex items-center gap-1">
        <Button size="sm" variant="ghost" disabled={page <= 1} onClick={() => onPage(page - 1)} aria-label="Previous page" icon={<ChevronLeft className="size-3.5" aria-hidden />} />
        <span className="px-1 tabular-nums">
          Page {page} of {pages}
        </span>
        <Button size="sm" variant="ghost" disabled={page >= pages} onClick={() => onPage(page + 1)} aria-label="Next page" icon={<ChevronRight className="size-3.5" aria-hidden />} />
      </div>
    </nav>
  );
}
