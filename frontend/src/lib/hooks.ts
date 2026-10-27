"use client";

import { useQuery } from "@tanstack/react-query";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { useCallback, useMemo } from "react";

import { api } from "./api";
import type { Me, Role } from "./types";

const RANK: Record<Role, number> = { viewer: 0, analyst: 1, lead: 2, admin: 3 };

export function useMe() {
  return useQuery({ queryKey: ["me"], queryFn: () => api<Me>("/auth/me"), staleTime: 5 * 60_000, retry: false });
}

export function useCan(minimum: Role): boolean {
  const { data } = useMe();
  return !!data && RANK[data.role] >= RANK[minimum];
}

/**
 * Filter state kept in the URL so views are shareable and survive reloads.
 * Must be used inside a <Suspense> boundary (useSearchParams requirement).
 */
export function useUrlState() {
  const params = useSearchParams();
  const router = useRouter();
  const pathname = usePathname();

  const get = useCallback((key: string, fallback = "") => params.get(key) ?? fallback, [params]);
  const getAll = useCallback((key: string) => params.getAll(key), [params]);

  const set = useCallback(
    (updates: Record<string, string | string[] | number | null | undefined>, opts: { resetPage?: boolean } = { resetPage: true }) => {
      const next = new URLSearchParams(params.toString());
      for (const [k, v] of Object.entries(updates)) {
        next.delete(k);
        if (v === null || v === undefined || v === "") continue;
        if (Array.isArray(v)) v.forEach((x) => next.append(k, x));
        else next.set(k, String(v));
      }
      if (opts.resetPage && !("page" in updates)) next.delete("page");
      const qs = next.toString();
      router.replace(qs ? `${pathname}?${qs}` : pathname, { scroll: false });
    },
    [params, pathname, router],
  );

  return useMemo(() => ({ get, getAll, set, params }), [get, getAll, set, params]);
}
