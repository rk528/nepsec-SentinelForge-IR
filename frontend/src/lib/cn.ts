import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

/** shadcn/ui's cn(): later Tailwind classes override earlier conflicting ones (e.g. w-32 beats w-full). */
export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}
