/** Only allow same-site relative paths after login, to prevent open redirects. */
export function safeNext(next: string | null | undefined): string {
  if (!next || !next.startsWith("/") || next.startsWith("//") || next.startsWith("/\\") || /[\r\n]/.test(next)) return "/dashboard";
  return next;
}
