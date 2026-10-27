import Link from "next/link";

export default function NotFound() {
  return (
    <main className="grid min-h-dvh place-items-center px-4">
      <div className="text-center">
        <p className="mono text-xs text-subtle">404</p>
        <h1 className="mt-1 text-lg font-semibold text-fg">Page not found</h1>
        <p className="mt-1 text-[13px] text-muted">The page does not exist, or you do not have access to it.</p>
        <Link href="/dashboard" className="mt-4 inline-block text-[13px] text-accent hover:underline">
          Back to overview
        </Link>
      </div>
    </main>
  );
}
