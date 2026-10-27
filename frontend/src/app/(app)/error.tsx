"use client";

import { ErrorState, Panel } from "@/components/ui/primitives";

export default function AppError({ error, reset }: { error: Error & { digest?: string }; reset: () => void }) {
  return (
    <Panel>
      <ErrorState title="This page failed to render" error={error} onRetry={reset} />
    </Panel>
  );
}
