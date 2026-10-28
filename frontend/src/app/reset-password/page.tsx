"use client";

import { useMutation, useQuery } from "@tanstack/react-query";
import { CheckCircle2 } from "lucide-react";
import Link from "next/link";
import { useState, useSyncExternalStore } from "react";

import { PASSWORD_RULES } from "@/components/password-change";
import { LogoMark } from "@/components/shell/logo";
import { ThemeToggle } from "@/components/shell/theme-toggle";
import { Button, ButtonLink, Field, Input, Spinner } from "@/components/ui/primitives";
import { ApiError, api } from "@/lib/api";

interface TokenInfo { email: string; display_name: string; purpose: "invite" | "reset"; expires_at: string }

// The token travels in the URL fragment (#token=...), which browsers never send to a
// server, so it cannot leak through access logs or the Referer header.
function readToken(): string {
  const match = window.location.hash.match(/token=([A-Za-z0-9_-]+)/);
  return match ? match[1] : "";
}
const subscribe = () => () => {};

function ResetForm() {
  const token = useSyncExternalStore(subscribe, readToken, () => "");
  const [pw, setPw] = useState({ next: "", confirm: "" });
  const mismatch = pw.confirm.length > 0 && pw.confirm !== pw.next;
  const info = useQuery({
    queryKey: ["reset-token", token],
    queryFn: () => api<TokenInfo>("/auth/reset-password/check", { method: "POST", body: { token } }),
    enabled: token.length > 0,
    retry: false,
  });
  const reset = useMutation({
    mutationFn: () => api("/auth/reset-password", { method: "POST", body: { token, new_password: pw.next } }),
    // The link is spent; drop it from the address bar and history.
    onSuccess: () => window.history.replaceState(null, "", window.location.pathname),
  });

  if (reset.isSuccess) {
    return (
      <div className="space-y-4 text-center">
        <CheckCircle2 className="mx-auto size-10 text-ok" aria-hidden />
        <h1 className="text-xl font-semibold text-fg">Password set</h1>
        <p className="text-sm text-muted">Sign in with your new password. Any other sessions were signed out.</p>
        <ButtonLink href="/login" variant="primary" className="w-full justify-center">Go to sign in</ButtonLink>
      </div>
    );
  }
  if (!token || info.isError) {
    return (
      <div className="space-y-3 text-center">
        <h1 className="text-xl font-semibold text-fg">Link not valid</h1>
        <p className="text-sm text-muted">{info.error instanceof ApiError ? info.error.detail : "This link is incomplete. Open it again from your email, or ask your administrator to send a new one."}</p>
        <Link href="/login" className="text-sm text-accent hover:underline">Back to sign in</Link>
      </div>
    );
  }
  if (!info.data) return <div className="grid place-items-center py-10"><Spinner label="Checking link" /></div>;

  const welcome = info.data.purpose === "invite";
  return (
    <form
      noValidate
      className="grid gap-5"
      onSubmit={(e) => {
        e.preventDefault();
        if (pw.next && !mismatch) reset.mutate();
      }}
    >
      <div className="space-y-1.5 text-center">
        <h1 className="text-xl font-semibold text-fg">{welcome ? `Welcome, ${info.data.display_name}` : "Choose a new password"}</h1>
        <p className="text-sm text-muted">{welcome ? "Set the password for your new account" : "Set a new password for your account"} <span className="mono text-fg">{info.data.email}</span></p>
      </div>
      <input type="email" autoComplete="username" value={info.data.email} readOnly hidden />
      <Field label="New password" htmlFor="rp-new" hint={PASSWORD_RULES}>
        <Input id="rp-new" type="password" autoComplete="new-password" value={pw.next} onChange={(e) => setPw({ ...pw, next: e.target.value })} />
      </Field>
      <Field label="Repeat new password" htmlFor="rp-confirm" error={mismatch ? "Passwords do not match" : undefined}>
        <Input id="rp-confirm" type="password" autoComplete="new-password" aria-invalid={mismatch} value={pw.confirm} onChange={(e) => setPw({ ...pw, confirm: e.target.value })} />
      </Field>
      {reset.isError && (
        <p role="alert" className="rounded-md border border-danger/30 bg-danger/10 px-3 py-2 text-sm text-danger">
          {reset.error instanceof ApiError ? reset.error.detail : "Password not set"}
        </p>
      )}
      <Button type="submit" variant="primary" className="w-full" loading={reset.isPending} disabled={!pw.next || mismatch}>
        Set password
      </Button>
    </form>
  );
}

export default function ResetPasswordPage() {
  return (
    <main className="flex min-h-dvh flex-col items-center justify-center bg-shell px-4 py-12 md:px-10">
      <ThemeToggle className="fixed top-4 right-4" />
      <div className="flex w-full max-w-sm flex-col gap-6">
        <div className="flex items-center gap-2 self-center font-medium">
          <span className="grid size-8 place-items-center rounded-lg bg-accent text-accent-fg">
            <LogoMark className="size-5" />
          </span>
          <span className="text-fg">SentinelForge IR</span>
        </div>
        <div className="rounded-xl border border-line bg-surface p-6 shadow-sm">
          <ResetForm />
        </div>
        <p className="text-center text-xs text-balance text-muted">Links work once and expire after 24 hours.</p>
      </div>
    </main>
  );
}
