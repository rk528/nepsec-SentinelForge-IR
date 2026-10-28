"use client";

import { useMutation, useQueryClient } from "@tanstack/react-query";
import { KeyRound } from "lucide-react";
import { useState } from "react";

import { useToast } from "@/components/ui/overlays";
import { Button, Field, Input, Panel } from "@/components/ui/primitives";
import { ApiError, api } from "@/lib/api";

export const PASSWORD_RULES = "12+ characters with upper and lower case letters and a digit.";

export function ChangePasswordForm({ currentLabel = "Current password", submitLabel = "Change password" }: { currentLabel?: string; submitLabel?: string }) {
  const toast = useToast();
  const qc = useQueryClient();
  const empty = { current_password: "", new_password: "", confirm: "" };
  const [form, setForm] = useState(empty);
  const mismatch = form.confirm.length > 0 && form.confirm !== form.new_password;
  const change = useMutation({
    mutationFn: () => api("/auth/password", { method: "POST", body: { current_password: form.current_password, new_password: form.new_password } }),
    onSuccess: () => {
      setForm(empty);
      toast({ kind: "success", title: "Password changed", description: "Your other sessions were signed out." });
      // Clears must_change_password, which releases the forced-change screen.
      qc.invalidateQueries({ queryKey: ["me"] });
    },
    onError: (e) => toast({ kind: "error", title: "Password not changed", description: e instanceof ApiError ? e.detail : "Unexpected error" }),
  });
  return (
    <form
      className="grid gap-3 md:grid-cols-3"
      onSubmit={(e) => {
        e.preventDefault();
        if (!mismatch && form.new_password) change.mutate();
      }}
    >
      <Field label={currentLabel} htmlFor="pw-current"><Input id="pw-current" type="password" autoComplete="current-password" value={form.current_password} onChange={(e) => setForm({ ...form, current_password: e.target.value })} /></Field>
      <Field label="New password" htmlFor="pw-new"><Input id="pw-new" type="password" autoComplete="new-password" value={form.new_password} onChange={(e) => setForm({ ...form, new_password: e.target.value })} /></Field>
      <Field label="Repeat new password" htmlFor="pw-confirm" error={mismatch ? "Passwords do not match" : undefined}><Input id="pw-confirm" type="password" autoComplete="new-password" aria-invalid={mismatch} value={form.confirm} onChange={(e) => setForm({ ...form, confirm: e.target.value })} /></Field>
      <div className="md:col-span-3">
        <Button type="submit" variant="primary" loading={change.isPending} disabled={!form.current_password || !form.new_password || mismatch}>{submitLabel}</Button>
      </div>
    </form>
  );
}

/** Shown instead of the app while the account still uses an emailed temporary password. */
export function ForcedPasswordChange() {
  return (
    <div className="mx-auto max-w-3xl py-6">
      <Panel
        title={<span className="flex items-center gap-1.5"><KeyRound className="size-3.5 text-accent" aria-hidden /> Choose your own password</span>}
        description={`You signed in with a temporary password. Replace it to open your workspace. ${PASSWORD_RULES}`}
      >
        <ChangePasswordForm currentLabel="Temporary password" submitLabel="Set password and continue" />
      </Panel>
    </div>
  );
}
