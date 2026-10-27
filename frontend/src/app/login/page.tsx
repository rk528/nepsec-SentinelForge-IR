"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Eye, FlaskConical, ShieldCheck, UserCog } from "lucide-react";
import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useState } from "react";
import { useForm } from "react-hook-form";
import { z } from "zod";

import { LogoMark } from "@/components/shell/logo";
import { Button, Field, Input } from "@/components/ui/primitives";
import { ApiError, api } from "@/lib/api";
import type { Me } from "@/lib/types";

const schema = z.object({
  email: z.string().trim().min(3, "Enter your email").max(320).regex(/^[^@\s]+@[^@\s]+\.[^@\s]+$/, "Enter a valid email address"),
  password: z.string().min(1, "Enter your password").max(256),
});
type FormValues = z.infer<typeof schema>;

function safeNext(next: string | null): string {
  // Only allow same-site relative paths to prevent open redirects.
  if (!next || !next.startsWith("/") || next.startsWith("//") || next.startsWith("/\\")) return "/dashboard";
  return next;
}

function LoginForm() {
  const router = useRouter();
  const params = useSearchParams();
  const qc = useQueryClient();
  const [serverError, setServerError] = useState<string | null>(null);
  const [demoBusy, setDemoBusy] = useState<string | null>(null);
  const { data: config } = useQuery({ queryKey: ["auth-config"], queryFn: () => api<{ demo_mode: boolean }>("/auth/config") });
  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
  } = useForm<FormValues>({ resolver: zodResolver(schema) });

  async function done(me: Me) {
    qc.setQueryData(["me"], me);
    router.replace(safeNext(params.get("next")));
  }

  async function onSubmit(values: FormValues) {
    setServerError(null);
    try {
      done(await api<Me>("/auth/login", { method: "POST", body: values }));
    } catch (e) {
      setServerError(e instanceof ApiError ? e.detail : "Sign-in failed");
    }
  }

  async function demo(role: "analyst" | "lead" | "viewer") {
    setServerError(null);
    setDemoBusy(role);
    try {
      done(await api<Me>("/auth/demo", { method: "POST", body: { role } }));
    } catch (e) {
      setServerError(e instanceof ApiError ? e.detail : "Demo sign-in failed");
      setDemoBusy(null);
    }
  }

  return (
    <div className="w-full max-w-sm">
      <div className="mb-8 flex items-center gap-3">
        <span className="text-accent">
          <LogoMark className="size-9" />
        </span>
        <div>
          <h1 className="text-base font-semibold tracking-tight text-fg">SentinelForge IR</h1>
          <p className="text-xs text-muted">Incident response and security engineering</p>
        </div>
      </div>

      <form onSubmit={handleSubmit(onSubmit)} noValidate className="space-y-4 rounded-xl border border-line bg-surface p-5">
        <h2 className="text-sm font-semibold text-fg">Sign in</h2>
        <Field label="Email" htmlFor="email" error={errors.email?.message}>
          <Input id="email" type="email" autoComplete="username" aria-invalid={!!errors.email} {...register("email")} />
        </Field>
        <Field label="Password" htmlFor="password" error={errors.password?.message}>
          <Input id="password" type="password" autoComplete="current-password" aria-invalid={!!errors.password} {...register("password")} />
        </Field>
        {serverError && (
          <p role="alert" className="rounded-md border border-danger/30 bg-danger/10 px-3 py-2 text-xs text-danger">
            {serverError}
          </p>
        )}
        <Button type="submit" variant="primary" className="w-full" loading={isSubmitting}>
          Sign in
        </Button>
      </form>

      {config?.demo_mode && (
        <div className="mt-5 rounded-xl border border-accent/25 bg-accent-soft/40 p-5">
          <div className="flex items-start gap-2.5">
            <FlaskConical className="mt-0.5 size-4 shrink-0 text-accent" aria-hidden />
            <div>
              <h2 className="text-[13px] font-semibold text-fg">Explore the synthetic demo</h2>
              <p className="mt-1 text-xs text-muted">No password needed. Every record is synthetic and response actions are simulated. Administrative functions are disabled.</p>
            </div>
          </div>
          <div className="mt-4 grid grid-cols-3 gap-2">
            {(
              [
                { role: "analyst", label: "Analyst", icon: ShieldCheck },
                { role: "lead", label: "Lead", icon: UserCog },
                { role: "viewer", label: "Viewer", icon: Eye },
              ] as const
            ).map(({ role, label, icon: Icon }) => (
              <Button key={role} size="sm" loading={demoBusy === role} disabled={!!demoBusy} onClick={() => demo(role)} icon={<Icon className="size-3.5" aria-hidden />}>
                {label}
              </Button>
            ))}
          </div>
          <p className="mt-3 text-[11px] text-subtle">Tip: sign in as Lead to approve the analyst&apos;s pending firewall block. Leads cannot approve their own requests.</p>
        </div>
      )}
    </div>
  );
}

export default function LoginPage() {
  return (
    <main className="grid min-h-dvh place-items-center bg-canvas px-4 py-12">
      <Suspense>
        <LoginForm />
      </Suspense>
    </main>
  );
}
