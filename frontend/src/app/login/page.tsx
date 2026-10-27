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
import { safeNext } from "@/lib/navigation";
import type { Me } from "@/lib/types";

const schema = z.object({
  email: z.string().trim().min(3, "Enter your email").max(320).regex(/^[^@\s]+@[^@\s]+\.[^@\s]+$/, "Enter a valid email address"),
  password: z.string().min(1, "Enter your password").max(256),
});
type FormValues = z.infer<typeof schema>;

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

  // Layout follows the shadcn/ui "login-03" block: centred brand, a welcome card,
  // and an "Or continue with" divider leading to the alternative sign-in options.
  return (
    <div className="flex w-full max-w-sm flex-col gap-6">
      <div className="flex items-center gap-2 self-center font-medium">
        <span className="grid size-8 place-items-center rounded-lg bg-accent text-accent-fg">
          <LogoMark className="size-5" />
        </span>
        <span className="text-fg">SentinelForge IR</span>
      </div>

      <div className="rounded-xl border border-line bg-surface shadow-sm">
        <div className="space-y-1.5 px-6 pt-6 text-center">
          <h1 className="text-xl font-semibold text-fg">Welcome back</h1>
          <p className="text-sm text-muted">Sign in to your incident response workspace</p>
        </div>
        <div className="p-6">
          <form onSubmit={handleSubmit(onSubmit)} noValidate className="grid gap-5">
            <Field label="Email" htmlFor="email" error={errors.email?.message}>
              <Input id="email" type="email" autoComplete="username" placeholder="you@company.com" aria-invalid={!!errors.email} {...register("email")} />
            </Field>
            <Field label="Password" htmlFor="password" error={errors.password?.message}>
              <Input id="password" type="password" autoComplete="current-password" aria-invalid={!!errors.password} {...register("password")} />
            </Field>
            {serverError && (
              <p role="alert" className="rounded-md border border-danger/30 bg-danger/10 px-3 py-2 text-sm text-danger">
                {serverError}
              </p>
            )}
            <Button type="submit" variant="primary" className="w-full" loading={isSubmitting}>
              Sign in
            </Button>
          </form>

          {config?.demo_mode && (
            <>
              <div className="relative my-6 text-center text-sm after:absolute after:inset-0 after:top-1/2 after:z-0 after:border-t after:border-line">
                <span className="relative z-10 bg-surface px-2 text-muted">Or explore the synthetic demo</span>
              </div>
              <div className="grid grid-cols-3 gap-2">
                {(
                  [
                    { role: "analyst", label: "Analyst", icon: ShieldCheck },
                    { role: "lead", label: "Lead", icon: UserCog },
                    { role: "viewer", label: "Viewer", icon: Eye },
                  ] as const
                ).map(({ role, label, icon: Icon }) => (
                  <Button key={role} loading={demoBusy === role} disabled={!!demoBusy} onClick={() => demo(role)} icon={<Icon className="size-4" aria-hidden />}>
                    {label}
                  </Button>
                ))}
              </div>
              <p className="mt-4 flex gap-2 text-xs text-muted">
                <FlaskConical className="mt-px size-3.5 shrink-0 text-accent" aria-hidden />
                <span>No password needed. Every record is synthetic, response actions are simulated and administration is disabled. Sign in as Lead to approve the analyst&apos;s pending firewall block.</span>
              </p>
            </>
          )}
        </div>
      </div>

      <p className="text-center text-xs text-balance text-muted">Accounts are created by your administrator. Sessions expire after 12 hours or 2 hours idle.</p>
    </div>
  );
}

export default function LoginPage() {
  return (
    <main className="flex min-h-dvh flex-col items-center justify-center bg-shell px-4 py-12 md:px-10">
      <Suspense>
        <LoginForm />
      </Suspense>
    </main>
  );
}
