"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowDown, ArrowUp, ListChecks, Plus, Trash2, Workflow } from "lucide-react";
import { useState } from "react";

import { Dialog, useToast } from "@/components/ui/overlays";
import { Button, Field, Input, Select, Textarea, cn } from "@/components/ui/primitives";
import { ApiError, api } from "@/lib/api";
import { PLAYBOOK_TEMPLATES } from "@/lib/playbook-templates";
import type { CustomPlaybook, Playbook, PlaybookStep, RuleRow } from "@/lib/types";

type Draft = { name: string; description: string; steps: PlaybookStep[]; trigger_rules: string[] };

const EMPTY: Draft = { name: "", description: "", steps: [{ kind: "task", title: "", action: null, instructions: "" }], trigger_rules: [] };

function errText(e: unknown) {
  return e instanceof ApiError ? e.message : "Something went wrong";
}

/** Create or edit an organisation playbook: ordered automated actions and manual tasks, plus the rules that suggest it. */
export function PlaybookBuilder({ open, onOpenChange, editing }: { open: boolean; onOpenChange: (o: boolean) => void; editing: CustomPlaybook | null }) {
  // Remounted per open (keyed by the caller), so the draft starts from the playbook being edited.
  const [draft, setDraft] = useState<Draft>(() => (editing ? { name: editing.name, description: editing.description, steps: editing.steps.map((s) => ({ ...s, instructions: s.instructions ?? "" })), trigger_rules: editing.trigger_rules } : EMPTY));
  const builtins = useQuery({ queryKey: ["playbooks"], queryFn: () => api<Playbook[]>("/playbooks"), staleTime: 10 * 60_000 });
  const rules = useQuery({ queryKey: ["rules"], queryFn: () => api<RuleRow[]>("/detections"), staleTime: 5 * 60_000 });
  const qc = useQueryClient();
  const toast = useToast();

  const save = useMutation({
    mutationFn: () => {
      const body = {
        name: draft.name.trim(),
        description: draft.description.trim(),
        trigger_rules: draft.trigger_rules,
        steps: draft.steps.map((s) => ({ kind: s.kind, title: s.title.trim(), action: s.kind === "action" ? s.action : null, instructions: s.instructions?.trim() || null })),
      };
      return editing ? api<CustomPlaybook>(`/custom-playbooks/${editing.id}`, { method: "PATCH", body }) : api<CustomPlaybook>("/custom-playbooks", { method: "POST", body });
    },
    onSuccess: (p) => {
      qc.invalidateQueries({ queryKey: ["custom-playbooks"] });
      toast({ kind: "success", title: editing ? `Saved “${p.name}”` : `Created “${p.name}”` });
      onOpenChange(false);
    },
    onError: (e) => toast({ kind: "error", title: "Playbook not saved", description: errText(e) }),
  });

  const setStep = (i: number, patch: Partial<PlaybookStep>) => setDraft((d) => ({ ...d, steps: d.steps.map((s, j) => (j === i ? { ...s, ...patch } : s)) }));
  const move = (i: number, by: number) =>
    setDraft((d) => {
      const steps = [...d.steps];
      [steps[i], steps[i + by]] = [steps[i + by], steps[i]];
      return { ...d, steps };
    });
  const firstAction = builtins.data?.[0];
  const invalid = !draft.name.trim() || draft.steps.length === 0 || draft.steps.some((s) => !s.title.trim() || (s.kind === "action" && !s.action));

  return (
    <Dialog
      open={open}
      onOpenChange={onOpenChange}
      size="lg"
      title={editing ? `Edit “${editing.name}”` : "New playbook"}
      description="Steps run in order on an incident. Automated steps reuse the built-in actions, with the same approvals; manual tasks are ticked off with a note that is kept as evidence."
      footer={
        <>
          <Button variant="ghost" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button variant="primary" loading={save.isPending} disabled={invalid} onClick={() => save.mutate()}>
            {editing ? "Save playbook" : "Create playbook"}
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        {!editing && (
          <Field label="Start from a template" htmlFor="pb-template" hint="Fills in the steps for a common scenario. Change anything before saving.">
            <Select
              id="pb-template"
              defaultValue=""
              onChange={(e) => {
                const t = PLAYBOOK_TEMPLATES.find((x) => x.id === e.target.value);
                setDraft(t ? { name: t.name, description: t.description, trigger_rules: [...t.trigger_rules], steps: t.steps.map((st) => ({ ...st })) } : EMPTY);
              }}
            >
              <option value="">Blank playbook</option>
              {PLAYBOOK_TEMPLATES.map((t) => (
                <option key={t.id} value={t.id}>
                  {t.name}
                </option>
              ))}
            </Select>
          </Field>
        )}
        <Field label="Name" htmlFor="pb-name">
          <Input id="pb-name" value={draft.name} maxLength={200} placeholder="e.g. Compromised account" onChange={(e) => setDraft({ ...draft, name: e.target.value })} />
        </Field>
        <Field label="Description" htmlFor="pb-desc" hint="Optional. When to use this playbook.">
          <Textarea id="pb-desc" value={draft.description} maxLength={2000} className="min-h-14" onChange={(e) => setDraft({ ...draft, description: e.target.value })} />
        </Field>

        <div>
          <p className="mb-2 text-sm font-medium text-fg">Steps</p>
          <ol className="space-y-2">
            {draft.steps.map((s, i) => (
              <li key={i} className="rounded-lg border border-line bg-canvas/40 p-3">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="mono w-6 text-xs text-subtle">{i + 1}.</span>
                  <Select
                    aria-label={`Step ${i + 1} type`}
                    value={s.kind}
                    className="w-48 shrink-0"
                    onChange={(e) => {
                      const kind = e.target.value as PlaybookStep["kind"];
                      setStep(i, kind === "action" ? { kind, action: s.action ?? firstAction?.id ?? null, title: s.title || firstAction?.name || "" } : { kind, action: null });
                    }}
                  >
                    <option value="task">Manual task</option>
                    <option value="action">Automated action</option>
                  </Select>
                  {s.kind === "action" && (
                    <Select
                      aria-label={`Step ${i + 1} action`}
                      value={s.action ?? ""}
                      className="min-w-0 flex-1"
                      onChange={(e) => {
                        const pb = builtins.data?.find((p) => p.id === e.target.value);
                        setStep(i, { action: e.target.value, title: !s.title || builtins.data?.some((p) => p.name === s.title) ? (pb?.name ?? s.title) : s.title });
                      }}
                    >
                      {builtins.data?.map((p) => (
                        <option key={p.id} value={p.id}>
                          {p.name}
                          {p.requires_approval ? " (needs approval)" : ""}
                        </option>
                      ))}
                    </Select>
                  )}
                  <div className="ml-auto flex gap-1">
                    <Button size="sm" variant="ghost" aria-label="Move up" disabled={i === 0} onClick={() => move(i, -1)} icon={<ArrowUp className="size-3.5" aria-hidden />} />
                    <Button size="sm" variant="ghost" aria-label="Move down" disabled={i === draft.steps.length - 1} onClick={() => move(i, 1)} icon={<ArrowDown className="size-3.5" aria-hidden />} />
                    <Button size="sm" variant="ghost" aria-label="Remove step" disabled={draft.steps.length === 1} onClick={() => setDraft({ ...draft, steps: draft.steps.filter((_, j) => j !== i) })} icon={<Trash2 className="size-3.5" aria-hidden />} />
                  </div>
                </div>
                <div className="mt-2 space-y-2 pl-8">
                  <Input aria-label={`Step ${i + 1} title`} value={s.title} maxLength={200} placeholder={s.kind === "task" ? "What the analyst does, e.g. Call the user to confirm" : "Step title"} onChange={(e) => setStep(i, { title: e.target.value })} />
                  <Textarea aria-label={`Step ${i + 1} instructions`} value={s.instructions ?? ""} maxLength={4000} className="min-h-12 text-xs" placeholder="Instructions (optional)" onChange={(e) => setStep(i, { instructions: e.target.value })} />
                </div>
              </li>
            ))}
          </ol>
          <div className="mt-2 flex flex-wrap gap-2">
            <Button size="sm" icon={<ListChecks className="size-3.5" aria-hidden />} disabled={draft.steps.length >= 30} onClick={() => setDraft({ ...draft, steps: [...draft.steps, { kind: "task", title: "", action: null, instructions: "" }] })}>
              Add manual task
            </Button>
            <Button
              size="sm"
              icon={<Workflow className="size-3.5" aria-hidden />}
              disabled={draft.steps.length >= 30 || !firstAction}
              onClick={() => setDraft({ ...draft, steps: [...draft.steps, { kind: "action", title: firstAction?.name ?? "", action: firstAction?.id ?? null, instructions: "" }] })}
            >
              Add automated action
            </Button>
          </div>
        </div>

        <fieldset>
          <legend className="mb-1 text-sm font-medium text-fg">Suggest for incidents raised by</legend>
          <p className="mb-2 text-xs text-muted">The playbook is offered first on incidents whose alerts came from these rules. Leave empty to only start it by hand.</p>
          <div className="grid max-h-48 gap-1 overflow-y-auto rounded-lg border border-line p-2 sm:grid-cols-2">
            {rules.data?.map((r) => {
              const on = draft.trigger_rules.includes(r.id);
              return (
                <label key={r.id} className={cn("flex cursor-pointer items-start gap-2 rounded-md px-2 py-1.5 text-xs hover:bg-raised", on && "bg-accent/10")}>
                  <input
                    type="checkbox"
                    className="mt-0.5 accent-[var(--color-accent)]"
                    checked={on}
                    onChange={() => setDraft({ ...draft, trigger_rules: on ? draft.trigger_rules.filter((x) => x !== r.id) : [...draft.trigger_rules, r.id] })}
                  />
                  <span className="min-w-0">
                    <span className="mono text-subtle">{r.id}</span> <span className="text-fg">{r.name}</span>
                  </span>
                </label>
              );
            })}
          </div>
        </fieldset>
      </div>
    </Dialog>
  );
}

export function NewPlaybookButton({ onClick }: { onClick: () => void }) {
  return (
    <Button size="sm" variant="primary" icon={<Plus className="size-3.5" aria-hidden />} onClick={onClick}>
      New playbook
    </Button>
  );
}
