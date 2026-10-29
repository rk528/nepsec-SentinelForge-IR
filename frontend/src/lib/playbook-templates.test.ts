import { describe, expect, it } from "vitest";

import { PLAYBOOK_TEMPLATES } from "@/lib/playbook-templates";

// The built-in actions in backend/app/playbooks/registry.py; the server refuses any other.
const BUILT_IN = ["collect_related_evidence", "enrich_iocs", "prepare_summary", "propose_blocklist", "simulate_firewall_block", "record_containment", "closure_report"];

describe("playbook templates", () => {
  it("save as the server expects", () => {
    expect(new Set(PLAYBOOK_TEMPLATES.map((t) => t.id)).size).toBe(PLAYBOOK_TEMPLATES.length);
    for (const t of PLAYBOOK_TEMPLATES) {
      expect(t.name.length).toBeGreaterThan(0);
      expect(t.steps.length).toBeGreaterThan(0);
      expect(t.steps.length).toBeLessThanOrEqual(30);
      for (const s of t.steps) {
        expect(s.title.trim().length).toBeGreaterThan(0);
        if (s.kind === "action") expect(BUILT_IN).toContain(s.action);
        else expect(s.action).toBeNull();
      }
      for (const r of t.trigger_rules) expect(r).toMatch(/^SF-[A-Z]+-\d{3}$/);
    }
  });
});
