import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import axe from "axe-core";
import { describe, expect, it, vi } from "vitest";

import { JsonViewer, Timeline } from "./investigation";
import { ConfidenceMeter, SeverityBadge, VerdictBadge } from "./ui/badges";
import { FilterChips, SearchBox } from "./ui/filters";
import { EmptyState, ErrorState, Segmented } from "./ui/primitives";

async function expectNoAxeViolations(container: HTMLElement) {
  // Colour contrast needs real layout and CSS, which jsdom lacks.
  const results = await axe.run(container, { rules: { "color-contrast": { enabled: false } } });
  expect(results.violations.map((v) => `${v.id}: ${v.help}`)).toEqual([]);
}

describe("severity and confidence", () => {
  it("always labels severity with text, not colour alone", () => {
    render(<SeverityBadge severity="critical" />);
    expect(screen.getByText("Critical")).toBeInTheDocument();
  });
  it("keeps the label available to screen readers in compact mode", () => {
    render(<SeverityBadge severity="high" compact />);
    expect(screen.getByText("High")).toHaveClass("sr-only");
  });
  it("renders confidence separately from severity", () => {
    render(<ConfidenceMeter confidence="low" />);
    expect(screen.getByTitle("Detection confidence: low")).toBeInTheDocument();
  });
  it("shows 'Not set' when no verdict exists", () => {
    render(<VerdictBadge verdict={null} />);
    expect(screen.getByText("Not set")).toBeInTheDocument();
  });
});

describe("untrusted content", () => {
  it("renders hostile log content as inert text", () => {
    const payload = { html: "<img src=x onerror=alert(1)>", script: "<script>alert(1)</script>" };
    const { container } = render(<JsonViewer value={payload} />);
    expect(container.querySelector("img")).toBeNull();
    expect(container.querySelector("script")).toBeNull();
    expect(container.textContent).toContain("<img src=x onerror=alert(1)>");
  });
  it("does not turn timeline details into markup", () => {
    const { container } = render(<Timeline items={[{ at: "2026-01-01T00:00:00Z", kind: "event", title: "<b>bold</b>", detail: "<a href='http://x'>x</a>" }]} />);
    expect(container.querySelector("b")).toBeNull();
    expect(container.querySelector("a[href='http://x']")).toBeNull();
  });
});

describe("interactive controls", () => {
  it("debounces search input before reporting a change", async () => {
    const onChange = vi.fn();
    render(<SearchBox label="Search incidents" placeholder="Search" value="" onChange={onChange} delay={10} />);
    await userEvent.type(screen.getByRole("searchbox", { name: "Search incidents" }), "vpn");
    await vi.waitFor(() => expect(onChange).toHaveBeenLastCalledWith("vpn"));
    expect(onChange).toHaveBeenCalledTimes(1);
  });
  it("toggles filter chips with aria-pressed", async () => {
    const onChange = vi.fn();
    render(
      <FilterChips
        label="Status"
        options={[
          { value: "new", label: "New" },
          { value: "open", label: "Open" },
        ]}
        selected={["new"]}
        onChange={onChange}
      />,
    );
    expect(screen.getByRole("button", { name: "New" })).toHaveAttribute("aria-pressed", "true");
    await userEvent.click(screen.getByRole("button", { name: "Open" }));
    expect(onChange).toHaveBeenCalledWith(["new", "open"]);
  });
  it("exposes the segmented control as a radio group", async () => {
    const onChange = vi.fn();
    render(
      <Segmented
        label="Time range"
        value={7}
        options={[
          { value: 1, label: "24h" },
          { value: 7, label: "7d" },
        ]}
        onChange={onChange}
      />,
    );
    expect(screen.getByRole("radio", { name: "7d" })).toHaveAttribute("aria-checked", "true");
    await userEvent.click(screen.getByRole("radio", { name: "24h" }));
    expect(onChange).toHaveBeenCalledWith(1);
  });
  it("offers retry on errors and shows the request id", async () => {
    const retry = vi.fn();
    const err = Object.assign(new Error("Server unavailable"), { requestId: "abc123" });
    render(<ErrorState error={err} onRetry={retry} />);
    expect(screen.getByRole("alert")).toHaveTextContent("Server unavailable");
    expect(screen.getByText(/abc123/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Retry" }));
    expect(retry).toHaveBeenCalled();
  });
});

describe("accessibility (axe-core)", () => {
  it("has no violations in core components", async () => {
    const { container } = render(
      <main>
        <SeverityBadge severity="medium" />
        <FilterChips label="Severity" options={[{ value: "high", label: "High" }]} selected={[]} onChange={() => {}} />
        <SearchBox label="Search alerts" placeholder="Search" value="" onChange={() => {}} />
        <Segmented label="Range" value="7d" options={[{ value: "7d", label: "7d" }]} onChange={() => {}} />
        <EmptyState title="Nothing here" description="Try another filter." />
      </main>,
    );
    await expectNoAxeViolations(container);
  });
});
