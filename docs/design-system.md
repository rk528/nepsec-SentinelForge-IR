# Design system

The visual system is adopted from **[shadcn/ui](https://ui.shadcn.com)** (MIT licence):
its `zinc` dark theme with the `violet` accent, its `dashboard-01` block (sidebar-inset
layout, `SectionCards` KPI tiles, data table styling) and its `login-03` block. The
template's component specifications (button and input sizes, card header, outline badges,
outline toggle groups, sidebar menu buttons, user menu in the sidebar footer) are
re-implemented on this project's existing components, so behaviour, accessibility and tests
are unchanged. Product-specific patterns (severity glyphs, provenance, synthetic labels)
come from the research in [ui-research.md](ui-research.md). Tokens live in
`frontend/src/app/globals.css` (Tailwind v4 `@theme`); components live in
`frontend/src/components/ui`.

## Principles

1. Colour encodes meaning (severity, status, focus), never structure.
2. Every colour signal is paired with text.
3. Severity and confidence are visually distinct (coloured badge vs neutral meter).
4. Provenance is always visible: where data came from and when.
5. Synthetic data is always labelled.
6. Keyboard first: visible focus, logical order, Ctrl/⌘+K palette.

## Tokens

| Token | Value | Use |
|---|---|---|
| Themes | dark (default) and light | `data-theme` on `<html>`, set before paint from the saved choice or the OS; toggle in the header and on the login page. Light uses shadcn zinc light with darker severity shades for 4.5:1 |
| `shell` | `#131316` | Sidebar and page background around the inset main area |
| `canvas` / `surface` / `raised` / `overlay` | `#09090b` / `#131316` / `#1b1b1f` / `#222227` | Inset main area, cards, hover/selected, menus |
| `line` / `line-strong` | `#232328` / `#2f2f36` | Borders |
| `fg` / `muted` / `subtle` | `#fafafa` / `#a1a1aa` / `#8c8c96` | Text (zinc); all meet 4.5:1 on every surface (axe-verified) |
| `accent` | `#a78bfa` | shadcn violet: primary actions, focus ring, selection |
| `sev-critical/high/medium/low/info` | `#f0506e` / `#f59e42` / `#e7c04a` / `#5aa9e6` / `#8a93a6` | Severity only |
| `ok` / `warn` / `danger` / `info` / `teal` | | Status |
| Radii | 6 / 8 / 10 / 14 px | shadcn scale (`--radius` 0.625rem); controls 8 px, cards 14 px |
| Type | Inter (UI), JetBrains Mono (IPs, hashes, IDs, commands) | Body and tables 14 px (`text-sm`), page titles 24 px |

## Components

| Component | File | Notes |
|---|---|---|
| App shell, collapsible sidebar, mobile drawer, top bar, user menu | `shell/app-shell.tsx` | Sidebar state persisted via `useSyncExternalStore` |
| Command palette | `shell/app-shell.tsx` | `cmdk`; pages plus live incident search |
| Breadcrumbs, page header with actions | `ui/primitives.tsx` | |
| Button, input, select, textarea, field with errors | `ui/primitives.tsx` | Labelled controls, `aria-invalid` |
| Panel, key-value grid, KPI tile | `ui/primitives.tsx`, dashboard | |
| Data table with sorting, row navigation, responsive column hiding | `ui/data-table.tsx` | `aria-sort`, caption |
| Pagination | `ui/data-table.tsx` | |
| Search box (debounced), filter chips, toolbar | `ui/filters.tsx` | State kept in the URL |
| Segmented time range | `ui/primitives.tsx` | `radiogroup` semantics |
| Severity badge, status badges, verdict, confidence meter, synthetic/simulated badges | `ui/badges.tsx` | |
| Dialog, confirm dialog, tooltip, toasts | `ui/overlays.tsx` | Radix primitives; toasts in a live region |
| Skeletons, empty, error-with-retry states | `ui/primitives.tsx` | Error state shows request ID |
| Event list, event dialog, JSON viewer, evidence viewer, timeline | `investigation.tsx` | Untrusted data rendered as text |
| Severity trend chart, bar list | `charts.tsx` | Recharts with legend, tooltip, and an equivalent hidden table |

## Responsive behaviour

The sidebar becomes a drawer below 768 px; tables hide secondary columns at `sm`/`md`/`lg`
breakpoints; detail pages collapse the properties rail under the main column below `lg`.

## Motion

160–180 ms fades and slides for overlays only; disabled under `prefers-reduced-motion`.
