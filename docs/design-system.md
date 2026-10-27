# Design system

Informed by the research in [ui-research.md](ui-research.md). Tokens live in
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
| `canvas` / `surface` / `raised` / `overlay` | `#0b0c10` / `#111319` / `#161922` / `#1c202b` | Elevation steps |
| `line` / `line-strong` | `#232836` / `#30364a` | Borders |
| `fg` / `muted` / `subtle` | `#e7e9ef` / `#a0a7b8` / `#858ca2` | Text; `subtle` meets 4.5:1 on all surfaces |
| `accent` | `#8b7cf6` | Primary actions, focus, selection |
| `sev-critical/high/medium/low/info` | `#f0506e` / `#f59e42` / `#e7c04a` / `#5aa9e6` / `#8a93a6` | Severity only |
| `ok` / `warn` / `danger` / `info` / `teal` | | Status |
| Radii | 4 / 6 / 8 / 12 px | Controls use 6 px |
| Type | Inter (UI), JetBrains Mono (IPs, hashes, IDs, commands) | Body 14 px, tables 13 px |

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
