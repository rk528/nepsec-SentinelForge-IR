# UI design research

**Date of review:** 27 October 2026
**Reviewer:** project engineer (assisted by Claude Code)
**Method:** Full-page screenshots and extracted page structure captured with Firecrawl (the Chrome
extension was not connected in this session), plus text extraction with a web fetcher. Only
public marketing and product pages were reviewed; no product accounts were used, so in-app
screens were studied only where the vendor shows them on public pages (product screenshots,
embedded tours and videos).

These references informed interaction principles only. No layouts, assets, logos, icons or code
were copied. SentinelForge IR uses its own palette, type scale, components and logo mark.

## Pages reviewed

| # | Product | Page actually reviewed | Notes |
|---|---|---|---|
| 1 | Linear | https://linear.app/ | Home page with a large in-app issue view (sidebar, issue body, activity feed, properties panel). |
| 2 | Vercel | https://vercel.com/ | Home page. Restrained monochrome layout; no deployment UI is shown publicly on this page. |
| 3 | Grafana | https://grafana.com/grafana/ (redirects to /products/cloud/grafana/) | Product page with breadcrumbs and a real dashboard screenshot (time-series, gauges, bar panels). |
| 4 | Sentry | https://sentry.io/product/error-monitoring/ | **Substitution:** the suggested https://sentry.io/product/issues/ returned HTTP 404. The error-monitoring page shows the issue stream and issue detail in its product screenshots. |
| 5 | CrowdStrike | https://www.crowdstrike.com/en-us/platform/next-gen-siem/ | Product page with an "Agentic SOC dashboard" screenshot (KPI tiles, triage flow). |
| 6 | Splunk | https://www.splunk.com/en_us/products/enterprise-security.html | **Substitution:** the `splunk-enterprise-security.html` URL returned 404; the current ES product page was used. It embeds an interactive tour showing the "Executive summary" view. |

## Observations and how each informs SentinelForge IR

### 1. Linear: dense, status-led work queues and a properties side panel

**Observed.** The in-app screenshot shows a narrow left sidebar grouped into personal views
(Inbox, My issues, Reviews), a "Workspace" section and "Favorites". The issue view uses a compact
header line (`DRV-8852 Faster app launch` with a status glyph), a body with an **Activity** feed
in which automated and human events are interleaved chronologically ("…created the issue via
Slack…", "…added the labels Performance and iOS"), and a **right-hand Properties panel**
(status, priority, assignee, cycle, labels as small chips). Paging controls (`1 / 84` with
up/down arrows) let the user step through a queue without returning to the list. Branding data:
near-black background (`#08090A`), body text around 15px, 4px spacing base, 8px radii, low-energy
visual personality.

**Adopted.**
- Incident detail uses a main column (overview, timeline, evidence, notes) and a **right-hand
  properties rail** (status, severity, assignee, verdict, tags, timestamps).
- A single **chronological activity timeline** merges telemetry, alerts, status changes, notes
  and response actions, with system actions visually quieter than analyst actions.
- Short **human references** (`INC-0007`) appear before titles everywhere.
- Sidebar groups: *Operate* (overview, incidents, alerts, events), *Investigate* (threat intel,
  investigations), *Engineer* (detections, ATT&CK coverage), *Respond* (playbooks, response
  actions, reports), *Govern* (audit, settings).

**Adapted.** Linear's command input is conversational; SentinelForge uses a classic **⌘K / Ctrl+K
command palette** for navigation and record lookup, which suits keyboard-heavy analysts.

**Rejected.** Pill-shaped (fully rounded) buttons. They read as consumer marketing; SentinelForge
uses 6px radii for controls.

### 2. Vercel: restraint, monochrome surfaces and quiet status

**Observed.** A near-white page with a very small palette, large tightly tracked headline
("Agentic Infrastructure"), three-word value statements, and paired primary/secondary buttons
of equal height (filled dark vs outlined). The navigation is minimal (Products, Resources,
Enterprise, Pricing). No decorative colour is used for structure; hierarchy comes from type
weight and spacing alone.

**Adopted.**
- **Colour is reserved for meaning** (severity, status, focus). Structure uses neutral greys,
  borders and spacing.
- **Small status dots plus a text label** (never colour alone) for data-source health and
  response-action state.
- Paired primary/secondary button styles with identical height and padding.

**Rejected.** Light-first presentation. SOC tools are used for long shifts in dim rooms, so
SentinelForge is dark-first (see design principles below).

### 3. Grafana: time ranges, panels and breadcrumbs

**Observed.** Breadcrumbs (`Grafana Cloud / Grafana`) above the page title; the dashboard
screenshot shows a grid of titled panels (Memory/CPU, logins, server requests, page load), each
with its own legend beneath the chart, gauges for single values, and a global search/time
control in the top bar.

**Adopted.**
- **Breadcrumbs** on all nested pages (`Incidents / INC-0007`).
- Charts live in **titled panels with legends and tooltips**, and the overview has a **global
  time-range control** that all panels respect.
- Gridlines and axes are low contrast so the data is the brightest thing in a panel.

**Rejected.** Gauges. A single number with context ("12 open, 3 critical") is easier to read and
does not imply a target or threshold that does not exist.

### 4. Sentry: issue streams and evidence-rich detail

**Observed.** The issue stream screenshot shows filter chips above the list (project,
environment, time period, a search box pre-filled with `is:unresolved`) and columns for **Last
Seen, Age, Trend, Events, Users, Priority**. The issue detail shows a per-issue events-over-time
chart, a **"Highlights" key-value grid** (handled, level, release, os.name, transaction), and
navigation between individual events (First / Latest). Primary actions (Resolve, Archive) sit at
the top left of the detail.

**Adopted.**
- The alert queue shows **first seen, last seen and occurrence count** next to severity, because
  deduplicated alerts are about recurrence as much as content.
- Alert and event detail pages use a **key-value "highlights" grid** for normalised fields, with
  the raw JSON available below it for authorised roles.
- **Search-first filtering**: a text query plus filter controls, with filters reflected in the URL
  so views can be shared.
- Primary triage actions sit at the top of the detail view.

**Adapted.** Sentry's sparkline "trend" column is replaced by first/last seen, because our
alert volumes are low and a sparkline of one or two points is noise.

### 5. CrowdStrike: severity-forward KPIs and SOC vocabulary

**Observed.** The "Agentic SOC dashboard" screenshot opens with **KPI tiles** (attacks assessed,
detections triaged, open investigations, mean time to resolve, average triage time) each with a
small trend line and delta, followed by a large Sankey-style **triage flow** from data sources
(Network, Email, Cloud, Endpoint, Identity) through detections to outcomes (awaiting input,
promoted to case, closed). Vocabulary: detections, investigations, triage, "promoted to case".

**Adopted.**
- The overview starts with **KPI tiles** for open incidents, detections in range, MTTA and MTTR.
  Each tile states its sample size, and MTTA/MTTR show "No data" rather than zero when no
  incidents qualify.
- Vocabulary: *detection rule → alert → incident*, *escalate*, *triage*, *disposition*, *verdict*.
- A "detections by rule" breakdown (a plain ranked bar list) answers the same question as the
  Sankey's left side.

**Rejected.**
- The Sankey triage flow. It is visually striking but hard to read precisely and would be mostly
  empty with portfolio-scale data. It would be decoration.
- Red-dominant branding. In a security tool red must mean "critical" and nothing else.

### 6. Splunk Enterprise Security: executive summary and time controls

**Observed.** The embedded tour shows a dense top navigation (Mission Control, Analytics,
Security content, Configure, Search), an **Executive summary** page with a **segmented
time-range control (24h / 7d / 30d / 90d / 1y)**, an "Include suppressed findings" toggle, and
page-level actions (Download, Edit, Actions menu) aligned right on the title row.

**Adopted.**
- A **segmented time-range control** (24h / 7d / 14d / 30d) on the overview and alert queue.
- **Page header pattern:** title and description on the left, page actions aligned right.
- Toggles for scoping a queue (for example "show escalated alerts").

**Rejected.** Top-bar mega navigation. A persistent, collapsible left sidebar scales better to
16 routes and keeps the current location visible.

## SentinelForge IR visual identity

**Name and mark.** A small geometric mark: a hexagonal "forge" outline with an inner chevron,
drawn as an inline SVG in the brand violet. It is original and contains no third-party shapes.

**Principles.**
1. **Evidence before decoration.** Every pixel of colour encodes severity, status or focus.
   Charts appear only where a trend or distribution answers a real question.
2. **Calm density.** Tables use 13px text and 36px rows so a lead can scan 25 alerts without
   scrolling, but spacing never drops below the 4px grid.
3. **Severity is not confidence.** Severity uses a coloured badge; confidence uses a neutral
   three-step meter. They are never merged into one colour.
4. **Provenance is visible.** Every value that came from outside (provider results, raw logs,
   generated summaries) is labelled with where it came from and when.
5. **Synthetic is obvious.** Demo data carries a persistent "Synthetic data" banner and badges.
6. **Keyboard first, mouse friendly.** ⌘K / Ctrl+K palette, visible focus rings and logical tab
   order on every page.

**Palette.** Charcoal surfaces (`#0B0C10` base, three elevation steps), cool grey text, and one
restrained violet accent (`#8B7CF6`) for primary actions, focus and selection. Severity uses a
separate, colour-blind-aware ramp: critical rose `#F0506E`, high orange `#F59E42`, medium amber
`#E7C04A`, low blue `#5AA9E6`, informational grey `#8A93A6`. Every severity and status is also
written as text.

**Type.** Inter for interface text and JetBrains Mono for machine values (IP addresses, hashes,
IDs, command lines), loaded with `next/font` so no third-party font requests happen at runtime.

## Summary of decisions

| Pattern | Source | Decision |
|---|---|---|
| Properties side panel on detail views | Linear | Adopted |
| Chronological mixed activity feed | Linear | Adopted (incident timeline) |
| Conversational command input | Linear | Adapted to a ⌘K command palette |
| Pill buttons | Linear | Rejected |
| Colour only for meaning; status dot + label | Vercel | Adopted |
| Light-first theme | Vercel | Rejected (dark-first) |
| Breadcrumbs, titled panels with legends | Grafana | Adopted |
| Gauges for single values | Grafana | Rejected |
| First/last seen + count columns; highlights grid | Sentry | Adopted |
| Sparkline trend column | Sentry | Adapted (first/last seen instead) |
| KPI tiles with sample context | CrowdStrike | Adopted |
| Sankey triage flow | CrowdStrike | Rejected (decorative at this scale) |
| Segmented time range; header actions right | Splunk ES | Adopted |
| Top mega-navigation | Splunk ES | Rejected (left sidebar instead) |
