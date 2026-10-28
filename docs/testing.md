# Testing

All tests run without Docker. Results below were recorded on 27 October 2026 on Windows 11,
Python 3.12, Node 24.

## Backend: `cd backend && python -m pytest`

Tests run against a real PostgreSQL database because constraints, JSONB, `ON CONFLICT` and
the audit trigger matter. If `TEST_DATABASE_URL` is unset, `tests/conftest.py` starts a local
PostgreSQL 16 with [pgserver](https://pypi.org/project/pgserver/); CI uses a `postgres:17`
service container. Migrations are applied with Alembic at session start, so the migration
itself is tested.

**Result: 153 passed.**

| File | Covers |
|---|---|
| `test_detection_rules.py` | Every rule passes its fixtures; metadata completeness; threshold boundaries; event ID preservation; hostile command lines treated as data; IP classification; RDP fan-out reported once per burst; malformed raw fields ignored |
| `test_workflow.py` | Ingest → detect → alert → escalate → notes → transitions → close → timeline → report → audit; idempotent re-ingest; detection re-runs; reopen rules |
| `test_security.py` | Auth required; generic login errors; password not echoed; login rate limit; CSRF; logout revocation; idle expiry; cookie flags; viewer/admin restrictions; ingest key; cross-tenant reads and writes (IDOR); assignee scoping; malicious payloads; Markdown escaping; validation; body size; append-only audit |
| `test_response.py` | All playbooks; idempotency; separation of duties; internal IP refusal; closure blocked by pending actions; demo seed, login, restrictions, reset; first demo sign-in seeds; dashboard metrics without data; ATT&CK coverage states |
| `test_linux.py` | Ubuntu journal mapping (SSH, GDM/console/su/sudo PAM, sudo commands and denials, useradd/usermod/gpasswd, service stops incl. byte-array messages and old systemd); SSH brute force, new sudo user with actor, logging stopped end to end; reboot stops ignored; shipper filtering, cursor only advanced after delivery, payload round trip; full capture: auditd execve records assembled into one command each (hex-encoded arguments, PROCTITLE fallback), USB and session-end mapping, unmapped lines kept as `system.log`, skipped by detection and deleted after the retention period |
| `test_custom_playbooks.py` | Building playbooks (lead only, unknown actions and rules refused), rule-based suggestions, automated steps through the built-in service, manual tasks with notes as evidence, gated steps completing after a second lead approves, skip reasons, reopening, archiving, tenant isolation |
| `test_onboarding.py` | Welcome email content (temporary password, one-time link, role and system details, HTML escaping); forced password change blocks the API; links are single-use, expire, and are retired by a newer link or a password change; admin-only and org-scoped resets; fallback when email is not configured; Resend request and error handling |
| `test_microsoft.py` | Entra ID sign-in and audit, Defender alert and Windows event mapping (Graph, Azure Monitor, Log Analytics and PowerShell shapes); MFA interrupts and machine logons skipped; Sysmon 10/13, task creation (4698, incl. escaped Log Analytics XML) and RDP logon types; alerts raised end to end; re-forwarded alerts de-duplicated; batch limits; ingest key required; `-CaptureAll` events kept as `system.log` |
| `test_fortigate.py` | FortiOS key=value and JSON lines, syslog headers, time zones, SSL-VPN brute force end to end, traffic/DNS/web filter/IPS mapping, relay traffic filter |
| `test_intel.py` | IOC normalisation (refanging, canonical URLs, hashes), invalid input, unconfigured providers, provider mapping, caching, rate-limit handling, "zero detections is unknown", timeouts, analyst vs provider verdicts |

Also run: `ruff check .`, `ruff format --check .` (clean) and `pip-audit -r requirements.txt`
(no known vulnerabilities).

## Frontend unit and component tests: `cd frontend && npm test`

Vitest + Testing Library + axe-core in jsdom. **Result: 23 passed.** Covers the open-redirect
guard, query encoding, formatting that never fabricates durations, severity/confidence labels,
inert rendering of hostile content, debounced search, filter chips, segmented control, error and
retry states, and axe checks on core components (colour contrast is checked in E2E instead).

Also run: `npm run lint` (clean), `npm run typecheck` (clean), `npm run build` (succeeds),
`npm audit --omit=dev --audit-level=high` (0 vulnerabilities).

## End-to-end: `cd frontend && npm run test:e2e`

Playwright against a running frontend and API with the demo seeded, run once per theme (`PW_COLOR_SCHEME=dark|light`) so the axe contrast scan covers both palettes. Locally it uses the
installed Chrome (`PW_CHANNEL=chrome`); CI uses bundled Chromium. **Result: 10 passed.**

- Unauthenticated redirect to login with `next`
- Analyst workflow: open incident, view evidence, add note, start investigating, timeline update
- Viewer cannot create incidents
- Alert detail shows rule, false positives and matching events
- axe WCAG 2 A/AA scan with no serious or critical violations on Overview, Incidents, Alerts,
  Threat intel, ATT&CK coverage and Settings

The axe scan found a real contrast issue (secondary text at 4.34:1 on tinted cards); the
`subtle` token was raised to `#858ca2` (≥4.8:1 on all surfaces) and the scan now passes.

## CI

`.github/workflows/ci.yml` runs backend (lint, format, tests, pip-audit), frontend (lint,
types, unit tests, build, npm audit), gitleaks secret scanning, and the full Playwright suite
against a seeded Postgres service. The repository is private, so CI results are visible in the
GitHub Actions tab; they have not been independently confirmed from this environment.

## Not covered

- Load and performance testing.
- Real threat-intel provider calls (all provider tests use mocked HTTP).
- Browsers other than Chromium.
