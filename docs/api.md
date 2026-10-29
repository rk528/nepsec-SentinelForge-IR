# API reference

Base path `/api/v1`. Interactive OpenAPI documentation is served at `/api/v1/docs` and the
schema at `/api/v1/openapi.json`.

## Conventions

- **Authentication:** session cookie `sf_session` (HttpOnly, Secure, SameSite=Lax), set by
  `POST /auth/login` or `POST /auth/demo`.
- **CSRF:** every `POST`/`PATCH`/`DELETE` must send `X-CSRF-Token` equal to the `sf_csrf`
  cookie. The token is bound to the session server-side.
- **Ingestion** uses a per-source bearer key instead of cookies.
- **Errors:** `{"detail": "..."}` (validation errors return a list without echoing input).
  Every response carries `X-Request-ID`; 500 responses include it as `request_id`.
- **Pagination:** `page` (1-based) and `page_size`; responses are
  `{"items": [...], "total": n, "page": p, "page_size": s}`.
- **Tenancy:** IDs from another organisation return **404**.
- **Status codes:** 401 unauthenticated, 403 role/CSRF/demo restriction, 404 not found or other
  tenant, 409 conflict (stale `version`, pending actions, idempotency clash), 413 body too
  large, 422 validation or illegal transition, 429 rate limited (`Retry-After` header).

Roles: `viewer` < `analyst` < `lead` < `admin`.

A user signed in with an emailed temporary password (`must_change_password: true`) gets
`403 Change your temporary password to continue` from every endpoint except `/auth/me`,
`/auth/password`, `/auth/logout` and `/auth/logout-all`.

## Endpoints

| Method | Path | Min role | Notes |
|---|---|---|---|
| GET | `/health` | public | Liveness + DB round trip |
| GET | `/auth/config` | public | `{demo_mode}` |
| POST | `/auth/login` | public | Rate limited per IP and per account |
| POST | `/auth/demo` | public, demo mode only | `{role: analyst\|lead\|viewer}`; seeds the demo on first use |
| POST | `/auth/logout`, `/auth/logout-all` | any | Revokes this / all sessions |
| POST | `/auth/password` | any non-demo user | Change own password (`current_password`, `new_password`); revokes the user's other sessions |
| GET | `/auth/me` | any | Current user, including `must_change_password` and `alert_email_severity` |
| PATCH | `/auth/me/notifications` | any non-demo user | `{alert_email_severity: critical\|high\|medium\|low\|null}`: turn your own alert digest emails on (minimum severity) or off |
| POST | `/auth/reset-password/check` | public | `{token}`: who a one-time link is for; 400 when invalid, used or expired. Rate limited |
| POST | `/auth/reset-password` | public | `{token, new_password}`: sets the password, consumes the link and signs out every session. Rate limited |
| GET | `/dashboard/summary?days=` | viewer | KPIs, trends, telemetry health |
| GET/POST | `/incidents` | viewer / analyst | Filters: `q,status[],severity[],assignee_id,unassigned,tag,sort,order` |
| GET/PATCH | `/incidents/{id}` | viewer / analyst | PATCH requires current `version` |
| POST | `/incidents/{id}/transition` | analyst (reopen: lead) | `{version,status,verdict?,closure_reason?,reason?}` |
| GET/POST | `/incidents/{id}/notes` | viewer / analyst | Notes are append-only |
| GET/POST | `/incidents/{id}/events` | viewer / analyst | Link events as evidence |
| DELETE | `/incidents/{id}/events/{event_id}` | analyst | Unlink an event from the incident's evidence |
| POST | `/incidents/{id}/alerts` | analyst | `{alert_ids}`: bring alerts in, with their events; an alert in another incident moves |
| GET | `/incidents/{id}/alerts`, `/evidence`, `/timeline`, `/audit`, `/indicators` | viewer | |
| GET | `/incidents/{id}/report?format=json\|markdown` | viewer | |
| GET | `/alerts`, `/alerts/{id}` | viewer | Detail includes rule metadata and matching events |
| PATCH | `/alerts/{id}` | analyst | Status, disposition (+reason), assignee |
| POST | `/alerts/{id}/escalate` | analyst | New incident, or `{incident_id}` to link |
| POST | `/alerts` | analyst | Raise an alert by hand: `{title, description, severity, event_ids?, incident_id?}`; rule `SF-MAN-001` |
| POST | `/alerts/{id}/events` | analyst | `{event_ids, reason?}`: link more events; they go to its incident too |
| DELETE | `/alerts/{id}/incident` | analyst | Take the alert out of its incident (back to acknowledged) |
| GET | `/events`, `/events/{id}`, `/events/{id}/related` | viewer | `raw` is returned to analyst+ only |
| GET | `/events/users?hours=&q=` | viewer | Accounts seen in the window with counts of commands, sign-ins, failures, account changes and devices, plus their hosts; drives the User activity page |
| GET | `/detections` | viewer | Rules with latest self-test results |
| POST | `/detections/run`, `/detections/self-test` | analyst | |
| PATCH | `/detections/{rule_id}` | admin (non-demo) | Enable/disable |
| GET | `/attack/coverage` | viewer | Techniques, coverage state, gaps |
| GET | `/iocs`, `/iocs/{id}`, `/iocs/providers` | viewer | |
| POST | `/iocs/normalise` | viewer | Syntax only |
| POST | `/iocs/lookup` | analyst | `{value, incident_id?, force_refresh?}`; rate limited |
| PATCH | `/iocs/{id}` | analyst | Analyst verdict + note |
| GET | `/playbooks`, `/playbooks/runs?incident_id=` | viewer | |
| POST | `/playbooks/{id}/run` | analyst | `{incident_id, idempotency_key, parameters}` |
| GET | `/custom-playbooks?incident_id=` | viewer | Your organisation's playbooks; with `incident_id`, ones whose `trigger_rules` match the incident's alerts come first with `suggested: true` |
| POST | `/custom-playbooks` | lead | `{name, description, steps: [{kind: action\|task, title, action?, instructions?}], trigger_rules}`; `action` is a built-in playbook id |
| PATCH / DELETE | `/custom-playbooks/{id}` | lead | Edit (runs already started keep their snapshot) / archive |
| POST | `/custom-playbooks/{id}/start` | analyst | `{incident_id}`: starts a checklist run on an open incident |
| GET | `/custom-playbook-runs?incident_id=` | viewer | Runs with each step's status, note, who and when |
| POST | `/custom-playbook-runs/{id}/steps/{index}` | analyst | `{action: run\|complete\|skip\|reopen, note, parameters}`. `run` executes an automated step through `/playbooks/{id}/run` (same roles and approvals); `complete` a manual task (a note becomes evidence); `skip` needs a reason |
| GET | `/response-actions` | viewer | |
| POST | `/response-actions/{id}/decision` | lead, not the requester | `{decision, reason}` |
| POST | `/response-actions/{id}/cancel` | requester or lead | |
| GET | `/audit` | lead | Search by action (supports `*`), actor, target, time |
| GET | `/users` | viewer | Active users for assignment |
| GET/POST/PATCH | `/admin/users[/{id}]` | admin (non-demo for writes) | POST `{email, display_name, role}` generates a temporary password and emails it with a one-time set-password link and the workspace details. Returns `{id, email_sent, email_error}`; when the email was not sent it also returns `temporary_password` and `password_link` (shown once) |
| POST | `/admin/users/{id}/send-reset` | admin, non-demo | Email a one-time password reset link; the current password keeps working until it is used. 5 per user per hour |
| DELETE | `/admin/users/{id}` | admin, non-demo | Remove an account: sessions revoked, cannot sign in, hidden, email freed; history kept. Not yourself or the last admin |
| GET/POST | `/data-sources` | viewer / admin | Creation returns the ingest key once |
| POST | `/data-sources/{id}/rotate-key` | admin | Issue a new key (the old one stops working) |
| POST | `/data-sources/{id}/revoke-key` | admin | Invalidate the key; events kept |
| DELETE | `/data-sources/{id}` | admin | Only for sources with no stored events (409 otherwise) |
| GET | `/scenarios` | viewer | |
| POST | `/scenarios/{id}/run` | analyst in demo org, else admin | Injects synthetic events |
| GET | `/system` | viewer | Version, migration revision, integration status (no secrets) |
| POST | `/ingest/events` | ingest key | See below |
| POST | `/ingest/linux` | ingest key | Linux journal records from the shipper (`{"records": [journalctl -o json objects], "capture": "security"\|"all"}`), at most 500. With `capture: all`, unmapped lines are stored as `system.log`; see [connectors-linux.md](connectors-linux.md) |
| POST | `/ingest/fortigate` | ingest key | FortiGate syslog lines from the relay (`{"logs": [...]}`); see [connectors-fortigate.md](connectors-fortigate.md) |
| POST | `/ingest/microsoft/{format}` | ingest key | Native Microsoft JSON: `entra-signin`, `entra-audit`, `defender-alert`, `windows-event`; see [connectors-microsoft.md](connectors-microsoft.md) |

## Ingestion

```http
POST /api/v1/ingest/events
Authorization: Bearer sfk_xxxxxxxxxxxxxxxx
Content-Type: application/json

{
  "events": [
    {
      "event_time": "2026-10-27T09:15:00Z",
      "event_type": "auth.failure",
      "user_name": "fin.user01",
      "src_ip": "203.0.113.45",
      "host": "vpn-gw-01",
      "outcome": "failure",
      "raw": {"original": "fields"}
    }
  ],
  "run_detection": true
}
```

Response: `{"received", "inserted", "duplicates", "alerts_created", "alerts_updated"}`.

NepSec Intel sends its attack surface findings as `security.alert` events with `raw.product = "NepSec Intel"`. Rule SF-EXT-001 keeps the severity it sends (`raw.severity`: critical, high, medium or low), and when `raw.open_incident` is true an incident is opened for the new alert straight away (source `integration`), once.

Rules: 1–500 events per request, body up to 1 MiB, timestamps must include a timezone and may
not be more than 5 minutes in the future, unknown fields are rejected, IPs are validated, and
`event_type` must be one of `auth.success, auth.failure, process.start, iam.user_created,
iam.group_member_added, log.cleared, service.stopped, network.connection, dns.query,
proxy.request, email.delivered, file.created, security.alert, process.access, registry.set,
task.created`. Some rules read source-specific fields from `raw`: `logon_type` (SF-LAT-001),
`target_image` and `granted_access` (SF-CRED-001), `target_object` (SF-PERS-002) and
`task_name` (SF-PERS-001). Re-sending an identical event is a no-op
(fingerprint de-duplication). Rate limit: 60 requests per minute per source by default.
