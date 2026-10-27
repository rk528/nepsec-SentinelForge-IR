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

## Endpoints

| Method | Path | Min role | Notes |
|---|---|---|---|
| GET | `/health` | public | Liveness + DB round trip |
| GET | `/auth/config` | public | `{demo_mode}` |
| POST | `/auth/login` | public | Rate limited per IP and per account |
| POST | `/auth/demo` | public, demo mode only | `{role: analyst\|lead\|viewer}`; seeds the demo on first use |
| POST | `/auth/logout`, `/auth/logout-all` | any | Revokes this / all sessions |
| GET | `/auth/me` | any | Current user |
| GET | `/dashboard/summary?days=` | viewer | KPIs, trends, telemetry health |
| GET/POST | `/incidents` | viewer / analyst | Filters: `q,status[],severity[],assignee_id,unassigned,tag,sort,order` |
| GET/PATCH | `/incidents/{id}` | viewer / analyst | PATCH requires current `version` |
| POST | `/incidents/{id}/transition` | analyst (reopen: lead) | `{version,status,verdict?,closure_reason?,reason?}` |
| GET/POST | `/incidents/{id}/notes` | viewer / analyst | Notes are append-only |
| GET/POST | `/incidents/{id}/events` | viewer / analyst | Link events as evidence |
| GET | `/incidents/{id}/alerts`, `/evidence`, `/timeline`, `/audit`, `/indicators` | viewer | |
| GET | `/incidents/{id}/report?format=json\|markdown` | viewer | |
| GET | `/alerts`, `/alerts/{id}` | viewer | Detail includes rule metadata and matching events |
| PATCH | `/alerts/{id}` | analyst | Status, disposition (+reason), assignee |
| POST | `/alerts/{id}/escalate` | analyst | New incident, or `{incident_id}` to link |
| GET | `/events`, `/events/{id}`, `/events/{id}/related` | viewer | `raw` is returned to analyst+ only |
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
| GET | `/response-actions` | viewer | |
| POST | `/response-actions/{id}/decision` | lead, not the requester | `{decision, reason}` |
| POST | `/response-actions/{id}/cancel` | requester or lead | |
| GET | `/audit` | lead | Search by action (supports `*`), actor, target, time |
| GET | `/users` | viewer | Active users for assignment |
| GET/POST/PATCH | `/admin/users[/{id}]` | admin (non-demo for writes) | |
| GET/POST | `/data-sources` | viewer / admin | Creation returns the ingest key once |
| POST | `/data-sources/{id}/rotate-key` | admin | |
| GET | `/scenarios` | viewer | |
| POST | `/scenarios/{id}/run` | analyst in demo org, else admin | Injects synthetic events |
| GET | `/system` | viewer | Version, migration revision, integration status (no secrets) |
| POST | `/ingest/events` | ingest key | See below |

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

Rules: 1–500 events per request, body up to 1 MiB, timestamps must include a timezone and may
not be more than 5 minutes in the future, unknown fields are rejected, IPs are validated, and
`event_type` must be one of `auth.success, auth.failure, process.start, iam.user_created,
iam.group_member_added, log.cleared, service.stopped, network.connection, dns.query,
proxy.request, email.delivered, file.created`. Re-sending an identical event is a no-op
(fingerprint de-duplication). Rate limit: 60 requests per minute per source by default.
