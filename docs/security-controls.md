# Security controls

Each control lists where it is implemented and how it is verified. Tests are in
`backend/tests` unless noted.

| Area | Control | Implementation | Verified by |
|---|---|---|---|
| Authentication | argon2id password hashing; constant-time dummy verify for unknown accounts | `app/security.py` | `test_login_failure_is_generic_and_audited` |
| Authentication | Generic login error; failed logins audited | `routers/auth.py` | same |
| Onboarding | Admins never choose passwords: a random temporary password must be changed before any other API call; enforced server-side | `services/onboarding.py`, `deps.py` | `test_temporary_password_must_be_changed_before_anything_else` |
| Password links | 256-bit one-time tokens, only SHA-256 stored, 24 h expiry; a new link, a password change or use retires earlier links; carried in the URL fragment so they never reach server logs or `Referer` | `services/onboarding.py`, `routers/auth.py`, `app/reset-password` | `test_invite_link_sets_password_once`, `test_admin_reset_email_revokes_sessions_and_earlier_links`, `test_expired_link_is_rejected` |
| Email content | User-supplied names HTML-escaped; temporary passwords and links never logged or audited | `services/onboarding.py`, `services/mail.py` | `test_names_are_escaped_in_html_email`, `test_invite_email_has_temp_password_link_and_system_info` |
| Sessions | Opaque 256-bit tokens, only SHA-256 stored; 12 h absolute, 120 min idle timeout | `routers/auth.py`, `deps.py` | `test_idle_session_expires`, `test_logout_revokes_session` |
| Sessions | HttpOnly, Secure, SameSite=Lax cookies | `routers/auth.py` | `test_session_cookie_flags` |
| Sessions | Logout and "log out everywhere" revoke server-side | `routers/auth.py` | `test_logout_revokes_session` |
| CSRF | Per-session token in a header, compared to a stored hash | `deps.py` | `test_csrf_required_for_mutations` |
| Authorisation | Role hierarchy enforced on every route | `deps.py` | `test_viewer_is_read_only...`, `test_admin_only_operations` |
| Tenant isolation | Every query filtered by the caller's `org_id`; 404 for other tenants | routers, `services/incidents.py` | `test_cross_tenant_access_is_rejected` |
| Separation of duties | Requester cannot approve their own action; approvals need lead | `playbooks/service.py` | `test_firewall_block_requires_approval_from_a_different_lead` |
| Safe response | Disruptive actions simulated; internal/reserved IPs refused | `playbooks/registry.py` | `test_block_refuses_internal_addresses` |
| Demo mode | Demo users have no password, work only with `DEMO_MODE=true`, cannot perform admin writes | `deps.py`, `routers/admin.py` | `test_demo_seed_login_and_reset`, `test_demo_login_disabled_without_demo_mode` |
| Input validation | Pydantic schemas with lengths, enums, IP parsing, tz-aware timestamps, unknown fields rejected | `schemas.py` | `test_input_validation` |
| Request size | 256 KiB default, 1 MiB for ingest, enforced on streamed bodies | `main.py` | `test_request_body_size_limit` |
| Rate limiting | Postgres fixed-window counters: login (per IP and account), ingest, intel, demo, scenarios | `ratelimit.py` | `test_login_rate_limit` |
| Untrusted data | Raw logs stored as JSONB and rendered only as escaped text; never executed or interpreted | `components/investigation.tsx` | `test_malicious_payloads_are_stored_as_inert_data`, frontend `components.test.tsx` |
| Report output | Untrusted values rendered as inline code, analyst text escaped in Markdown | `services/reports.py` | `test_markdown_report_escapes_untrusted_values` |
| Error handling | Validation errors strip input echoes; 500s return only a request ID | `main.py` | `test_validation_errors_do_not_echo_passwords` |
| Headers | API: CSP `default-src 'none'`, nosniff, DENY framing, no-store, HSTS in production. Frontend: CSP, nosniff, DENY, referrer policy, HSTS | `main.py`, `next.config.ts` | `test_health_is_public` |
| Open redirects | Post-login `next` restricted to same-site relative paths | `lib/navigation.ts` | frontend `lib.test.ts` |
| Audit | Append-only audit log with actor, IP, request ID; DB trigger blocks tampering | migration 0001 | `test_audit_log_is_append_only` |
| Secrets | No secrets in code or seeds; keys from environment; ingest keys shown once and stored hashed; no `NEXT_PUBLIC_` secrets | config, `.gitignore` | gitleaks in CI |
| Dependencies | `pip-audit` and `npm audit` in CI; exact version pins | `.github/workflows/ci.yml` | CI |
| Threat intel | Missing data reported as "unknown"; provider and analyst verdicts stored separately | `intel/` | `test_zero_detections_is_unknown_not_safe` |

## Known limitations

- Single-factor password authentication; no MFA or SSO yet.
- No account lockout beyond rate limiting.
- No self-service "forgot password": an administrator sends reset links. Emailed temporary
  passwords are only as private as the recipient's mailbox; the one-time link and forced
  change limit how long that exposure lasts.
- The frontend CSP allows `'unsafe-inline'` scripts because Next.js injects inline bootstrap
  scripts; a nonce-based CSP would remove this.
- Rate limiting by IP depends on the hosting proxy's `X-Forwarded-For`; per-account limits do
  not.
- Detection rules and playbook definitions are platform-wide, so only non-demo admins can
  toggle rules.
- The public demo shares one synthetic workspace: demo visitors can see each other's notes.
