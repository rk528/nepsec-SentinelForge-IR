# Deployment

Target: frontend and backend as two **Vercel Hobby** projects deployed from this GitHub
repository, with **Neon Free** PostgreSQL. No Docker is required anywhere.

Current state (27 October 2026):

| Component | Status |
|---|---|
| Neon project `sentinelforge-ir` (us-east-1), branches `production` and `development` | Created |
| Schema migration `0001` on `production` | Applied (via Neon SQL, equivalent to `alembic upgrade head`) |
| Demo data | Seeds itself on the first demo sign-in when `DEMO_MODE=true` |
| Vercel projects | **Not created yet**: the Vercel connection needs access to the team (see below) |

## 1. Neon

1. In the Neon console open project **sentinelforge-ir** → **Connect**, database
   `sentinelforge`, branch `production`.
2. Copy two connection strings:
   - **Pooled** (host contains `-pooler`) → `DATABASE_URL`
   - **Direct** (no `-pooler`) → `DATABASE_URL_UNPOOLED` (migrations only)
3. Keep `sslmode=require` in both.

Never paste these into chat, commits or issue trackers. Put them only in Vercel's environment
variable settings and a local, git-ignored `backend/.env`.

## 2. Backend project on Vercel

1. Vercel dashboard → **Add New → Project** → import `rk528/nepsec-SentinelForge-IR`.
2. Name: `sentinelforge-ir-api`. **Root Directory: `backend`**. Framework preset: FastAPI
   (detected from `pyproject.toml`, entrypoint `app.main:app`).
3. Environment variables (Production):

| Name | Value | Type |
|---|---|---|
| `DATABASE_URL` | Neon pooled string | Sensitive |
| `DATABASE_URL_UNPOOLED` | Neon direct string | Sensitive |
| `APP_ENV` | `production` | Plain |
| `DEMO_MODE` | `true` for the public demo | Plain |
| `COOKIE_SECURE` | `true` | Plain |
| `VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY`, `OTX_API_KEY` | optional | Sensitive |
| `NEPSECINTEL_API_KEY` | optional: an API key from NepSec Intel's Workspace page (needs a Pro or admin account there) | Sensitive |

4. Deploy, then check `https://<backend-domain>/api/v1/health` returns
   `{"status":"ok","database":"ok",...}`.

## 3. Frontend project on Vercel

1. Import the same repository again. Name: `sentinelforge-ir`. **Root Directory: `frontend`**.
   Framework: Next.js.
2. Environment variable (Production and Preview):

| Name | Value | Type |
|---|---|---|
| `BACKEND_URL` | `https://<backend-domain>` (no trailing slash) | Plain (server-only; no `NEXT_PUBLIC_` prefix) |

`BACKEND_URL` is read when the rewrite table is built, so **redeploy the frontend after
changing it**.

3. Deploy, open `https://<frontend-domain>/login` and choose a demo role. The first demo
   sign-in on an empty database creates the synthetic workspace (allow up to ~30 seconds).

Both projects redeploy automatically on pushes to `main`; pull requests get preview
deployments.

## Granting the Vercel connection access (for automated setup)

The automated setup attempt failed with `403 Not authorized: ... scope "petlyfyp"`. To let an
agent create the projects, grant the Vercel integration access to that team in Vercel
(Account → Integrations / Connected apps), or create the projects manually as above.

## Migrations

Run migrations as an explicit step before deploying a version that needs them, never on
application start-up:

```bash
cd backend
# DATABASE_URL_UNPOOLED is read from the environment or backend/.env
python -m alembic upgrade head
python -m alembic current
```

Migrations are additive in this release. Do not run `alembic downgrade` against production
without a backup: it drops tables.

## Health checks

- Backend: `GET /api/v1/health` (public, no configuration details; 503 if the database is unreachable)
- Frontend: `GET /login` returns 200; `GET /api/v1/health` through the frontend proves the rewrite works

## Rollback

- **Application:** Vercel dashboard → project → Deployments → select the previous production
  deployment → **Promote to Production** (instant, no rebuild).
- **Database:** Neon → branch `production` → restore to a point in time within the plan's
  history window, or restore into a new branch and repoint `DATABASE_URL`.

## Backup and export

- Logical export: `pg_dump "$DATABASE_URL_UNPOOLED" --format=custom -f sentinelforge.dump`
  (requires a local PostgreSQL client).
- Before risky changes, create a Neon branch from `production` as an instant copy.
- Reports can be exported per incident as Markdown or JSON from the UI.

## Demo reset

The demo workspace can be deleted only with an explicit confirmation phrase:

```bash
python -m app.cli reset-demo          # prompts for "RESET DEMO DATA"
```

The next demo sign-in reseeds it.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| Health shows `database: unreachable` | `DATABASE_URL` missing/wrong, or Neon compute quota exhausted |
| Login works locally but not on Vercel | `COOKIE_SECURE=true` requires HTTPS (correct on Vercel); check `BACKEND_URL` |
| 404s on `/api/...` from the frontend | `BACKEND_URL` unset at build time; set it and redeploy |
| First request slow | Python cold start plus Neon resume; subsequent requests are fast |
| `prepared statement ... does not exist` | A pooled URL used with prepared statements; the app disables them, so check for custom scripts |
