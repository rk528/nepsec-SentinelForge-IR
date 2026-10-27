# Free-tier services and limitations

Checked against official vendor documentation on **27 October 2026**. Free tiers change;
re-check the linked pages before relying on these numbers. None of these services is
"permanently free", and no billing method has been added to any account for this project.

## Vercel Hobby (frontend and backend functions)

Source: <https://vercel.com/docs/plans/hobby>, <https://vercel.com/docs/functions/limitations>

| Limit | Hobby |
|---|---|
| Use | **Non-commercial, personal use only** (fair use guidelines). Fine for a portfolio demo. |
| Function max duration | 300 s default and maximum (`backend/vercel.json` sets 60 s) |
| Function memory | 2 GB / 1 vCPU |
| Request/response body | 4.5 MB (the API itself caps bodies at 256 KiB, ingest at 1 MiB) |
| Function invocations | First 1,000,000 per month |
| Active CPU | 4 CPU-hours per month |
| Provisioned memory | 360 GB-hours per month |
| Fast Data Transfer | First 100 GB per month |
| Deployments | 100 per day |
| Runtime logs | 1 hour retention |
| Over-limit behaviour | Features pause until 30 days have passed; there is no paid overage on Hobby |

Implications:

- **Cold starts.** Python functions start cold after idle periods; the first request can take
  a few seconds. The UI retries transient failures twice.
- **No background workers.** Detection runs inside the ingest request. Large batches are capped
  at 500 events per request.
- **Short log retention.** One hour of runtime logs. The application's own audit log in
  Postgres is the durable record.

## Neon Free (PostgreSQL)

Source: <https://neon.com/docs/introduction/plans>, <https://neon.com/pricing>

| Limit | Free |
|---|---|
| Compute | 100 CU-hours per project per month |
| Storage | 0.5 GB per project |
| Branches | 10 per project |
| Network transfer | 5 GB public transfer per project per month |
| Autosuspend | After 5 minutes idle; cannot be disabled on Free |
| Over-limit behaviour | Compute suspends when the monthly allowance is used up |

Implications:

- **Wake-up latency.** After 5 idle minutes the compute suspends; the next query waits for it to
  resume (typically under a second or two). `pool_pre_ping` discards dead pooled connections.
- **Storage.** The seeded demo uses well under 10 MB. Storing real log volumes would exhaust
  0.5 GB quickly; this deployment is a demonstration, not a production SIEM.
- **Point-in-time restore** is limited to the plan's short history window. See
  [deployment.md](deployment.md#backup-and-export) for exports.

## GitHub Actions

Free for public repositories; private repositories on the Free plan receive a monthly minute
allowance (see <https://docs.github.com/billing/managing-billing-for-github-actions>). The CI
workflow runs four jobs per push and typically finishes within about ten minutes.

## Threat-intelligence providers (optional)

| Provider | Free access | Notes |
|---|---|---|
| VirusTotal | Public API with low per-minute and daily quotas | Public API terms prohibit commercial use; results are cached 24 h |
| AbuseIPDB | Free account with a daily check quota | IP addresses only |
| AlienVault OTX | Free account and API key | Pulse counts are "reported", not "confirmed malicious" |

Check each provider's current terms before enabling a key. Without keys the platform still
works and shows providers as "Not configured". It never invents results.

## What a free deployment is not

This is a portfolio demonstration. It has no SLA, no high availability, no long-term log
retention, and runs on infrastructure that may suspend. It must not be used to protect a real
organisation.
