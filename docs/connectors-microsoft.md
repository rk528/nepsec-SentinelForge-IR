# Microsoft log sources

SentinelForge accepts Microsoft logs in their native JSON shape at

```
POST /api/v1/ingest/microsoft/{format}
Authorization: Bearer sfk_...        # the data source's ingest key
```

| `format` | Microsoft source | Becomes | Feeds rules |
|---|---|---|---|
| `entra-signin` | Entra ID sign-in logs (Graph `auditLogs/signIns`, Azure Monitor `SignInLogs`) | `auth.success`, `auth.failure` | SF-AUTH-001 |
| `entra-audit` | Entra ID audit logs (Graph `auditLogs/directoryAudits`, Azure Monitor `AuditLogs`): *Add user*, *Add member to role* (incl. PIM), *Add member to group* | `iam.user_created`, `iam.group_member_added` | SF-IAM-001 |
| `defender-alert` | Microsoft Defender XDR / Defender for Cloud / Entra ID Protection alerts (Graph `security/alerts_v2`) | `security.alert` | SF-EXT-001 |
| `windows-event` | Windows Security, System and Sysmon logs (shipper script, or Log Analytics `SecurityEvent`) | auth (with logon type), process, process access, registry, scheduled task, IAM, log-cleared, service-stopped, network, DNS events | SF-AUTH-001, SF-PROC-001, SF-IAM-001, SF-DEF-001, SF-NET-001, SF-CRED-001, SF-PERS-001, SF-PERS-002, SF-LAT-001 |

The body can be a Graph response (`{"value": [...]}`), an Azure Monitor export
(`{"records": [...]}`), a JSON array, or one record; at most 500 records per request and
1 MiB per body. The response reports `inserted`, `duplicates` and `skipped`. Re-sending
records is safe: identical events are de-duplicated.

Records that do not map are **skipped, not guessed at**: unrelated audit activities,
failed audit operations, sign-in *interrupts* (MFA prompts, "stay signed in?", password
expiry: these are not credential failures and would otherwise look like password
guessing), machine-account and service logons, and unsupported event IDs.

## 1. Create a data source

Settings → Data sources → **Add source** (admin). Choose `microsoft_entra`,
`microsoft_defender` or `windows_security`. Copy the ingest key when it is shown; it is
displayed once. Use one source per log stream if you want separate health tracking.

## 2a. Entra ID and Defender: Graph shipper

[`connectors/microsoft-graph/ship_graph_logs.py`](../connectors/microsoft-graph/ship_graph_logs.py)
pulls from Microsoft Graph and posts to SentinelForge. Python 3.10+, standard library only.

1. **Register an app** in the Entra admin centre → App registrations → New registration.
2. **API permissions** → Microsoft Graph → *Application permissions*:
   `AuditLog.Read.All`, `Directory.Read.All` (sign-ins and audit logs) and
   `SecurityAlert.Read.All` (Defender alerts). Click **Grant admin consent**.
3. **Certificates & secrets** → new client secret. Note the tenant ID, client ID and secret.
4. Set environment variables on the machine that runs the shipper (never in the script):

   ```powershell
   [Environment]::SetEnvironmentVariable('MS_TENANT_ID', '<tenant id>', 'User')
   [Environment]::SetEnvironmentVariable('MS_CLIENT_ID', '<client id>', 'User')
   [Environment]::SetEnvironmentVariable('MS_CLIENT_SECRET', '<secret>', 'User')
   [Environment]::SetEnvironmentVariable('SENTINELFORGE_URL', 'https://sentinelforge-api.kuinkel.com', 'User')
   [Environment]::SetEnvironmentVariable('SENTINELFORGE_INGEST_KEY', 'sfk_...', 'User')
   ```

5. Run once to test, then schedule every 5 minutes (Task Scheduler, cron, or `--loop 300`):

   ```bash
   python ship_graph_logs.py                       # all streams
   python ship_graph_logs.py --streams entra-audit,defender-alert
   ```

Sign-in logs through Graph need an **Entra ID P1 or P2** licence; without one, use
`--streams entra-audit,defender-alert`. The shipper keeps a checkpoint per stream in
`.graph_shipper_state.json` (git-ignored) and retries on throttling (HTTP 429).

## 2b. Windows servers and workstations

[`connectors/windows/Send-WindowsEvents.ps1`](../connectors/windows/Send-WindowsEvents.ps1)
reads the event IDs the detections use (4624, 4625, 4688, 4698, 4720, 4728, 4732, 4756, 1102;
System 7036 and 104; Sysmon 1, 3, 10, 13, 22 when installed) and posts them. Run as Administrator.
To limit volume it sends Sysmon 10 only when the target is `lsass.exe` and Sysmon 13 only for
Run/RunOnce keys.

```powershell
[Environment]::SetEnvironmentVariable('SENTINELFORGE_INGEST_KEY', 'sfk_...', 'Machine')
.\Send-WindowsEvents.ps1 -ApiUrl https://sentinelforge-api.kuinkel.com

# Every 5 minutes, as SYSTEM:
$action  = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -ExecutionPolicy Bypass -File "C:\SentinelForge\Send-WindowsEvents.ps1" -ApiUrl https://sentinelforge-api.kuinkel.com'
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 5)
Register-ScheduledTask -TaskName 'SentinelForge event shipper' -Action $action -Trigger $trigger -User 'SYSTEM' -RunLevel Highest
```

Process command lines in 4688 need *Include command line in process creation events*
(Group Policy → Administrative Templates → System → Audit Process Creation). Logon and
account-management auditing must be enabled in the Advanced Audit Policy. Scheduled task
creation (4698) needs *Object Access > Audit Other Object Access Events*. Sysmon 10 and 13
must be enabled in your Sysmon configuration (for example, rules for `TargetImage` ending in
`lsass.exe` and `TargetObject` containing `CurrentVersion\Run`).

**Full capture.** Add `-CaptureAll` to send every event in the Security, System, Application,
PowerShell/Operational and (when installed) Sysmon logs, with the rendered message; the
Sysmon and network-logon filters above are switched off. Events the detections use are
mapped as usual; the rest are stored as `system.log` and deleted after `LOG_RETENTION_DAYS`.
With 4688 command-line auditing on, every program started is recorded. Batches drop to 80
records, and a rate-limited batch is retried rather than lost.

```powershell
.\Send-WindowsEvents.ps1 -ApiUrl https://sentinelforge-api.kuinkel.com -CaptureAll
```

The shipper's own scheduled task runs PowerShell, so SF-PERS-001 raises one alert per host
when you register it. Close it as benign positive (runbook RB-8).

## 2c. Azure Monitor / Microsoft Sentinel (no script)

If logs already go to a Log Analytics workspace or Event Hub, a Logic App or Azure
Function can forward them: run a query (`SigninLogs`, `AuditLogs`, `SecurityEvent`,
`SecurityAlert`) or read the Event Hub batch, then `POST` the rows as a JSON array to the
matching format with the ingest key header. Keep the ingest key in Key Vault.

## Verified

Tested end to end on 27 October 2026: the PowerShell shipper's serialisation (including
Windows PowerShell 5.1's `/Date(…)/` timestamps) posted to a local API raised SF-AUTH-001
and SF-DEF-001; the Graph shipper's batching raised SF-AUTH-001 from sign-in records,
skipped an MFA interrupt, and re-sending was fully de-duplicated. Mapping is covered by
`backend/tests/test_microsoft.py`. Not yet run against a real Microsoft tenant from this
environment: that needs your app registration.
