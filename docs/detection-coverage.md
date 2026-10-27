# Detection coverage

Six rules (`backend/app/detection/rules.py`) evaluate normalised events. Each rule declares
required telemetry, rationale, false-positive considerations and ATT&CK techniques, and ships
with labelled fixtures (`backend/app/detection/fixtures.py`).

**An ATT&CK mapping states design intent. It is not proof that a technique is reliably
detected in every environment.** The coverage view in the app also lists curated techniques
with no rule (gaps).

## Rules

| ID | Name | Severity / confidence | Required telemetry | ATT&CK |
|---|---|---|---|---|
| SF-AUTH-001 | Successful sign-in after repeated failures (≥5 failures, same account + source, success within 10 min) | High / medium | `auth.failure`, `auth.success` with user and source IP | T1110, T1110.001, T1078 |
| SF-PROC-001 | Suspicious process command line (encoded PowerShell, certutil download, remote mshta, rundll32 javascript, shadow-copy deletion, Office spawning interpreters) | High (critical for shadow deletion) / medium | `process.start` with command line and parent | T1059.001, T1027, T1105, T1218.005, T1218.011, T1204.002, T1490 |
| SF-IAM-001 | New account added to a privileged group within 30 min | High / medium | `iam.user_created`, `iam.group_member_added` | T1136.001, T1136.002, T1098 |
| SF-DEF-001 | Security logging cleared or stopped | High (critical when cleared) / high | `log.cleared`, `service.stopped` | T1070.001, T1562.001, T1562.002 |
| SF-NET-001 | Suspicious outbound connection (non-standard port, ≥50 MiB upload, or watchlisted destination) | Medium (high on watchlist or multiple reasons) / low | `network.connection` with dst IP/port and bytes | T1571, T1041, T1071 |
| SF-MAIL-001 | Emailed link visited by the recipient within 60 min | High / medium | `email.delivered` with URL/domain, `dns.query` or `proxy.request` with user | T1566.002, T1204.001 |
| SF-EXT-001 | Medium/high alert forwarded from Microsoft Defender XDR or Entra ID Protection | From the alert (high / medium) | `security.alert` (Graph `alerts_v2`) | Taken from each alert (`mitreTechniques`); none claimed by the rule |

Severity (impact if real) and confidence (likelihood the detection is right) are stored
separately on every alert.

## Deduplication

Alerts are upserted on `(org_id, dedup_key)`. Keys include the rule, the main entities and a
time bucket (hour or day), so re-running detection over the same window never duplicates
alerts or inflates counts, while recurrences on later days create new alerts. Triggering event
IDs are stored in `alert_events`.

## Evaluation results

`python -m app.cli self-test` (or **Detections → Run self-test**) evaluates every rule
against its fixtures and stores the results. Results from 27 October 2026:

| Rule | TP | FP | TN | FN | Precision | Recall | Result |
|---|---|---|---|---|---|---|---|
| SF-AUTH-001 | 2 | 0 | 3 | 1 | 1.00 | 0.67 | Pass (FN is a documented limitation) |
| SF-PROC-001 | 4 | 0 | 3 | 1 | 1.00 | 0.80 | Pass (FN documented) |
| SF-IAM-001 | 1 | 0 | 3 | 0 | 1.00 | 1.00 | Pass |
| SF-DEF-001 | 2 | 0 | 1 | 0 | 1.00 | 1.00 | Pass |
| SF-NET-001 | 3 | 0 | 2 | 1 | 1.00 | 0.75 | Pass (FN documented) |
| SF-MAIL-001 | 1 | 1 | 3 | 0 | 0.50 | 1.00 | Pass (FP documented) |
| SF-EXT-001 | 2 | 0 | 2 | 0 | 1.00 | 1.00 | Pass |

A rule "passes" when every case is classified correctly except cases explicitly marked as known
limitations. These fixtures are small and hand-written: the numbers show that rules behave as
specified, not how they would perform on production traffic.

Evaluation latency (pure in-memory rule evaluation over fixtures) is reported per run and is
typically below 1 ms per rule. End-to-end ingest-to-alert latency is the duration of the ingest
request, because detection runs inline.

## Known limitations (reported, not hidden)

| Rule | Missed or wrong case | Why |
|---|---|---|
| SF-AUTH-001 | Low-and-slow guessing over 30 minutes | Fixed 10-minute window |
| SF-PROC-001 | Base64 decoded via `FromBase64String` without `-enc` | Pattern list, not behaviour |
| SF-NET-001 | C2 beaconing over 443 to a non-watchlisted host | No frequency/beacon analysis |
| SF-MAIL-001 | Wanted newsletter clicked (false positive) | Cannot judge intent; relies on triage |

## Gaps (no rule)

T1003 credential dumping, T1021.001 RDP, T1053.005 scheduled tasks, T1547.001 run keys, T1486
encryption for impact, T1567 exfiltration to web services. Reasons are shown in the coverage
view, most often "telemetry not collected".

## Sigma

Rules are Python, not Sigma. Executing arbitrary Sigma would require a conversion layer to this
schema, which is not implemented.
