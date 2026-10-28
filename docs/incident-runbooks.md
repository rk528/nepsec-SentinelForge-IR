# Incident runbooks

Short, rule-aligned procedures. Each step names where it happens in SentinelForge IR. Steps
marked *(manual)* happen outside the platform; the platform records them as notes and evidence.

## General lifecycle

1. **Triage** the alert: read *Why this alert fired*, the matching events and the rule's known
   false positives. Acknowledge it, close it with a disposition, or escalate it.
2. **Open** an incident by escalating (or link to an existing one). Assign an owner.
3. **Investigate:** move to *Investigating*, run *Collect related evidence* and *Enrich
   associated IOCs*, pivot in Events, record findings as notes.
4. **Contain:** run *Record containment recommendations*; request *Simulate firewall block* for
   confirmed external IPs, approved by a second lead; carry out real containment *(manual)*.
   Mark *Contained*.
5. **Resolve and close:** mark *Resolved*, add an assessment note, close with a verdict and a
   closure reason, and generate the closure report.

Verdicts: **true positive** (malicious/unauthorised), **benign positive** (rule correct,
activity expected), **false positive** (rule fired on activity outside its intent),
**undetermined** (insufficient evidence). A verdict is independent of severity.

## RB-1 Password guessing followed by success (SF-AUTH-001)

- Confirm the success came from the same source as the failures (alert evidence).
- Check whether the user expected the sign-in *(manual: contact the user)*.
- Pivot on the source IP in Events and Threat intel; set an analyst verdict on the IP.
- Contain: reset the password and revoke sessions *(manual)*; request a simulated block of
  the source IP.
- Close as true positive if the user did not sign in; benign positive if they mistyped.

## RB-2 Suspicious process execution (SF-PROC-001)

- Read the command line in the evidence (it is displayed as inert text; do not run it).
- Use *Related events* to find downloads (`dns.query`, `network.connection`) and child processes.
- Look up any downloaded file hash and contacted domains.
- Contain: isolate the host in the EDR *(manual)*; collect the file and process tree.

## RB-3 Privileged account created (SF-IAM-001)

- Confirm whether a change ticket exists *(manual)*.
- Investigate the creating account's recent sign-ins.
- Contain: disable the new account and remove group membership *(manual)*; rotate the creating
  account's credentials.

## RB-4 Logging cleared or stopped (SF-DEF-001)

- Treat the logging gap as unknown activity; review alerts on the same host before and after.
- Restore logging and confirm events arrive again (Settings → Data sources, Overview → Telemetry health).
- Escalate even if the cause seems benign until it is explained.

## RB-5 Suspicious outbound traffic (SF-NET-001)

- Decide whether the destination is sanctioned (cloud storage, vendor service).
- Large upload alone: often benign positive; non-standard port: investigate the host.
- Look up the destination IP/domain; mark it malicious to add it to the detection watchlist.

## RB-6 Phishing link followed (SF-MAIL-001)

- Check sender authentication results in the raw email event (SPF/DKIM fields).
- Check proxy logs for credential submission (POST) versus a single page view.
- Contain: purge the message, block the domain, reset credentials if submitted *(manual)*.
- Close newsletters and wanted mail as benign positive.

## RB-7 Credential dumping (SF-CRED-001)

- Treat as critical: assume every credential cached on the host is exposed.
- Identify the source process and its parent in *Related events*; check its hash and path
  (an allowlisted name outside `System32` or the Defender platform folder is suspicious).
- List accounts that signed in to the host recently (Events, host pivot, `auth.success`).
- Contain: isolate the host *(manual)*; reset passwords of exposed accounts, starting with
  privileged ones; for domain controllers consider a double `krbtgt` reset *(manual)*.
- Close as benign positive only when a named security or support tool and a change record
  explain the access.

## RB-8 Scheduled task or Run key persistence (SF-PERS-001, SF-PERS-002)

- Read the task action or registry value in the evidence (inert text; do not run it).
- Find who created it and what ran just before (*Related events*, same host and user).
- Look up any file path or URL it references; collect the binary *(manual)*.
- Contain: disable the task or delete the value *(manual)* after collecting it as evidence,
  then hunt for the same payload hash or name on other hosts.
- The SentinelForge shipper's own task (`powershell.exe -File ...Send-WindowsEvents.ps1`)
  raises SF-PERS-001 once per host at install: close it as benign positive.

## RB-9 Suspicious RDP (SF-LAT-001)

- External source: confirm whether RDP should be reachable from the internet at all; if not,
  the exposure itself is a finding. Pivot on the source IP in Threat intel.
- Fan-out: compare the hosts and time with change records; check whether the account
  normally administers those hosts.
- Contain: disable or reset the account and end its sessions *(manual)*; request a
  simulated block of an external source IP; close RDP exposure at the firewall.
