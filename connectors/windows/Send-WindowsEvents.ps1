<#
.SYNOPSIS
    Ship Windows Security, System and Sysmon events to SentinelForge IR.

.DESCRIPTION
    Reads the event IDs SentinelForge's detections use since the last run, and posts
    them to /api/v1/ingest/microsoft/windows-event. Run it as Administrator (the
    Security log needs it), on each server or domain controller, from Task Scheduler
    every 5 minutes.

    Events read:
      Security  4624 4625 (logons), 4688 (process creation), 4698 (scheduled task created),
                4720 (user created), 4728 4732 4756 (added to a privileged group), 1102 (log cleared)
      System    7036 (service stopped), 104 (log cleared)
      Sysmon    1 (process), 3 (network connection), 10 (process access, LSASS only),
                13 (registry value set, Run keys only), 22 (DNS query), when installed

    With -CaptureAll, every event in the Security, System, Application,
    PowerShell/Operational and Sysmon logs is sent as well; SentinelForge stores the
    ones its detections do not use as 'system.log' and deletes them after
    LOG_RETENTION_DAYS. Enable 'Include command line in process creation events' so
    4688 records each program's full command line.

    Event 4698 needs 'Audit Other Object Access Events' enabled; Sysmon 10 and 13 need
    a Sysmon configuration that logs them (most community configs log LSASS access and
    Run key writes).

    The ingest key is read from the SENTINELFORGE_INGEST_KEY environment variable
    (machine scope), never from the command line, so it stays out of process listings.

.EXAMPLE
    [Environment]::SetEnvironmentVariable('SENTINELFORGE_INGEST_KEY', 'sfk_...', 'Machine')
    .\Send-WindowsEvents.ps1 -ApiUrl https://sentinelforge-api.kuinkel.com
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $ApiUrl,
    [string] $StateFile = (Join-Path $env:ProgramData 'SentinelForge\windows-events.state'),
    [int] $LookbackMinutes = 60,
    [int] $BatchSize = 200,
    # Network logons (type 3) are very frequent; failures are always sent.
    [switch] $IncludeNetworkLogons,
    # Send every event from the logs below, not only the ones the detections use.
    [switch] $CaptureAll
)

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$key = [Environment]::GetEnvironmentVariable('SENTINELFORGE_INGEST_KEY', 'Process')
if (-not $key) { $key = [Environment]::GetEnvironmentVariable('SENTINELFORGE_INGEST_KEY', 'Machine') }
if (-not $key -or -not $key.StartsWith('sfk_')) { throw 'Set SENTINELFORGE_INGEST_KEY to the data source ingest key (sfk_...).' }
if (-not ($ApiUrl.StartsWith('https://') -or $ApiUrl -match '^http://(127\.0\.0\.1|localhost)(:\d+)?/?$')) { throw 'ApiUrl must use https.' }
$endpoint = $ApiUrl.TrimEnd('/') + '/api/v1/ingest/microsoft/windows-event'

$since = (Get-Date).ToUniversalTime().AddMinutes(-$LookbackMinutes)
if (Test-Path $StateFile) {
    $saved = Get-Content $StateFile -Raw
    if ($saved) { $since = [datetime]::Parse($saved.Trim(), $null, [Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime() }
}
$start = $since.ToLocalTime()

$queries = @(
    @{ LogName = 'Security'; Id = 4624, 4625, 4688, 4698, 4720, 4728, 4732, 4756, 1102; StartTime = $start },
    # Other providers reuse ID 7036, so only the Service Control Manager's is a service state change.
    @{ LogName = 'System'; ProviderName = 'Service Control Manager'; Id = 7036; StartTime = $start },
    @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Eventlog'; Id = 104; StartTime = $start }
)
$hasSysmon = [bool](Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' -ErrorAction SilentlyContinue)
if ($CaptureAll) {
    $queries = @(
        @{ LogName = 'Security'; StartTime = $start },
        @{ LogName = 'System'; StartTime = $start },
        @{ LogName = 'Application'; StartTime = $start },
        @{ LogName = 'Microsoft-Windows-PowerShell/Operational'; StartTime = $start }
    )
    if ($hasSysmon) { $queries += @{ LogName = 'Microsoft-Windows-Sysmon/Operational'; StartTime = $start } }
} elseif ($hasSysmon) {
    $queries += @{ LogName = 'Microsoft-Windows-Sysmon/Operational'; Id = 1, 3, 10, 13, 22; StartTime = $start }
}
$maxText = 2000
# Full-capture records carry the rendered message; smaller batches stay under the API's 1 MiB body limit.
if ($CaptureAll -and -not $PSBoundParameters.ContainsKey('BatchSize')) { $BatchSize = 80 }

$records = New-Object System.Collections.Generic.List[object]
$newest = $since
foreach ($q in $queries) {
    $events = Get-WinEvent -FilterHashtable $q -ErrorAction SilentlyContinue
    foreach ($e in $events) {
        $xml = [xml]$e.ToXml()
        $data = @{}
        foreach ($d in $xml.Event.EventData.Data) {
            if ($d.Name) {
                $text = [string]$d.'#text'
                if ($CaptureAll -and $text.Length -gt $maxText) { $text = $text.Substring(0, $maxText) }
                $data[$d.Name] = $text
            }
        }
        if ($e.Id -eq 4624 -and -not ($IncludeNetworkLogons -or $CaptureAll) -and $data['LogonType'] -eq '3') { continue }
        if ($q.LogName -like '*Sysmon*' -and -not $CaptureAll) {
            # Process access and registry events are high volume; send only what the detections read.
            if ($e.Id -eq 10 -and $data['TargetImage'] -notlike '*\lsass.exe') { continue }
            if ($e.Id -eq 13 -and $data['TargetObject'] -notmatch '\\CurrentVersion\\Run(Once)?(Ex)?\\') { continue }
        }
        if ($e.Id -in 4728, 4732, 4756 -and ($data['MemberName'] -in $null, '', '-') -and $data['MemberSid']) {
            # Local group changes record only the member's SID; resolve it so it matches the 4720 account name.
            try { $data['MemberName'] = ([Security.Principal.SecurityIdentifier]$data['MemberSid']).Translate([Security.Principal.NTAccount]).Value } catch { }
        }
        if ($e.Id -eq 7036 -and $e.ProviderName -eq 'Service Control Manager') {
            # 7036 carries the service name and state as param1/param2 in the System log.
            $data['param1'] = [string]$e.Properties[0].Value
            $data['param2'] = [string]$e.Properties[1].Value
        }
        $utc = $e.TimeCreated.ToUniversalTime()
        if ($utc -gt $newest) { $newest = $utc }
        $record = [ordered]@{
            EventID     = $e.Id
            TimeCreated = $utc.ToString('o')
            Computer    = $e.MachineName
            LogName     = $e.LogName
            Channel     = $e.LogName
            EventData   = $data
        }
        if ($CaptureAll) {
            $message = [string]$e.Message
            if ($message.Length -gt $maxText) { $message = $message.Substring(0, $maxText) }
            $record['ProviderName'] = $e.ProviderName
            $record['Level'] = [string]$e.LevelDisplayName
            $record['Message'] = $message
            $record['Capture'] = 'all'
        }
        $records.Add($record)
    }
}

$sent = 0; $inserted = 0; $alerts = 0
for ($i = 0; $i -lt $records.Count; $i += $BatchSize) {
    $batch = $records.GetRange($i, [Math]::Min($BatchSize, $records.Count - $i))
    $body = [Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject @($batch) -Depth 5 -Compress))
    for ($attempt = 1; ; $attempt++) {
        try {
            $result = Invoke-RestMethod -Method Post -Uri $endpoint -Body $body -ContentType 'application/json' -Headers @{ Authorization = "Bearer $key" }
            break
        } catch {
            # 429 is the per-source rate limit (60 requests a minute); wait and resend the same batch.
            $code = [int]$_.Exception.Response.StatusCode
            if ($code -notin 429, 502, 503, 504 -or $attempt -ge 5) { throw }
            Start-Sleep -Seconds (15 * $attempt)
        }
    }
    $sent += $batch.Count; $inserted += $result.inserted; $alerts += $result.alerts_created
}

New-Item -ItemType Directory -Force -Path (Split-Path $StateFile) | Out-Null
Set-Content -Path $StateFile -Value $newest.ToString('o') -Encoding ASCII
Write-Output ("{0:u} sent {1} events, {2} new, {3} alerts raised" -f (Get-Date).ToUniversalTime(), $sent, $inserted, $alerts)
