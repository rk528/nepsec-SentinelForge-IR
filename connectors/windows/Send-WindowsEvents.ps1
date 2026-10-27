<#
.SYNOPSIS
    Ship Windows Security, System and Sysmon events to SentinelForge IR.

.DESCRIPTION
    Reads the event IDs SentinelForge's detections use since the last run, and posts
    them to /api/v1/ingest/microsoft/windows-event. Run it as Administrator (the
    Security log needs it), on each server or domain controller, from Task Scheduler
    every 5 minutes.

    Events read:
      Security  4624 4625 (logons), 4688 (process creation), 4720 (user created),
                4728 4732 4756 (added to a privileged group), 1102 (log cleared)
      System    7036 (service stopped), 104 (log cleared)
      Sysmon    1 (process), 3 (network connection), 22 (DNS query), when installed

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
    [switch] $IncludeNetworkLogons
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
    @{ LogName = 'Security'; Id = 4624, 4625, 4688, 4720, 4728, 4732, 4756, 1102; StartTime = $start },
    # Other providers reuse ID 7036, so only the Service Control Manager's is a service state change.
    @{ LogName = 'System'; ProviderName = 'Service Control Manager'; Id = 7036; StartTime = $start },
    @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Eventlog'; Id = 104; StartTime = $start }
)
if (Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' -ErrorAction SilentlyContinue) {
    $queries += @{ LogName = 'Microsoft-Windows-Sysmon/Operational'; Id = 1, 3, 22; StartTime = $start }
}

$records = New-Object System.Collections.Generic.List[object]
$newest = $since
foreach ($q in $queries) {
    $events = Get-WinEvent -FilterHashtable $q -ErrorAction SilentlyContinue
    foreach ($e in $events) {
        $xml = [xml]$e.ToXml()
        $data = @{}
        foreach ($d in $xml.Event.EventData.Data) {
            if ($d.Name) { $data[$d.Name] = [string]$d.'#text' }
        }
        if ($e.Id -eq 4624 -and -not $IncludeNetworkLogons -and $data['LogonType'] -eq '3') { continue }
        if ($e.Id -in 4728, 4732, 4756 -and ($data['MemberName'] -in $null, '', '-') -and $data['MemberSid']) {
            # Local group changes record only the member's SID; resolve it so it matches the 4720 account name.
            try { $data['MemberName'] = ([Security.Principal.SecurityIdentifier]$data['MemberSid']).Translate([Security.Principal.NTAccount]).Value } catch { }
        }
        if ($e.Id -eq 7036) {
            # 7036 carries the service name and state as param1/param2 in the System log.
            $data['param1'] = [string]$e.Properties[0].Value
            $data['param2'] = [string]$e.Properties[1].Value
        }
        $utc = $e.TimeCreated.ToUniversalTime()
        if ($utc -gt $newest) { $newest = $utc }
        $records.Add([ordered]@{
            EventID     = $e.Id
            TimeCreated = $utc.ToString('o')
            Computer    = $e.MachineName
            LogName     = $e.LogName
            Channel     = $e.LogName
            EventData   = $data
        })
    }
}

$sent = 0; $inserted = 0; $alerts = 0
for ($i = 0; $i -lt $records.Count; $i += $BatchSize) {
    $batch = $records.GetRange($i, [Math]::Min($BatchSize, $records.Count - $i))
    $body = [Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject @($batch) -Depth 5 -Compress))
    $result = Invoke-RestMethod -Method Post -Uri $endpoint -Body $body -ContentType 'application/json' -Headers @{ Authorization = "Bearer $key" }
    $sent += $batch.Count; $inserted += $result.inserted; $alerts += $result.alerts_created
}

New-Item -ItemType Directory -Force -Path (Split-Path $StateFile) | Out-Null
Set-Content -Path $StateFile -Value $newest.ToString('o') -Encoding ASCII
Write-Output ("{0:u} sent {1} events, {2} new, {3} alerts raised" -f (Get-Date).ToUniversalTime(), $sent, $inserted, $alerts)
