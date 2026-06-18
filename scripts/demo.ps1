<#
.SYNOPSIS
  Phase 6 PoC demo driver. Injects synthetic NormalizedEvent NDJSON into the
  Wazuh ingest path so the custom Slack rules fire real alerts — without
  needing a populated Slack workspace or Enterprise scopes.

.DESCRIPTION
  Each scenario emits a burst of events that match a stateful frequency rule
  in wazuh-rules/0500-slack-rules.xml. The lines are written in the exact
  NormalizedEvent shape the connector produces, so they travel the same
  decoder + rule path as live traffic.

  Scenario        Events                                  Rule fired
  ----------------------------------------------------------------------------
  channel-recon   25x member_joined_channel (1 actor)     100011  (level 10)
  file-exfil      25x file_shared + 6x file_public        100021 + 100026
  replit          55x file_downloaded source=audit        100051  (level 12)
  anomaly         1x audit anomaly                        100080  (level 12)
  export          1x export_started + 1x organization_exported  100081 + 100083
  login-geo       1x user_login from untrusted IP+country 100091 + 100092
  off-hours       16x file_downloaded source=audit        100094*
                  (* off-hours rules only fire when the manager processes the
                   burst inside the 18:00-08:00 window — see Gap 5)

.PARAMETER Scenario
  channel-recon | file-exfil | replit | anomaly | export | login-geo | off-hours | all

.PARAMETER Target
  docker  -> pipe into the wazuh.manager container's localfile (default)
  local   -> append to ./events.ndjson (dev JsonFileSink path)

.EXAMPLE
  ./scripts/demo.ps1 -Scenario channel-recon
  ./scripts/demo.ps1 -Scenario all -Target docker
#>
[CmdletBinding()]
param(
    [ValidateSet('channel-recon', 'file-exfil', 'replit', 'anomaly', 'export', 'login-geo', 'off-hours', 'all')]
    [string]$Scenario = 'all',

    [ValidateSet('docker', 'local')]
    [string]$Target = 'docker',

    # Override the "insider" actor id used across a scenario burst.
    [string]$Actor = 'U_DEMO_INSIDER'
)

$ErrorActionPreference = 'Stop'

# --- event builder -----------------------------------------------------------
function New-SlackEvent {
    param(
        [string]$Source,        # events | audit
        [string]$Action,
        [string]$ActorId,
        [string]$EntityType = 'channel',
        [string]$EntityId = 'C_DEMO',
        [string]$Severity = 'low',
        [string]$Ip,            # optional slack.context.ip   (login-geo)
        [string]$Country,       # optional slack.context.location (login-geo)
        [datetime]$When = (Get-Date).ToUniversalTime()
    )
    $slack = [ordered]@{
        source   = $Source
        action   = $Action
        event_id = "demo-" + [guid]::NewGuid().ToString('N')
        actor    = [ordered]@{ type = 'user'; id = $ActorId }
        entity   = [ordered]@{ type = $EntityType; id = $EntityId }
    }
    if ($Ip -or $Country) {
        $ctx = [ordered]@{}
        if ($Ip)      { $ctx.ip = $Ip }
        if ($Country) { $ctx.location = $Country }
        $slack.context = $ctx
    }
    $evt = [ordered]@{
        '@timestamp' = $When.ToString("yyyy-MM-ddTHH:mm:ssZ")
        slack        = $slack
        severity     = $Severity
        raw          = [ordered]@{ demo = $true }
    }
    # -Compress => single line; NDJSON requires one JSON object per line.
    $evt | ConvertTo-Json -Depth 8 -Compress
}

# --- scenario generators -----------------------------------------------------
function Get-ScenarioLines {
    param([string]$Name)
    $lines = New-Object System.Collections.Generic.List[string]

    switch ($Name) {
        'channel-recon' {
            # 25 channel joins by one actor -> rule 100011 (>=20 / 1h)
            1..25 | ForEach-Object {
                $lines.Add( (New-SlackEvent -Source events -Action member_joined_channel `
                            -ActorId $Actor -EntityType channel -EntityId ("C_DEMO_{0:D3}" -f $_)) )
            }
        }
        'file-exfil' {
            # 25 file shares -> 100021 (>=20 / 1h)
            1..25 | ForEach-Object {
                $lines.Add( (New-SlackEvent -Source events -Action file_shared `
                            -ActorId $Actor -EntityType file -EntityId ("F_DEMO_{0:D3}" -f $_) -Severity low) )
            }
            # 6 public-link exposures -> 100026 (>=5 / 10min, level 12)
            1..6 | ForEach-Object {
                $lines.Add( (New-SlackEvent -Source events -Action file_public `
                            -ActorId $Actor -EntityType file -EntityId ("F_PUB_{0:D3}" -f $_) -Severity medium) )
            }
        }
        'replit' {
            # 55 audit file_downloaded by one actor -> 100051 (>=50 / 24h, level 12)
            # Reproduces the Replit insider pattern on synthetic Enterprise audit signal.
            1..55 | ForEach-Object {
                $lines.Add( (New-SlackEvent -Source audit -Action file_downloaded `
                            -ActorId $Actor -EntityType file -EntityId ("F_DL_{0:D3}" -f $_) -Severity medium) )
            }
        }
        'anomaly' {
            # Gap 2: Slack's own anomaly audit action -> 100080 (level 12)
            $lines.Add( (New-SlackEvent -Source audit -Action anomaly `
                        -ActorId $Actor -EntityType workspace -EntityId 'T_DEMO' -Severity high) )
        }
        'export' {
            # Gap 3: data/workspace/org export -> 100081 (level 12) + 100083 (level 13)
            $lines.Add( (New-SlackEvent -Source audit -Action export_started `
                        -ActorId $Actor -EntityType workspace -EntityId 'T_DEMO' -Severity high) )
            $lines.Add( (New-SlackEvent -Source audit -Action organization_exported `
                        -ActorId $Actor -EntityType workspace -EntityId 'E_DEMO' -Severity critical) )
        }
        'login-geo' {
            # Gap 4: login from an IP + country outside the CDB allow-lists
            #   -> 100091 (untrusted IP, level 10) + 100092 (untrusted country, level 8).
            # 192.0.2.10 (TEST-NET-1) and RU are absent from the shipped CDB lists.
            $lines.Add( (New-SlackEvent -Source audit -Action user_login `
                        -ActorId $Actor -EntityType workspace -EntityId 'T_DEMO' -Severity low `
                        -Ip '192.0.2.10' -Country 'RU') )
        }
        'off-hours' {
            # Gap 5: off-hours download burst -> 100094 (16+ downloads / 1h off-hours).
            # NOTE: the <time> guard means 100094 only fires if the manager
            # processes these inside 18:00-08:00 local; outside that window only the
            # daytime base rule 100050 matches.
            1..16 | ForEach-Object {
                $lines.Add( (New-SlackEvent -Source audit -Action file_downloaded `
                            -ActorId $Actor -EntityType file -EntityId ("F_OH_{0:D3}" -f $_) -Severity medium) )
            }
        }
    }
    return $lines
}

# --- sink --------------------------------------------------------------------
function Send-Lines {
    param([System.Collections.Generic.List[string]]$Lines)

    $payload = ($Lines -join "`n") + "`n"

    if ($Target -eq 'local') {
        $path = Join-Path (Get-Location) 'events.ndjson'
        Add-Content -Path $path -Value $payload -NoNewline -Encoding utf8
        Write-Host "  -> appended $($Lines.Count) lines to $path"
    }
    else {
        # Pipe into the manager container's localfile. -T disables TTY so stdin streams.
        $payload | docker compose exec -T wazuh.manager sh -c 'cat >> /var/log/wazuh-slack/events.ndjson'
        if ($LASTEXITCODE -ne 0) { throw "docker compose exec failed (is the stack up?)" }
        Write-Host "  -> injected $($Lines.Count) lines into wazuh.manager:/var/log/wazuh-slack/events.ndjson"
    }
}

# --- run ---------------------------------------------------------------------
$scenarios = if ($Scenario -eq 'all') {
    @('channel-recon', 'file-exfil', 'replit', 'anomaly', 'export', 'login-geo', 'off-hours')
} else { @($Scenario) }

foreach ($s in $scenarios) {
    Write-Host "[demo] scenario: $s (actor=$Actor, target=$Target)"
    $lines = Get-ScenarioLines -Name $s
    Send-Lines -Lines $lines
}

Write-Host ""
Write-Host "Done. Watch alerts:"
if ($Target -eq 'docker') {
    Write-Host "  docker compose exec wazuh.manager tail -f /var/ossec/logs/alerts/alerts.json"
} else {
    Write-Host "  (point a Wazuh agent/localfile at ./events.ndjson)"
}
