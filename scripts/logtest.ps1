<#
.SYNOPSIS
  Pipe one synthetic Slack NormalizedEvent through `wazuh-logtest` in the
  running manager container to confirm the decoder + base rule match.

.DESCRIPTION
  Single-event sanity check (no frequency burst). Confirms:
    - the JSON decodes as `slack`
    - slack.action / slack.actor.id are extracted
    - the matching base rule (e.g. 100010 / 100020 / 100050) fires
  Frequency rules (100011 etc.) need a burst — use demo.ps1 for those.

.EXAMPLE
  ./scripts/logtest.ps1 -Action member_joined_channel
  ./scripts/logtest.ps1 -Action file_downloaded -Source audit
#>
[CmdletBinding()]
param(
    [string]$Action = 'member_joined_channel',
    [ValidateSet('events', 'audit')][string]$Source = 'events',
    [string]$ActorId = 'U_DEMO_INSIDER'
)

$ErrorActionPreference = 'Stop'

$evt = [ordered]@{
    '@timestamp' = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    slack        = [ordered]@{
        source   = $Source
        action   = $Action
        event_id = "logtest-" + [guid]::NewGuid().ToString('N')
        actor    = [ordered]@{ type = 'user'; id = $ActorId }
        entity   = [ordered]@{ type = 'file'; id = 'F_TEST' }
    }
    severity     = 'low'
    raw          = [ordered]@{ demo = $true }
}
$line = $evt | ConvertTo-Json -Depth 8 -Compress

Write-Host "[logtest] feeding: $line`n"
$line | docker compose exec -T wazuh.manager /var/ossec/bin/wazuh-logtest
