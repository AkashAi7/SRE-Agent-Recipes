<#
.SYNOPSIS
  Azure SRE Agent hackathon kit - App Service.
  Interactive CLI that gives you a ready-made workload (Linux App Service running a Node.js web app with Application
  Insights), an Azure Monitor alert, and an Azure SRE Agent connected to Azure Monitor with an incident response plan
  and a sanity runbook. Break the app, then watch the agent pick up the incident, investigate it and propose a fix.
.EXAMPLE
  ./sre-appservice.ps1                                                       # interactive menu (recommended)
  ./sre-appservice.ps1 -Action Deploy -SubscriptionId <id> -Location westus2 # no prompts
  ./sre-appservice.ps1 -Action Status | Break | Watch | Fix | Preflight
#>
[CmdletBinding()]
param(
  [string]$SubscriptionId,
  [ValidateSet('Menu', 'Preflight', 'Deploy', 'Status', 'Break', 'Watch', 'Fix')][string]$Action = 'Menu',
  [string]$Location = 'westus2',
  [ValidatePattern('^[a-z][a-z0-9]{1,9}$')][string]$Prefix,
  [ValidateSet('Low', 'High')][string]$AccessLevel = 'Low',
  [string]$Sku = 'B1'
)
$LocationGiven = $PSBoundParameters.ContainsKey('Location')
$PrefixGiven = $PSBoundParameters.ContainsKey('Prefix')
$ErrorActionPreference = 'Stop'
$Api = '2025-05-01-preview'
$Kind = 'app'; $Title = 'App Service'; $Me = './sre-appservice.ps1'; $AlertSuffix = 'http-5xx'
$DeployWhat = 'App Service + Node.js app + HTTP 5xx alert + SRE agent + incident plan (~10 min)'
# ---------- helpers ----------
function Step($m) { Write-Host "`n==> $m" -ForegroundColor Cyan }
function Warn($m) { Write-Host "WARN: $m" -ForegroundColor Yellow }
function AzRun { $o = & az @args; if ($LASTEXITCODE -ne 0) { throw "az $($args -join ' ') failed" }; $o }
function AzJson { (AzRun @args -o json) -join "`n" | ConvertFrom-Json }
function AzTry { $ErrorActionPreference = 'Continue'; $o = & az @args 2>$null; if ($LASTEXITCODE -ne 0) { return $null }; $o }
function AzTryJson { $o = AzTry @args -o json; if ($o) { ($o -join "`n") | ConvertFrom-Json } }
function Test-Group([string]$Name) { ((AzRun group exists -n $Name) -join '') -eq 'true' }
function Get-MyIdentity {
  # Object ID from the ARM token, so no Microsoft Graph call is needed.
  try {
    $p = ((AzRun account get-access-token --query accessToken -o tsv) -join '').Split('.')[1].Replace('-', '+').Replace('_', '/')
    $c = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($p + '=' * ((4 - $p.Length % 4) % 4))) | ConvertFrom-Json
    if ($c.oid) { return @{ Id = $c.oid; Type = $(if ($c.idtyp -eq 'app') { 'ServicePrincipal' } else { 'User' }) } }
  } catch { }
  @{ Id = (AzRun ad signed-in-user show --query id -o tsv) -join ''; Type = 'User' }
}
function Get-Hash([string]$s) {
  $md5 = [Security.Cryptography.MD5]::Create()
  ([BitConverter]::ToString($md5.ComputeHash([Text.Encoding]::UTF8.GetBytes($s))) -replace '-', '').ToLower()
}
function Ensure-Providers($names) {
  foreach ($n in $names) {
    if ((AzRun provider show -n $n --query registrationState -o tsv) -ne 'Registered') {
      Step "Registering provider $n"; AzRun provider register -n $n --wait | Out-Null
    }
  }
}
function ArmPut([string]$Url, $Obj) {
  $f = Join-Path ([IO.Path]::GetTempPath()) "$Prefix-$((Get-Hash $Url).Substring(0, 8)).json"
  [IO.File]::WriteAllText($f, ($Obj | ConvertTo-Json -Depth 20))
  try { AzJson rest --method put --url $Url --body "@$f" } finally { Remove-Item $f -ErrorAction SilentlyContinue }
}
function Ask([string]$Prompt, [string]$Default) {
  $p = if ($Default) { "$Prompt [$Default]" } else { $Prompt }
  try { $r = Read-Host $p } catch { $r = $null; $script:NoPrompt = $true }
  if ([string]::IsNullOrWhiteSpace($r)) { $Default } else { $r.Trim() }
}
function Show-Check([string]$Name, $Ok, [string]$Detail, [switch]$WarnOnly) {
  $tag = if ($Ok) { 'PASS' } elseif ($WarnOnly) { 'WARN' } else { 'FAIL' }
  $color = @{ PASS = 'Green'; WARN = 'Yellow'; FAIL = 'Red' }[$tag]
  Write-Host ("  [{0}] {1}{2}" -f $tag, $Name, $(if ($Detail) { " - $Detail" })) -ForegroundColor $color
}
function Get-HttpState([string]$Url, [string]$Expect) {
  try {
    $r = Invoke-WebRequest $Url -UseBasicParsing -TimeoutSec 10
    if ($r.Content -match $Expect) { "HEALTHY (HTTP $($r.StatusCode))" } else { "UNEXPECTED RESPONSE (HTTP $($r.StatusCode))" }
  } catch { "DOWN ($(if ($_.Exception.Response) { 'HTTP ' + [int]$_.Exception.Response.StatusCode } else { 'no response' }))" }
}
function Wait-OrKey([int]$Seconds) {
  for ($i = 0; $i -lt $Seconds; $i++) {
    try { if ([Console]::KeyAvailable) { [void][Console]::ReadKey($true); return $true } } catch { }
    Start-Sleep 1
  }
  $false
}
function Format-Time($v) { try { ([datetime]$v).ToLocalTime().ToString('MMM dd HH:mm') } catch { "$v" } }

# ---------- pre-flight: subscription, region, SKU, quota, permissions ----------
function Select-Subscription([switch]$Force) {
  if ($SubscriptionId -and -not $Force) { AzRun account set --subscription $SubscriptionId | Out-Null; return }
  $cur = AzJson account show
  Write-Host "Current subscription: $($cur.name) ($($cur.id))" -ForegroundColor Cyan
  $all = $null
  while ($true) {
    $q = Ask 'Press Enter to use it, or type part of another subscription name/ID' ''
    if (-not $q) { return }
    if (-not $all) { $all = @(AzJson account list | Where-Object state -eq 'Enabled') }
    $m = @($all | Where-Object { $_.name.IndexOf($q, [StringComparison]::OrdinalIgnoreCase) -ge 0 -or $_.id.StartsWith($q, [StringComparison]::OrdinalIgnoreCase) } | Select-Object -First 20)
    if (-not $m) { Warn "No enabled subscription matches '$q'."; continue }
    for ($i = 0; $i -lt $m.Count; $i++) { Write-Host ("  {0,2}) {1}  ({2})" -f ($i + 1), $m[$i].name, $m[$i].id) }
    $n = Ask "Pick 1-$($m.Count)" '1'
    if ($n -match '^\d+$' -and [int]$n -ge 1 -and [int]$n -le $m.Count) {
      AzRun account set --subscription $m[[int]$n - 1].id | Out-Null
      Write-Host "Using $($m[[int]$n - 1].name)"; return
    }
  }
}
function Invoke-Preflight {
  Step "Pre-flight checks (subscription $subName)"
  $regions = @(((AzJson provider show -n Microsoft.App).resourceTypes | Where-Object resourceType -eq 'agents').locations |
      ForEach-Object { ($_ -replace '\s', '').ToLower() } | Sort-Object)
  Show-Check 'SRE Agent offered to this subscription' ([bool]$regions) "$($regions.Count) regions"
  if (-not $regions) { throw 'SRE Agent (Microsoft.App/agents) is not available to this subscription. See README > Troubleshooting.' }
  try {
    $me = Get-MyIdentity
    $roles = @(AzRun role assignment list --assignee $me.Id --only-show-errors --scope "/subscriptions/$sub" --include-inherited --include-groups --query '[].roleDefinitionName' -o tsv) | Sort-Object -Unique
    $ok = [bool]($roles | Where-Object { $_ -in 'Owner', 'User Access Administrator', 'Role Based Access Control Administrator' })
    Show-Check 'Can create role assignments' $ok "your roles: $(if ($roles) { $roles -join ', ' } else { 'none at subscription scope' })" -WarnOnly
  } catch { Show-Check 'Can create role assignments' $false 'could not verify; needs Owner or Contributor + User Access Administrator' -WarnOnly }

  if (Test-Group $wRg) {
    $script:Location = (AzRun group show -n $wRg --query location -o tsv) -join ''
    Show-Check "Region $Location" $true "$wRg already exists there, reusing it"; $script:PreflightOk = $true; return
  }
  $tried = @()
  while ($true) {
    $loc = $Location
    if (-not $LocationGiven) {
      if (-not $tried) {
        Write-Host 'Regions where SRE Agent is available:'
        for ($i = 0; $i -lt $regions.Count; $i += 3) {
          Write-Host (($i..[Math]::Min($i + 2, $regions.Count - 1) | ForEach-Object { '{0,4}) {1,-20}' -f ($_ + 1), $regions[$_] }) -join '')
        }
      }
      $def = if (-not $tried -and $regions -contains $Location) { $Location } else { $regions | Where-Object { $_ -notin $tried } | Select-Object -First 1 }
      if (-not $def -or ($script:NoPrompt -and $tried.Count -ge 5)) { throw 'No region passed pre-flight. Try another subscription or size, or pass -Location.' }
      $ans = Ask 'Region (number or name)' $def
      $loc = if ($ans -match '^\d+$' -and [int]$ans -ge 1 -and [int]$ans -le $regions.Count) { $regions[[int]$ans - 1] } else { ($ans -replace '\s', '').ToLower() }
    }
    $tried += $loc
    Write-Host "Checking $loc ..."
    $ok = $regions -contains $loc
    Show-Check "SRE Agent region $loc" $ok $(if (-not $ok) { 'not supported, pick one from the list' })
    if ($ok) { $ok = Test-Workload $loc }
    if ($ok) { $script:Location = $loc; $script:PreflightOk = $true; Write-Host "Pre-flight passed: region $loc" -ForegroundColor Green; return }
    if ($LocationGiven) { throw "Pre-flight failed for -Location $loc (see above). Omit -Location to choose a region interactively." }
    Warn 'Choose another region.'
  }
}

# ---------- SRE agent, Azure Monitor alerts and the incident response plan ----------
function Get-AgentUrl { "https://management.azure.com/subscriptions/$sub/resourceGroups/$aRg/providers/Microsoft.App/agents/${agent}?api-version=$Api" }
function Get-Agent {
  $a = AzTryJson rest --method get --url (Get-AgentUrl)
  if ($a) { $script:SreEndpoint = $a.properties.agentEndpoint }
  $a
}
# Calls the agent's data-plane API (same API the sre.azure.com portal uses).
function Sre([string]$Method, [string]$Path, $Body) {
  if (-not $script:SreTok -or $script:SreTokAt -lt (Get-Date).AddMinutes(-40)) {
    $t = (AzTry account get-access-token --resource https://azuresre.dev --query accessToken -o tsv) -join ''
    if (-not $t) { throw 'Could not get a token for the SRE Agent API. Try: az account get-access-token --resource https://azuresre.dev' }
    $script:SreTok = $t
    $script:SreTokAt = Get-Date
  }
  $p = @{ Uri = "$script:SreEndpoint$Path"; Method = $Method; ContentType = 'application/json'; UseBasicParsing = $true
    Headers = @{ Authorization = 'Bearer ' + $script:SreTok } }
  if ($null -ne $Body) { $p.Body = ($Body | ConvertTo-Json -Depth 10) }
  $r = Invoke-RestMethod @p
  $r
}
function Wait-DataPlane {
  for ($i = 0; $i -lt 16; $i++) {
    try { [void](Sre GET '/api/v1/incidentplayground/filters' $null); return $true } catch { Start-Sleep 15 }
  }
  $false
}
function Get-Incidents {
  try { $r = Sre GET '/api/v1/threads' $null } catch { return @() }
  @($r.value | Where-Object { $_.source -eq 'Incident' } | Sort-Object { "$($_.createdTimestamp)" } -Descending)
}
function Show-Incidents($List) {
  if (-not $List) { Write-Host '    (none yet)'; return }
  foreach ($t in @($List | Select-Object -First 5)) {
    Write-Host ("    {0}  {1}  - investigation: {2}, alert: {3}" -f (Format-Time $t.createdTimestamp), $t.title, $t.incidentDetails.investigationStatus, $t.incidentDetails.incidentStatus)
  }
}
function Get-FiredAlerts {
  $r = AzTryJson rest --method get --url "https://management.azure.com/subscriptions/$sub/providers/Microsoft.AlertsManagement/alerts" `
    --url-parameters api-version=2019-05-05-preview "targetResourceGroup=$wRg" monitorCondition=Fired timeRange=1d
  @($r.value | ForEach-Object { $e = $_.properties.essentials; [pscustomobject]@{ Rule = ($e.alertRule -split '/')[-1]; Severity = $e.severity; State = $e.alertState; Since = $e.startDateTime } })
}
function New-MetricAlert([string]$Scope, [string]$Namespace, [string]$Metric, [string]$Aggregation, [double]$Threshold, $Dimensions, [string]$Description) {
  $crit = @{ criterionType = 'StaticThresholdCriterion'; name = 'c1'; metricNamespace = $Namespace; metricName = $Metric; operator = 'GreaterThan'; threshold = $Threshold; timeAggregation = $Aggregation }
  if ($Dimensions) { $crit.dimensions = @($Dimensions) }
  $body = @{ location = 'global'; properties = @{ description = $Description; severity = 2; enabled = $true; scopes = @($Scope); evaluationFrequency = 'PT1M'; windowSize = 'PT5M'
      autoMitigate = $true; actions = @(); criteria = @{ 'odata.type' = 'Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria'; allOf = @($crit) } } }
  ArmPut "https://management.azure.com/subscriptions/$sub/resourceGroups/$wRg/providers/Microsoft.Insights/metricAlerts/${AlertName}?api-version=2018-03-01" $body | Out-Null
}
function Set-ResponsePlan([string[]]$Steps, [string]$Instructions) {
  $filter = @{ Id = $PlanId; Priorities = @('P1', 'P2', 'P3', 'P4'); TitleContains = $Prefix; AgentMode = 'review' }
  [void](Sre PUT "/api/v1/incidentplayground/filters/$PlanId" $filter)
  $handler = @{ id = "$PlanId-handler"; name = "$PlanId-handler"; description = "Incident response plan for the $Title workload in $wRg"
    incidentFilterId = $PlanId; incidentProcessingGuide = $Steps; tools = @(); incidents = @(); customInstructions = $Instructions }
  [void](Sre PUT "/api/v1/incidentplayground/handlers/$PlanId-handler" $handler)
  [void](Sre POST "/api/v1/incidentplayground/filters/$PlanId/enable" $null)
}
function New-SreAgent([string]$Runbook, [string[]]$Steps, [string]$Instructions) {
  Step "Creating SRE agent '$agent' in $Location (agent RG: $aRg)"
  AzRun group create -n $aRg -l $Location -o none | Out-Null
  $uami = AzJson identity create -g $aRg -n "$agent-id" -l $Location
  $law = AzJson monitor log-analytics workspace create -g $aRg -n "law-$agent" -l $Location
  try { AzRun extension add --name application-insights --only-show-errors | Out-Null } catch { }
  $ai = AzJson monitor app-insights component create -g $aRg -a "ai-$agent" -l $Location --workspace $law.id --kind web --application-type web

  $targetScope = "/subscriptions/$sub/resourceGroups/$wRg"
  $roles = @('Reader', 'Monitoring Reader', 'Log Analytics Reader')
  if ($AccessLevel -eq 'High') { $roles += 'Contributor' }
  foreach ($scope in @($targetScope, "/subscriptions/$sub/resourceGroups/$aRg")) {
    foreach ($r in $roles) {
      AzRun role assignment create --assignee-object-id $uami.principalId --assignee-principal-type ServicePrincipal --role $r --scope $scope -o none | Out-Null
    }
  }

  $id = $uami.id
  $body = @{
    location   = $Location
    identity   = @{ type = 'SystemAssigned, UserAssigned'; userAssignedIdentities = @{ $id = @{} } }
    properties = @{
      knowledgeGraphConfiguration     = @{ identity = $id; managedResources = @($targetScope) }
      actionConfiguration             = @{ accessLevel = $AccessLevel; identity = $id; mode = 'Review' }
      logConfiguration                = @{ applicationInsightsConfiguration = @{ appId = $ai.appId; connectionString = $ai.connectionString } }
      incidentManagementConfiguration = @{ type = 'AzMonitor'; connectionName = 'azmonitor' }
    }
  }
  try { ArmPut (Get-AgentUrl) $body | Out-Null }
  catch { throw "Agent creation failed. Is this subscription registered for the SRE Agent preview and is '$Location' supported? See README > Troubleshooting." }

  Write-Host 'Waiting for agent provisioning (2-5 min)...'
  $a = $null
  for ($i = 0; $i -lt 60; $i++) {
    $a = AzTryJson rest --method get --url (Get-AgentUrl)
    if ($a -and $a.properties.provisioningState -eq 'Succeeded') { break }
    if ($a -and $a.properties.provisioningState -eq 'Failed') { throw 'Agent provisioning failed.' }
    Start-Sleep 15
  }
  if (-not $a -or $a.properties.provisioningState -ne 'Succeeded') { throw 'Timed out waiting for the agent.' }
  $script:SreEndpoint = $a.properties.agentEndpoint

  # Known preview quirk: managedResources can come back empty.
  if (-not $a.properties.knowledgeGraphConfiguration.managedResources) {
    AzRun resource update --ids $a.id --api-version $Api `
      --set "properties.knowledgeGraphConfiguration.managedResources=['$targetScope']" `
      --set "properties.logConfiguration.applicationInsightsConfiguration.appId=$($ai.appId)" `
      --set "properties.logConfiguration.applicationInsightsConfiguration.connectionString=$($ai.connectionString)" -o none | Out-Null
  }

  Step 'Connecting the agent to Azure Monitor alerts (Monitoring Contributor for the agent identities)'
  foreach ($p in @($uami.principalId, $a.identity.principalId) | Where-Object { $_ } | Select-Object -Unique) {
    try { AzRun role assignment create --assignee-object-id $p --assignee-principal-type ServicePrincipal --role 'Monitoring Contributor' --scope "/subscriptions/$sub" -o none | Out-Null }
    catch {
      Warn "Could not grant Monitoring Contributor on the subscription; granting it on $wRg only. See README > Troubleshooting if incidents are not picked up."
      try { AzRun role assignment create --assignee-object-id $p --assignee-principal-type ServicePrincipal --role 'Monitoring Contributor' --scope $targetScope -o none | Out-Null } catch { }
    }
  }
  try {
    $me = Get-MyIdentity
    AzRun role assignment create --assignee-object-id $me.Id --assignee-principal-type $me.Type --role 'SRE Agent Administrator' --scope $a.id -o none | Out-Null
  } catch { Warn "Could not grant you 'SRE Agent Administrator' on the agent; ask a subscription owner to grant it." }

  $res = @{ Id = $a.id; Uploaded = $false; Plan = $false }
  Write-Host 'Waiting for access to the agent API (role propagation, up to ~4 min)...'
  if (-not (Wait-DataPlane)) { Warn 'Agent API not reachable yet; re-run Deploy in a few minutes to finish the runbook + response plan.'; return $res }

  Step 'Uploading the sanity runbook to agent memory'
  try {
    $win = ($PSVersionTable.PSVersion.Major -lt 6) -or $IsWindows
    $curl = if ($win) { 'curl.exe' } else { 'curl' }
    $nul = if ($win) { 'NUL' } else { '/dev/null' }
    $md = Join-Path ([IO.Path]::GetTempPath()) "$Prefix-sanity-runbook.md"
    [IO.File]::WriteAllText($md, $Runbook)
    $auth = 'Bearer ' + $script:SreTok
    $code = & $curl -s -o $nul -w '%{http_code}' -X POST -H "Authorization: $auth" -F "files=@$md;type=text/markdown" "$script:SreEndpoint/api/v1/agentmemory/upload"
    Remove-Item $md -ErrorAction SilentlyContinue
    if ("$code" -notmatch '^2') { throw "HTTP $code" }
    $res.Uploaded = $true; Write-Host "Runbook '$Prefix-sanity-runbook.md' uploaded."
  } catch { Warn "Runbook upload skipped ($_). Paste it into the chat instead (menu: Prompts)." }

  Step "Creating incident response plan '$PlanId'"
  try { Set-ResponsePlan $Steps $Instructions; $res.Plan = $true; Write-Host "Enabled: Azure Monitor alerts whose title contains '$Prefix' -> agent '$agent' (Review mode)." }
  catch { Warn "Response plan not created ($_). Create it in the portal: Settings > Incident platform > Azure Monitor." }
  $res
}
function Get-AgentSteps([string]$ThreadId) { try { @((Sre GET "/api/v1/threads/$ThreadId/messages" $null).value) } catch { @() } }
# One readable line per agent step: its narrative, the tools it used and the commands it ran or wants to run.
function Format-AgentStep($m) {
  $x = @($m.azCliExecution, $m.kubectlExecution) | Where-Object { $_ } | Select-Object -First 1
  if ($x) {
    if ("$($x.status)" -match '^Pending') {
      $why = if ("$($x.status)" -match 'Authori') { 'NEEDS YOUR AUTHORIZATION' } else { 'NEEDS YOUR APPROVAL' }
      return [pscustomobject]@{ Key = "$($m.id)|p"; Label = $why; Text = "$($x.command)"; Color = 'Yellow'; Pending = $true }
    }
    return [pscustomobject]@{ Key = "$($m.id)|r"; Label = "ran ($($x.status))"; Text = "$($x.command)"; Color = 'DarkGray'; Pending = $false }
  }
  $t = ("$($m.text)" -replace '\*\*', '' -replace '\s+', ' ').Trim()
  if (-not $t -or $m.isComplete -eq $false) { return $null }
  $tool = $t -match '^(Terminal|Tool Search|Memory Search|Knowledge Graph|Grep|Read File|Write File|Web Search|Python|Todo)\b'
  [pscustomobject]@{ Key = "$($m.id)|t"; Label = $(if ($tool) { 'tool' } else { 'agent' }); Text = $t; Color = $(if ($tool) { 'DarkGray' } else { 'White' }); Pending = $false }
}
function Watch-Incident([int]$Minutes = 20) {
  if (-not (Get-Agent)) { Warn 'The SRE agent is not deployed yet. Deploy first.'; return }
  $inc = Get-Incidents
  $seen = @{}; foreach ($t in $inc) { $seen[$t.id] = $t.lastMessage.id }
  Step "Watching for the alert and the agent's incident thread (up to $Minutes min; press any key to stop)"
  Write-Host "  Alert rule '$AlertName' -> Azure Monitor -> response plan '$PlanId' -> agent '$agent'"
  $start = Get-Date; $fired = $false; $thread = $null; $status = ''; $shown = @{}; $steps = @()
  $done = 'Complete|Fail|Wait|Approv|Pause|Block|Pending|Input|Resolv|Mitigat|Cancel'
  if ($inc) {
    Write-Host "  Latest incident so far: $($inc[0].title) (investigation: $($inc[0].incidentDetails.investigationStatus))"
    if ($inc[0].incidentDetails.investigationStatus -notmatch $done) { $thread = $inc[0]; Write-Host '  It is still being investigated - following it.' }
    elseif (@(Get-FiredAlerts | Where-Object Rule -eq $AlertName)) { $thread = $inc[0]; Write-Host '  The alert is still firing and the agent already picked it up - showing where it got to.' }
  }
  while (((Get-Date) - $start).TotalMinutes -lt $Minutes) {
    $now = Get-Date -Format 'HH:mm:ss'
    if (-not $fired) {
      $al = @(Get-FiredAlerts | Where-Object Rule -eq $AlertName)
      if ($al) { $fired = $true; Write-Host "  [$now] Alert FIRED: $($al[0].Rule) ($($al[0].Severity))" -ForegroundColor Yellow }
    }
    $inc = Get-Incidents
    if (-not $thread) {
      $thread = $inc | Where-Object { -not $seen.ContainsKey($_.id) -or $seen[$_.id] -ne $_.lastMessage.id } | Select-Object -First 1
      if ($thread) { Write-Host "  [$now] SRE agent opened incident: $($thread.title)" -ForegroundColor Green }
      elseif (-not $fired) { Write-Host "  [$now] waiting for the alert to fire (metrics lag a few minutes)..." }
      else { Write-Host "  [$now] waiting for the agent to pick up the alert (it polls every minute)..." }
    }
    if ($thread) {
      $cur = $inc | Where-Object id -eq $thread.id | Select-Object -First 1
      if ($cur) { $thread = $cur }
      if ($thread.incidentDetails.investigationStatus -ne $status) { $status = $thread.incidentDetails.investigationStatus; Write-Host "  [$now] Investigation: $status" -ForegroundColor Cyan }
      $steps = @(Get-AgentSteps $thread.id | ForEach-Object { Format-AgentStep $_ } | Where-Object { $_ })
      $new = @($steps | Where-Object { -not $shown.ContainsKey($_.Key) })
      if ($shown.Count -eq 0 -and $new.Count -gt 12) {
        Write-Host "    ... $($new.Count - 12) earlier steps (see the portal)" -ForegroundColor DarkGray
        $new[0..($new.Count - 13)] | ForEach-Object { $shown[$_.Key] = 1 }; $new = $new[-12..-1]
      }
      foreach ($s in $new) {
        $shown[$s.Key] = 1; $txt = $s.Text
        if ($txt.Length -gt 150) { $txt = $txt.Substring(0, 147) + '...' }
        Write-Host "    $($s.Label): $txt" -ForegroundColor $s.Color
      }
      if ($status -match $done -or $thread.waitReason) { break }
    }
    if (Wait-OrKey 20) { Write-Host '  Stopped watching.'; return }
    Invoke-WatchTick
  }
  if (-not $thread) { Warn "No incident yet. Metric alerts can take 5-10 min to fire; run Watch again or check Status."; return }
  $say = @(Get-AgentSteps $thread.id | Where-Object { $s = Format-AgentStep $_; $s -and $s.Label -eq 'agent' }) | Select-Object -Last 1
  if ($say -and (Format-AgentStep $say).Text.Length -gt 150) {
    $lines = @("$($say.text)" -split "`n")
    Write-Host "`n----- latest from the agent -----" -ForegroundColor Cyan
    Write-Host (($lines | Select-Object -First 40) -join "`n")
    if ($lines.Count -gt 40) { Write-Host '  ...' }
    Write-Host '---------------------------------' -ForegroundColor Cyan
  }
  $pending = @($steps | Where-Object Pending)
  if ($pending) {
    Write-Host "`nThe agent is waiting for you to approve or authorize:" -ForegroundColor Yellow
    $pending | ForEach-Object { Write-Host "  [$($_.Label -replace 'NEEDS YOUR ', '')] $($_.Text)" -ForegroundColor Yellow }
    Write-Host "Open the incident thread '$($thread.title)' and click Approve / Authorize (or Deny)." -ForegroundColor Yellow
    Write-Host '  Approve   = Review mode: the agent asks before running anything that changes state.' -ForegroundColor DarkGray
    Write-Host '  Authorize = its identity is read-only (-AccessLevel Low), so it borrows your access for this one call (OBO).' -ForegroundColor DarkGray
  }
  elseif ("$status$($thread.waitReason)" -match 'Pending|Input|Approv|Wait') { Write-Host 'The agent is waiting for you (Review mode): open the incident and reply or approve.' -ForegroundColor Yellow }
  Write-Host "Full thread, approvals and follow-up chat: https://sre.azure.com -> agent '$agent' -> Incidents"
}
function Show-AgentStatus {
  $a = Get-Agent
  if (-not $a) { Write-Host "  SRE agent : $agent - not deployed"; return }
  Write-Host "  SRE agent : $agent ($($a.properties.provisioningState), $($a.properties.actionConfiguration.mode) mode, access $($a.properties.actionConfiguration.accessLevel))"
  Write-Host "  Portal    : https://sre.azure.com (pick agent '$agent')"
  Write-Host "  Incidents : $($a.properties.incidentManagementConfiguration.type) incident platform"
  $plan = try { @(Sre GET '/api/v1/incidentplayground/filters' $null) | Where-Object id -eq $PlanId | Select-Object -First 1 } catch { $null }
  Write-Host "  Plan      : $(if ($plan) { "$PlanId (enabled: $($plan.isEnabled), mode: $($plan.agentMode), title contains '$($plan.titleContains)')" } else { 'not found (re-run Deploy) or no access yet' })"
  $fired = @(Get-FiredAlerts)
  Write-Host "  Alerts    : $(if ($fired) { ($fired | ForEach-Object { "$($_.Rule) [$($_.State)]" }) -join ', ' } else { 'none firing' })"
  Write-Host '  Recent incident threads:'
  Show-Incidents (Get-Incidents)
}

# ---------- names (unique per participant and subscription) ----------
function Set-Context {
  $acct = AzJson account show
  $script:sub = $acct.id; $script:subName = $acct.name
  if (-not $PrefixGiven) {
    $u = "$($acct.user.name)".ToLower()
    $alias = (($u -split '@')[0]) -replace '[^a-z0-9]', ''
    if ($alias.Length -gt 5) { $alias = $alias.Substring(0, 5) }
    if (-not $alias) { $alias = 'user' }
    $script:Prefix = "$Kind$alias$((Get-Hash $u).Substring(0, 2))"
  }
  $sfx = (Get-Hash "$sub$Prefix").Substring(0, 4)
  $script:wRg = "rg-$Prefix-workload"; $script:aRg = "rg-$Prefix-agent"; $script:agent = "sre-$Prefix-$sfx"
  $script:AlertName = "$Prefix-$AlertSuffix"; $script:PlanId = "$Prefix-incident-plan"
  $script:PreflightOk = $false; $script:SreEndpoint = $null
  Set-WorkloadNames $sfx
}

# ================= workload: App Service (Linux) + Node.js app =================
function Test-Workload([string]$Loc) {
  if (-not $script:AspRegions) { $script:AspRegions = @(AzJson appservice list-locations --sku $Sku --linux-workers-enabled | ForEach-Object { ($_.name -replace '\s', '').ToLower() }) }
  $ok = $script:AspRegions -contains $Loc
  Show-Check "App Service plan $Sku (Linux)" $ok $(if ($ok) { "offered in $Loc" } else { "not offered in $Loc" })
  $ok
}
function Set-WorkloadNames([string]$Sfx) {
  $script:asp = "asp-$Prefix-$Sfx"; $script:app = "app-$Prefix-$Sfx"; $script:wAiName = "ai-$Prefix-$Sfx"; $script:wLawName = "law-$Prefix-$Sfx"
  $script:AspRegions = $null; $script:AppUrl = $null
}
function Get-SizeArg { "-Sku $Sku" }
# Newest Node.js LTS that App Service offers today (works with old and new az output formats).
function Get-NodeRuntime {
  $rx = '^NODE[|:](\d+)-lts$'
  $best = @(AzTryJson webapp list-runtimes --os-type linux) | ForEach-Object { if ($_ -is [string]) { $_ } else { $_.config } } |
    Where-Object { $_ -match $rx } | Sort-Object { [int]($_ -replace $rx, '$1') } -Descending | Select-Object -First 1
  if ($best) { $best -replace '\|', ':' } else { 'NODE:22-lts' }
}
function Get-AppUrl {
  if (-not $script:AppUrl) {
    $h = (AzTry webapp show -g $wRg -n $app --query defaultHostName -o tsv) -join ''
    if ($h) { $script:AppUrl = "https://$h/" }
  }
  $script:AppUrl
}
function Get-AppCode {
  try { [int](Invoke-WebRequest (Get-AppUrl) -UseBasicParsing -TimeoutSec 15).StatusCode }
  catch { if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { 0 } }
}
# App setting changes restart the app; on B1 that can take a few minutes.
function Wait-AppCode([int]$Code, [int]$Seconds = 300) {
  $t0 = Get-Date
  while (((Get-Date) - $t0).TotalSeconds -lt $Seconds) {
    $c = Get-AppCode
    if ($c -eq $Code) { Write-Host "  app now returns HTTP $c (after $([int]((Get-Date) - $t0).TotalSeconds)s)"; return $true }
    Write-Host "  still HTTP $c - waiting for the restart..." -ForegroundColor DarkGray
    Start-Sleep 15
  }
  $false
}
function Send-Traffic([int]$Count) {
  $codes = [ordered]@{}
  for ($i = 0; $i -lt $Count; $i++) { $c = Get-AppCode; $codes["$c"] = 1 + [int]$codes["$c"] }
  ($codes.GetEnumerator() | ForEach-Object { "HTTP $($_.Key) x$($_.Value)" }) -join ', '
}
# While watching, simulate a few users so the HTTP 5xx metric keeps getting data.
function Invoke-WatchTick {
  if (-not $script:TickSaid) { Write-Host '  (simulating users: 5 requests to the app every 20s)' -ForegroundColor DarkGray; $script:TickSaid = $true }
  [void](Send-Traffic 5)
}
function Assert-Deployed { if (-not (AzTry webapp show -g $wRg -n $app --query id -o tsv)) { throw "Web app $app not found - run Deploy first." } }
function Get-Runbook([string]$Url) {
  @"
# App Service sanity runbook - $app (resource group $wRg)
Read-only checks. Report a PASS/WARN/FAIL table, then root cause and a recommended fix for anything not PASS.

1. Web app $app state must be Running; App Service plan $asp ($Sku) must be healthy.
2. Application check: HTTP GET $Url must return 200 with 'healthy' in the body; ${Url}health must return 200 'ok'.
3. Application Insights ($wAiName), last 60 min: failed request rate (WARN > 1%, FAIL > 5%), p95 response time (WARN > 1s), exceptions.
4. Platform metrics, last 60 min: Http5xx, Http4xx, AverageResponseTime; plan CpuPercentage and MemoryPercentage (WARN > 80%).
5. Activity log, last 24h: deployments, restarts, app setting changes. Correlate any change with the start of errors.
6. App settings: look for suspicious or drifted settings such as FAULT. Never print secret values.
"@
}
function Get-PlanSteps([string]$Url) {
  @(
    'Acknowledge the incident: name the alert rule, the affected resource, the severity and when it fired.',
    "Run the App Service sanity runbook from your memory ($Prefix-sanity-runbook.md) against web app $app in resource group $wRg and show the PASS/WARN/FAIL table.",
    "Test the app: HTTP GET $Url should return 200 with the word 'healthy'.",
    "Correlate the evidence: Http5xx and response time for the last 60 minutes, failed requests and exceptions in Application Insights $wAiName, and Activity Log changes in the last 2 hours (app settings, restarts, deployments).",
    'State the most likely root cause and the evidence behind it.',
    "Propose the mitigation as exact az CLI commands (for example az webapp config appsettings delete -g $wRg -n $app --setting-names <name>, or az webapp restart -g $wRg -n $app). Ask for approval before changing anything.",
    "After mitigation, re-check $Url and Http5xx and confirm that alert $AlertName resolves.",
    'Finish with a short incident report: timeline, impact, root cause, fix and one prevention idea.'
  )
}
function Get-Instructions { "You are the on-call SRE for a hackathon demo workload. Only investigate and act on resources in resource group $wRg. Be concise: use tables and bullet points. Never print secrets." }
function Show-Prompts {
  $url = Get-AppUrl
  Write-Host "`nPrompts to try in the agent chat (https://sre.azure.com -> agent '$agent'):" -ForegroundColor Cyan
  Write-Host "  1. Run the App Service sanity runbook for $app in resource group $wRg and give me a PASS/WARN/FAIL table."
  Write-Host "  2. Why is $url returning errors? Check the app, its settings and Application Insights."
  Write-Host "  3. Show me failed requests and exceptions for $app in the last hour."
  Write-Host "  4. What changed on $app in the last 24 hours (deployments, app settings, restarts)?"
  Write-Host "  5. Is plan $asp sized correctly for this app? Check CPU and memory."
  Write-Host "  6. Summarize the latest incident: timeline, root cause, fix and prevention."
  Write-Host "`nIf the runbook is not in the agent's memory, paste this first:" -ForegroundColor DarkGray
  Write-Host (Get-Runbook $url) -ForegroundColor DarkGray
}
function Show-WorkloadStatus {
  $w = AzTryJson webapp show -g $wRg -n $app
  if (-not $w) { Write-Host "  Web app   : $app - not deployed"; return }
  $url = "https://$($w.defaultHostName)/"
  $fault = (AzTry webapp config appsettings list -g $wRg -n $app --query "[?name=='FAULT'].value" -o tsv) -join ''
  $faultText = if ($fault) { "FAULT=$fault - injected by Break" } else { 'none' }
  Write-Host "  Web app   : $app ($($w.state), plan $asp, $($w.location))"
  Write-Host "  App       : $url -> $(Get-HttpState $url 'healthy')"
  Write-Host "  Fault     : $faultText"
  Write-Host "  Alert rule: $AlertName (more than 5 HTTP 5xx in 5 min, Sev2)"
}
function Invoke-Deploy {
  if (-not $script:PreflightOk) { Invoke-Preflight }
  Ensure-Providers @('Microsoft.Web', 'Microsoft.App', 'Microsoft.OperationalInsights', 'Microsoft.Insights', 'Microsoft.AlertsManagement', 'Microsoft.ManagedIdentity')

  Step "Creating workload RG, Application Insights, App Service plan ($Sku, Linux) and web app"
  AzRun group create -n $wRg -l $Location -o none | Out-Null
  $wLaw = AzJson monitor log-analytics workspace create -g $wRg -n $wLawName -l $Location
  try { AzRun extension add --name application-insights --only-show-errors | Out-Null } catch { }
  $wAi = AzJson monitor app-insights component create -g $wRg -a $wAiName -l $Location --workspace $wLaw.id --kind web --application-type web
  if (-not (AzTry appservice plan show -g $wRg -n $asp --query id -o tsv)) { AzRun appservice plan create -g $wRg -n $asp -l $Location --sku $Sku --is-linux -o none | Out-Null }
  if (-not (AzTry webapp show -g $wRg -n $app --query id -o tsv)) {
    $rt = Get-NodeRuntime; Write-Host "  runtime $rt"
    AzRun webapp create -g $wRg -p $asp -n $app --runtime $rt --only-show-errors -o none | Out-Null
  }
  AzRun webapp config appsettings set -g $wRg -n $app --settings "APPLICATIONINSIGHTS_CONNECTION_STRING=$($wAi.connectionString)" 'ApplicationInsightsAgent_EXTENSION_VERSION=~3' 'SCM_DO_BUILD_DURING_DEPLOYMENT=false' -o none | Out-Null
  try { AzRun webapp config set -g $wRg -n $app --generic-configurations healthCheckPath=/health -o none | Out-Null } catch { Warn 'Could not set the health check path; continuing.' }
  $script:AppUrl = $null; $url = Get-AppUrl

  Step 'Deploying the Node.js app (zip deploy)'
  $dir = Join-Path ([IO.Path]::GetTempPath()) "$Prefix-src"
  New-Item -ItemType Directory -Force $dir | Out-Null
  [IO.File]::WriteAllText((Join-Path $dir 'package.json'), '{"name":"sre-demo-app","version":"1.0.0","scripts":{"start":"node server.js"}}')
  [IO.File]::WriteAllText((Join-Path $dir 'server.js'), @'
const http = require('http');
http.createServer((req, res) => {
  const fault = process.env.FAULT || 'none';
  if (fault === 'error') { console.error('dependency call failed: connection refused (FAULT=error)'); res.writeHead(500); return res.end('unhealthy: simulated dependency failure'); }
  if (fault === 'slow' && req.url !== '/health') { return setTimeout(() => { res.writeHead(200); res.end('slow'); }, 8000); }
  res.writeHead(200, { 'Content-Type': 'text/plain' });
  res.end(req.url === '/health' ? 'ok' : 'SRE demo web app - healthy');
}).listen(process.env.PORT || 8080);
'@.Replace("`r`n", "`n"))
  $zip = Join-Path ([IO.Path]::GetTempPath()) "$Prefix-app.zip"
  Remove-Item $zip -ErrorAction SilentlyContinue
  Compress-Archive -Path (Join-Path $dir '*') -DestinationPath $zip
  Write-Host '  uploading and starting the app (first start takes 2-3 min)...'
  try { AzRun webapp deploy -g $wRg -n $app --src-path $zip --type zip --only-show-errors -o none | Out-Null }
  finally { Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue; Remove-Item $zip -ErrorAction SilentlyContinue }

  Step "Waiting for $url to report healthy"
  $ok = $false
  for ($i = 0; $i -lt 30 -and -not $ok; $i++) {
    try { $ok = (Invoke-WebRequest $url -UseBasicParsing -TimeoutSec 10).Content -match 'healthy' } catch { Start-Sleep 10 }
  }
  if ($ok) { Write-Host 'App is healthy.' -ForegroundColor Green } else { Warn 'App did not respond yet; give it a minute.' }

  Step "Creating Azure Monitor alert '$AlertName' (more than 5 HTTP 5xx in 5 min, Sev2)"
  $appId = (AzRun webapp show -g $wRg -n $app --query id -o tsv) -join ''
  New-MetricAlert $appId 'Microsoft.Web/sites' 'Http5xx' 'Total' 5 $null "More than 5 HTTP 5xx errors in 5 min on $app - users of $url are getting errors."

  $res = New-SreAgent (Get-Runbook $url) (Get-PlanSteps $url) (Get-Instructions)

  Write-Host "`n======================= READY =======================" -ForegroundColor Green
  Write-Host " App URL       : $url"
  Write-Host " Alert rule    : $AlertName (more than 5 HTTP 5xx in 5 min)"
  Write-Host " SRE agent     : $agent  ->  https://sre.azure.com"
  Write-Host " Response plan : $(if ($res.Plan) { "$PlanId (alerts with '$Prefix' in the title, Review mode)" } else { 'NOT created - see warnings above' })"
  Write-Host " Runbook       : $(if ($res.Uploaded) { 'uploaded to agent memory' } else { 'not uploaded - use the Prompts option' })"
  Write-Host '======================================================' -ForegroundColor Green
  if ($Action -ne 'Menu') { Write-Host "Next: $Me -Action Break, then $Me -Action Watch" }
}
function Invoke-Break {
  Assert-Deployed
  Step 'Breaking the app: setting app setting FAULT=error (every request now returns HTTP 500)'
  AzRun webapp config appsettings set -g $wRg -n $app --settings FAULT=error -o none | Out-Null
  Write-Host 'Waiting for the app to restart with the new setting (1-4 min)...'
  if (-not (Wait-AppCode 500)) { Warn 'The app is not returning 500 yet. It will after the restart; Watch keeps sending traffic.' }
  Write-Host "Traffic: $(Send-Traffic 30)"
  Write-Host "Fault injected at $(Get-Date -Format 'HH:mm'). What happens next:" -ForegroundColor Yellow
  Write-Host "  1. $(Get-AppUrl) returns HTTP 500 (try it in a browser)."
  Write-Host "  2. Alert '$AlertName' fires once more than 5 errors are counted in 5 min (about 3-8 min)."
  Write-Host "  3. The agent picks up the alert, opens an incident thread and follows response plan '$PlanId'."
  Write-Host "  4. It proposes a fix and waits for your approval in https://sre.azure.com (Review mode)."
  if ($Action -ne 'Menu') { Write-Host "Watch it: $Me -Action Watch (it also keeps sending a little traffic)" }
}
function Invoke-Fix {
  Assert-Deployed
  Step 'Fixing the app: removing the FAULT app setting'
  AzRun webapp config appsettings delete -g $wRg -n $app --setting-names FAULT -o none | Out-Null
  Write-Host 'Waiting for the app to restart (1-4 min)...'
  if (-not (Wait-AppCode 200)) { Warn 'The app is not healthy yet; check again in a minute with Status.' }
  Write-Host "Traffic: $(Send-Traffic 10)"
  Write-Host "App: $(Get-HttpState (Get-AppUrl) 'healthy'). The alert auto-resolves within ~5-10 min."
  Write-Host "Tip: ask the agent to verify recovery and write the incident summary."
}
function Show-Status {
  Step "Status ($subName)"
  if (Test-Group $wRg) { Show-WorkloadStatus } else { Write-Host "  Workload  : $wRg - not deployed" }
  if (Test-Group $aRg) { Show-AgentStatus } else { Write-Host "  SRE agent : $agent - not deployed" }
}

# ================= interactive menu =================
function Show-Menu {
  Write-Host "`nWelcome to the Azure SRE Agent hackathon kit ($Title)." -ForegroundColor Green
  Write-Host 'Deploy a ready-made app + alert + SRE agent with an incident response plan, break the app, and watch the agent respond.'
  while ($true) {
    $wLoc = (AzTry group show -n $wRg --query location -o tsv) -join ''
    $aOk = Test-Group $aRg
    Write-Host ''
    Write-Host ('=' * 70) -ForegroundColor DarkCyan
    Write-Host " Azure SRE Agent hackathon kit - $Title" -ForegroundColor White
    Write-Host ('=' * 70) -ForegroundColor DarkCyan
    Write-Host " Subscription : $subName ($sub)"
    Write-Host " Workload     : $wRg  [$(if ($wLoc) { "deployed in $wLoc" } else { 'not deployed' })]"
    Write-Host " SRE agent    : $agent  [$(if ($aOk) { 'deployed' } else { 'not deployed' })]"
    $next = if (-not $wLoc -or -not $aOk) { '1) Deploy everything' } else { '2) Break the app, then watch the agent respond' }
    Write-Host " Next step    : $next" -ForegroundColor Yellow
    Write-Host ('-' * 70) -ForegroundColor DarkCyan
    Write-Host "  1) Deploy everything: $DeployWhat"
    Write-Host '  2) Break the app (start an incident) and watch the agent respond'
    Write-Host '  3) Fix the app'
    Write-Host '  4) Status: app health, alerts, agent, incidents'
    Write-Host '  5) Watch the agent pick up and investigate the incident'
    Write-Host '  6) Prompts to try in the agent chat'
    Write-Host '  7) Pre-flight checks only (region, capacity, quota, permissions)'
    Write-Host '  8) Switch subscription'
    Write-Host '  0) Exit'
    $c = Ask "`nChoose an option" ''
    if ($script:NoPrompt) { throw "No interactive input available. Use -Action Deploy|Break|Watch|Fix|Status|Preflight instead." }
    if (-not $c) { if ([Console]::IsInputRedirected) { return }; continue }
    if ($c -eq '0') { return }
    try {
      switch ($c) {
        '1' { Invoke-Deploy }
        '2' { Invoke-Break; if ((Ask 'Watch the agent respond now? (Y/n)' 'Y') -match '^[Yy]') { Watch-Incident } }
        '3' { Invoke-Fix }
        '4' { Show-Status }
        '5' { Watch-Incident }
        '6' { Assert-Deployed; Show-Prompts }
        '7' { $script:PreflightOk = $false; Invoke-Preflight }
        '8' { Select-Subscription -Force; Set-Context }
        default { Warn "Unknown option '$c'." }
      }
    } catch { Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red }
    [void](Ask "`nPress Enter to return to the menu" '')
  }
}

# ================= main =================
if (-not (Get-Command az -ErrorAction SilentlyContinue)) { throw 'Azure CLI (az) not found. Use Azure Cloud Shell (https://shell.azure.com) or install the Azure CLI.' }
try { AzRun account show -o none | Out-Null } catch { throw 'Not logged in. Run: az login' }
Select-Subscription
Set-Context
Write-Host "Subscription: $subName | Name prefix: $Prefix | Workload RG: $wRg | Agent: $agent"
switch ($Action) {
  'Menu' { Show-Menu }
  'Preflight' { Invoke-Preflight; Write-Host "`nDeploy with: $Me -Action Deploy -SubscriptionId $sub -Location $Location $(Get-SizeArg)" }
  'Deploy' { Invoke-Deploy }
  'Status' { Show-Status }
  'Break' { Invoke-Break }
  'Watch' { Watch-Incident }
  'Fix' { Invoke-Fix }
}
