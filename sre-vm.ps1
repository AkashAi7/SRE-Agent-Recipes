<#
.SYNOPSIS
  Azure SRE Agent hackathon kit - Linux VM.
  Interactive CLI that gives you a ready-made workload (Ubuntu VM running an nginx web app), an Azure Monitor
  alert, and an Azure SRE Agent connected to Azure Monitor with an incident response plan and a sanity runbook.
  Break the app, then watch the agent pick up the incident, investigate it and propose a fix.
.EXAMPLE
  ./sre-vm.ps1                                                       # interactive menu (recommended)
  ./sre-vm.ps1 -Action Deploy -SubscriptionId <id> -Location westus2 # no prompts
  ./sre-vm.ps1 -Action Status | Break | Watch | Fix | Preflight
#>
[CmdletBinding()]
param(
  [string]$SubscriptionId,
  [ValidateSet('Menu', 'Preflight', 'Deploy', 'Status', 'Break', 'Watch', 'Fix')][string]$Action = 'Menu',
  [string]$Location = 'westus2',
  [ValidatePattern('^[a-z][a-z0-9]{1,9}$')][string]$Prefix,
  [ValidateSet('Low', 'High')][string]$AccessLevel = 'Low',
  [string]$VmSize = 'Standard_B2s_v2'
)
$LocationGiven = $PSBoundParameters.ContainsKey('Location')
$PrefixGiven = $PSBoundParameters.ContainsKey('Prefix')
$ErrorActionPreference = 'Stop'
$Api = '2025-05-01-preview'
$Kind = 'vm'; $Title = 'Linux VM'; $Me = './sre-vm.ps1'; $AlertSuffix = 'cpu-high'
$DeployWhat = 'Ubuntu VM + nginx app + CPU alert + SRE agent + incident plan (~15 min)'

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

# ================= workload: Linux VM + nginx =================
# Returns the VM size to use in $Loc (the requested one or a chosen alternative), or $null if the region won't work.
function Test-VmSize([string]$Loc, [string]$Size, [int]$Count) {
  $url = "https://management.azure.com/subscriptions/$sub/providers/Microsoft.Compute/skus?api-version=2021-07-01&`$filter=location eq '$Loc'"
  $all = @((AzJson rest --method get --url $url).value | Where-Object resourceType -eq 'virtualMachines')
  $cap = { param($s, $n) "$(($s.capabilities | Where-Object name -eq $n).value)" }
  $usable = @($all | Where-Object { -not ($_.restrictions | Where-Object type -eq 'Location') })
  $s = $usable | Where-Object name -eq $Size | Select-Object -First 1
  if (-not $s) {
    Show-Check "VM size $Size" $false "not available to this subscription in $Loc"
    $ref = $all | Where-Object name -eq $Size | Select-Object -First 1
    $vcpu = if ($ref) { [double](& $cap $ref 'vCPUs') } else { 2 }; $mem = if ($ref) { [double](& $cap $ref 'MemoryGB') } else { 4 }
    $letter = if ($Size -match '^Standard_(\w)') { $Matches[1] } else { 'D' }
    # Same vCPU count, enough memory, x64 + Gen2 + SCSI capable (works with the default images); prefer same series letter and Premium SSD support.
    $alts = @($usable | Where-Object { $_.name -match '^Standard_[BD]\d' -and $_.name -notmatch 'Promo' -and [double](& $cap $_ 'vCPUs') -eq $vcpu -and
        [double](& $cap $_ 'MemoryGB') -ge $mem -and (& $cap $_ 'HyperVGenerations') -match 'V2' -and (& $cap $_ 'DiskControllerTypes') -notmatch '^NVMe$' -and (& $cap $_ 'CpuArchitectureType') -ne 'Arm64' } |
        Sort-Object { -not $_.name.StartsWith("Standard_$letter") }, { (& $cap $_ 'PremiumIO') -ne 'True' }, { [double](& $cap $_ 'MemoryGB') }, name |
        Select-Object -First 5 -ExpandProperty name)
    if (-not $alts) { return $null }
    Write-Host "    Sizes with $vcpu vCPU available here: $($alts -join ', ')"
    $pick = Ask '    Size to use instead (n = try another region)' $alts[0]
    $s = $usable | Where-Object name -eq $pick | Select-Object -First 1
    if (-not $s) { return $null }
  }
  Show-Check "VM size $($s.name)" $true "available in $Loc"
  $need = $Count * [int](& $cap $s 'vCPUs'); $ok = $true
  foreach ($q in @(AzJson vm list-usage -l $Loc) | Where-Object { $_.name.value -in @('cores', $s.family) }) {
    $free = [int]$q.limit - [int]$q.currentValue
    Show-Check "Quota: $($q.localName)" ($free -ge $need) "$free free, need $need"
    if ($free -lt $need) { $ok = $false }
  }
  if ($ok) { $s.name } else { $null }
}
function Test-Workload([string]$Loc) {
  $s = Test-VmSize $Loc $VmSize 1
  if ($s) { $script:VmSize = $s }
  [bool]$s
}
function Set-WorkloadNames([string]$Sfx) { $script:vm = "vm-$Prefix-$Sfx" }
function Get-SizeArg { "-VmSize $VmSize" }
function Invoke-WatchTick { }
function Invoke-OnVm([string]$Script) {
  $f = Join-Path ([IO.Path]::GetTempPath()) "$Prefix-cmd.sh"
  [IO.File]::WriteAllText($f, $Script.Replace("`r`n", "`n"))
  try { AzRun vm run-command invoke -g $wRg -n $vm --command-id RunShellScript --scripts "@$f" -o none | Out-Null }
  finally { Remove-Item $f -ErrorAction SilentlyContinue }
}
function Get-AppUrl { $ip = (AzTry vm show -d -g $wRg -n $vm --query publicIps -o tsv) -join ''; if ($ip) { "http://$ip/" } }
function Assert-Deployed { if (-not (AzTry vm show -g $wRg -n $vm --query id -o tsv)) { throw "VM $vm not found - run Deploy first." } }
function Get-Runbook([string]$Url) {
  @"
# VM sanity runbook - $vm (resource group $wRg)
Read-only checks. Report a PASS/WARN/FAIL table, then root cause and a recommended fix for anything not PASS.

1. Power and provisioning state of VM $vm (instance view). Expect Running / Succeeded.
2. Azure Resource Health availability of the VM.
3. Platform metrics, last 60 min: Percentage CPU (WARN > 70% avg, FAIL > 90%), Network In/Out, Disk operations.
4. NSG exposure: only TCP 80 may be open to the internet. Flag SSH/RDP open to any source.
5. Activity log, last 24h: errors, restarts, failed operations.
6. Application check: HTTP GET $Url must return 200 and contain the word 'healthy'. If not, assume nginx is down.
7. If run-command is permitted: 'systemctl is-active nginx' and the top CPU processes.
"@
}
function Get-PlanSteps([string]$Url) {
  @(
    'Acknowledge the incident: name the alert rule, the affected resource, the severity and when it fired.',
    "Run the VM sanity runbook from your memory ($Prefix-sanity-runbook.md) against VM $vm in resource group $wRg and show the PASS/WARN/FAIL table.",
    "Test the app: HTTP GET $Url should return 200 with the word 'healthy'.",
    "Correlate the evidence: Percentage CPU for the last 60 minutes, Activity Log changes in the last 2 hours and, if run-command is allowed, 'systemctl is-active nginx' plus the top CPU processes.",
    'State the most likely root cause and the evidence behind it.',
    "Propose the mitigation as exact az CLI commands (for example az vm run-command invoke -g $wRg -n $vm --command-id RunShellScript --scripts '...'). Ask for approval before changing anything.",
    "After mitigation, re-check $Url and CPU and confirm that alert $AlertName resolves.",
    'Finish with a short incident report: timeline, impact, root cause, fix and one prevention idea.'
  )
}
function Get-Instructions { "You are the on-call SRE for a hackathon demo workload. Only investigate and act on resources in resource group $wRg. Be concise: use tables and bullet points. Never print secrets." }
function Show-Prompts {
  $url = Get-AppUrl
  Write-Host "`nPrompts to try in the agent chat (https://sre.azure.com -> agent '$agent'):" -ForegroundColor Cyan
  Write-Host "  1. Run the VM sanity runbook for $vm in resource group $wRg and give me a PASS/WARN/FAIL table."
  Write-Host "  2. Why is $url not responding? Check the VM, nginx and CPU."
  Write-Host "  3. Show me the CPU trend for $vm over the last hour and what is using it."
  Write-Host "  4. What changed in resource group $wRg in the last 24 hours?"
  Write-Host "  5. Which NSG rules expose $vm to the internet? Is anything risky?"
  Write-Host "  6. Summarize the latest incident: timeline, root cause, fix and prevention."
  Write-Host "`nIf the runbook is not in the agent's memory, paste this first:" -ForegroundColor DarkGray
  Write-Host (Get-Runbook $url) -ForegroundColor DarkGray
}
function Show-WorkloadStatus {
  $v = AzTryJson vm show -d -g $wRg -n $vm
  if (-not $v) { Write-Host "  VM        : $vm - not deployed"; return }
  Write-Host "  VM        : $vm ($($v.powerState), $($v.hardwareProfile.vmSize), $($v.location))"
  Write-Host "  App       : http://$($v.publicIps)/ -> $(Get-HttpState "http://$($v.publicIps)/" 'healthy')"
  Write-Host "  Alert rule: $AlertName (avg CPU > 80% over 5 min, Sev2)"
}
function Invoke-Deploy {
  if (-not $script:PreflightOk) { Invoke-Preflight }
  Ensure-Providers @('Microsoft.Compute', 'Microsoft.Network', 'Microsoft.App', 'Microsoft.OperationalInsights', 'Microsoft.Insights', 'Microsoft.AlertsManagement', 'Microsoft.ManagedIdentity')

  Step "Creating workload RG + Ubuntu VM ($VmSize) running nginx"
  AzRun group create -n $wRg -l $Location -o none | Out-Null
  if (AzTry vm show -g $wRg -n $vm --query id -o tsv) { Write-Host "VM $vm already exists, reusing it." }
  else {
    $ci = Join-Path ([IO.Path]::GetTempPath()) "$Prefix-cloud-init.yaml"
    [IO.File]::WriteAllText($ci, @'
#cloud-config
package_update: true
packages: [nginx]
write_files:
  - path: /var/www/html/index.html
    content: |
      <h1>SRE demo VM - healthy</h1>
runcmd:
  - systemctl enable --now nginx
'@.Replace("`r`n", "`n"))
    try {
      AzRun vm create -g $wRg -n $vm --image Ubuntu2204 --size $VmSize --admin-username azureuser --generate-ssh-keys `
        --custom-data $ci --public-ip-sku Standard --nsg-rule NONE -o none | Out-Null
    } finally { Remove-Item $ci -ErrorAction SilentlyContinue }
  }
  try { AzRun vm open-port -g $wRg -n $vm --port 80 --priority 900 -o none | Out-Null } catch { Warn 'Could not open port 80 (it may already be open).' }
  $url = Get-AppUrl

  Step "Waiting for $url to report healthy"
  $ok = $false
  for ($i = 0; $i -lt 40 -and -not $ok; $i++) {
    try { $ok = (Invoke-WebRequest $url -UseBasicParsing -TimeoutSec 5).Content -match 'healthy' } catch { Start-Sleep 10 }
  }
  if ($ok) { Write-Host 'App is healthy.' -ForegroundColor Green } else { Warn 'App did not respond yet (cloud-init may still be running).' }

  Step "Creating Azure Monitor alert '$AlertName' (avg CPU > 80% over 5 min, Sev2)"
  $vmId = (AzRun vm show -g $wRg -n $vm --query id -o tsv) -join ''
  New-MetricAlert $vmId 'Microsoft.Compute/virtualMachines' 'Percentage CPU' 'Average' 80 $null "CPU on $vm is above 80% - the web app at $url may be degraded."

  $res = New-SreAgent (Get-Runbook $url) (Get-PlanSteps $url) (Get-Instructions)

  Write-Host "`n======================= READY =======================" -ForegroundColor Green
  Write-Host " App URL       : $url"
  Write-Host " Alert rule    : $AlertName (avg CPU > 80% over 5 min)"
  Write-Host " SRE agent     : $agent  ->  https://sre.azure.com"
  Write-Host " Response plan : $(if ($res.Plan) { "$PlanId (alerts with '$Prefix' in the title, Review mode)" } else { 'NOT created - see warnings above' })"
  Write-Host " Runbook       : $(if ($res.Uploaded) { 'uploaded to agent memory' } else { 'not uploaded - use the Prompts option' })"
  Write-Host '======================================================' -ForegroundColor Green
  if ($Action -ne 'Menu') { Write-Host "Next: $Me -Action Break, then $Me -Action Watch" }
}
function Invoke-Break {
  Assert-Deployed
  Step 'Breaking the app: stopping nginx and starting 2 CPU burners on the VM'
  Invoke-OnVm "systemctl stop nginx; for i in 1 2; do setsid nohup yes >/dev/null 2>&1 & done; sleep 1; echo done"
  Write-Host "Fault injected at $(Get-Date -Format 'HH:mm'). What happens next:" -ForegroundColor Yellow
  Write-Host "  1. $(Get-AppUrl) is down (try it in a browser) and CPU is pinned at 100%."
  Write-Host "  2. Alert '$AlertName' fires once avg CPU stays above 80% (about 5-10 min)."
  Write-Host "  3. The agent picks up the alert, opens an incident thread and follows response plan '$PlanId'."
  Write-Host "  4. It proposes a fix and waits for your approval in https://sre.azure.com (Review mode)."
  if ($Action -ne 'Menu') { Write-Host "Watch it: $Me -Action Watch" }
}
function Invoke-Fix {
  Assert-Deployed
  Step 'Fixing the app: killing the CPU burners and starting nginx'
  Invoke-OnVm "pkill -x yes; systemctl start nginx; echo done"
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
