<# ====================================================================================================
NAME
    Set-Sentinel-Data-Lake-Retentions.ps1

SYNOPSIS
    Idempotent per-table retention & plan manager for Microsoft Sentinel / Log Analytics workspaces.
    Reads desired settings from a CSV and applies them only when different, with a WhatIf-safe dry run.

WHAT COUNTS AS “SENTINEL” HERE?
    Per your requirement: **if a table exists in the Log Analytics workspace, and the workspace is connected
    to Sentinel, it is treated as a Sentinel table**—except **Custom** tables, which the UI shows as “Custom”.
    We therefore classify:
      • Sentinel  = every Log Analytics table that is NOT Custom
      • Custom    = schema.tableType = CustomLog  (or name like *_CL)
      • XDR       = ignored (does not exist in Log Analytics; only in Defender) — TYPE:XDR returns none

DESCRIPTION
    - Multi-subscription / multi-tenant via per-row SubscriptionId.
    - Wildcard pattern matching (* and ?) for table names.
    - Supports special TYPE filters in CSV:
        TYPE:SENTINEL              → all LA tables that are NOT Custom
        TYPE:SENTINEL:ANALYTICS    → same, but Plan = Analytics
        TYPE:CUSTOM                → all CustomLog tables (e.g., *_CL)
        TYPE:XDR                   → (empty by design; XDR isn’t in LA)
    - Idempotent: only updates when values differ.
    - Optional plan changes per table (Analytics/Basic) if provided.
    - Optional auto-upgrade: Sentinel tables with CSV=30 → 90 days Analytics.
    - Coverage report (UNMATCHED printed first; full bulleted lists), compact matched summary,
      and detailed “WhatIf/Changes” section.
    - Exports a CSV of the full run.

CSV FORMAT
    Required columns:
      SubscriptionId,ResourceGroup,Workspace,TablePattern,AnalyticsRetentionDays,DataLakeTotalRetentionInDays
    Optional:
      Plan  (Analytics | Basic) — blank to keep current.

    TablePattern can be a wildcard or a TYPE token:
      Examples:
        SecurityEvent
        Device*Events
        *_CL
        *
        TYPE:SENTINEL
        TYPE:SENTINEL:ANALYTICS
        TYPE:CUSTOM
        TYPE:XDR  # returns none (by design)

EXAMPLE CSV
    SubscriptionId,ResourceGroup,Workspace,TablePattern,AnalyticsRetentionDays,DataLakeTotalRetentionInDays,Plan
    00000000-0000-0000-0000-000000000000,rg,ws,TYPE:SENTINEL:ANALYTICS,90,365,Analytics
    00000000-0000-0000-0000-000000000000,rg,ws,SecurityEvent,90,180,Analytics
    00000000-0000-0000-0000-000000000000,rg,ws,*_CL,30,730,Analytics

AUTO-UPGRADE (OPTIONAL)
    $AutoUpgradeSentinelAnalyticsFrom30To90 = $true :
      For **Sentinel** tables (i.e., not Custom), if CSV asks for 30 days, target becomes 90.
    $AutoUpgradeSentinelAnalyticsFrom30To90 = $false :
      CSV value is respected.

OUTPUT ORDER
    1) Out-of-Scope tables (no match) — grouped by workspace header
    2) Retention Setting after Change (in-scope tables) — grouped by workspace header
    3) Retention Setting WhatIf Changes (in-scope tables) — grouped by workspace header

USAGE
    • Run with static defaults (no params):  .\Set-Sentinel-Data-Lake-Retentions.ps1
    • Actually apply changes:                .\Set-Sentinel-Data-Lake-Retentions.ps1 -WhatIf:$false
    • Verbose logging:                       .\Set-Sentinel-Data-Lake-Retentions.ps1 -Verbose
==================================================================================================== #>

# ---------- STATIC DEFAULTS ----------
$DefaultCsvPath  = "C:\TMP\Sentinel-Data-Lake-Retention\Sentinel-Data-Lake-Retentions.csv"
$DefaultTenantId = "f0fa27a0-8e7c-4f63-9a77-ec94786b7c9e"
$DefaultWhatIf   = $true

# ---------- LOGIN SETTINGS ----------
# Choose one:
#   "Interactive"            → opens browser sign-in (no device code used)
#   "ServicePrincipalSecret" → uses Client ID + Secret below
$LoginMode           = "Interactive"
$ForceLoginAtStart   = $true   # prompt at start even if a context exists

# Service principal secret creds (used only when $LoginMode = "ServicePrincipalSecret")
$SpnTenantId         = $DefaultTenantId      # override per your SPN tenant if different
$SpnClientId         = "<APP/CLIENT ID GUID>"
$SpnClientSecret     = "<CLIENT SECRET VALUE>"  # load from secure store in production

# Auto-upgrade (CSV 30 -> force 90) for Sentinel tables (non-Custom)
$AutoUpgradeSentinelAnalyticsFrom30To90 = $true

# Include NoChange rows in final summary table/CSV
$IncludeNoChangeInSummary = $true

# ---------- READABILITY/OUTPUT TUNING ----------
$DefaultSummaryCsvPath = "C:\TMP\Sentinel-Data-Lake-Retention\retention-summary_{date}.csv"
$EnableOutGridView     = $true
$ConsoleBufferWidth    = 220
$MaxRG = 30; $MaxWS = 30; $MaxTable = 42
# ----------------------------------------------

# ---------- Output helpers ----------
function Write-Step([string]$msg) { Write-Host ("[STEP]  {0}" -f $msg) }
function Write-Info([string]$msg) { Write-Host ("[INFO]  {0}" -f $msg) }
function Write-Done([string]$msg) { Write-Host ("[DONE]  {0}" -f $msg) }
function Write-Act ([string]$msg) { Write-Host ("[APPLY] {0}" -f $msg) }
function Write-Sim ([string]$msg) { Write-Host ("[WHATIF]{0}" -f $msg) }
function Write-Skip([string]$msg) { Write-Host ("[SKIP]  {0}" -f $msg) }
function Write-Err ([string]$msg) { Write-Host ("[ERROR] {0}" -f $msg); Write-Warning $msg }

function Ensure-Module {
  param([string]$Name)
  if (-not (Get-Module -ListAvailable -Name $Name)) {
    Write-Step ("Installing module $($Name)...")
    Install-Module $Name -Scope CurrentUser -Force -AllowClobber
    Write-Done ("Installed module $($Name).")
  }
  Import-Module $Name -ErrorAction Stop
  Write-Info ("Imported module $($Name).")
}

function Get-WorkspaceTables {
  param([string]$ResourceGroupName,[string]$WorkspaceName)
  Write-Info ("Fetching tables for RG='$($ResourceGroupName)' WS='$($WorkspaceName)' ...")
  $result = Get-AzOperationalInsightsTable -ResourceGroupName $ResourceGroupName -WorkspaceName $WorkspaceName
  Write-Done ("Fetched $(@($result).Count) tables.")
  return $result
}

function Normalize-RequestedName {
  param([string]$Name)
  switch -Regex ($Name) { '^SecurityEvents$' { 'SecurityEvent'; break } default { $Name } }
}

function Convert-WildcardToRegex { param([string]$Pattern) $Pattern -replace '\.', '\.' -replace '\*', '.*' -replace '\?', '.' }

# --- helpers to read nested schema props safely ---
function Get-TableSchemaProp {
  param([object]$Table,[string]$PropName)
  if ($Table.PSObject.Properties['Schema'] -and $Table.Schema.PSObject.Properties[$PropName]) { return $Table.Schema.$PropName }
  if ($Table.PSObject.Properties['Properties'] -and $Table.Properties.PSObject.Properties['Schema'] -and $Table.Properties.Schema.PSObject.Properties[$PropName]) { return $Table.Properties.Schema.$PropName }
  return $null
}

# CLASSIFICATION (per your rule):
# - Custom   = schema.tableType == 'CustomLog' OR name like *_CL (case-insensitive)
# - Sentinel = NOT Custom  (everything that exists in LA and is not Custom)
function Test-IsCustomTable {
  param([object]$Table)
  $tt = Get-TableSchemaProp -Table $Table -PropName 'TableType'
  if ($tt -and $tt -eq 'CustomLog') { return $true }
  if ($Table.Name -match '(?i)_CL$') { return $true }
  return $false
}

function Test-IsSentinelTable {
  param([object]$Table)
  return -not (Test-IsCustomTable -Table $Table)  # XDR is not in LA; nothing else to exclude
}

# --- Login helper (Interactive or Service Principal Secret; no device code) ---
function Invoke-AzLogin {
  param([string]$TenantToUse)
  $t = if ([string]::IsNullOrWhiteSpace($TenantToUse)) { $DefaultTenantId } else { $TenantToUse }

  if ($LoginMode -eq "ServicePrincipalSecret") {
    if ([string]::IsNullOrWhiteSpace($SpnClientId) -or [string]::IsNullOrWhiteSpace($SpnClientSecret) -or [string]::IsNullOrWhiteSpace($SpnTenantId)) {
      throw "ServicePrincipalSecret login selected but SPN variables are missing."
    }
    Write-Step ("Logging in as Service Principal (ClientId=$($SpnClientId)) to Tenant=$($t)")
    $sec = ConvertTo-SecureString $SpnClientSecret -AsPlainText -Force
    $cred = New-Object System.Management.Automation.PSCredential($SpnClientId, $sec)
    Connect-AzAccount -ServicePrincipal -Tenant $t -Credential $cred -ErrorAction Stop | Out-Null
    Write-Done ("Logged in (SPN).")
  }
  else {
    Write-Step ("Interactive login to Tenant=$($t)")
    Connect-AzAccount -Tenant $t -ErrorAction Stop | Out-Null
    Write-Done ("Logged in (Interactive).")
  }
}

# Pattern matching with TYPE: tokens
function Match-TablesByPattern {
  param([System.Collections.Generic.List[object]]$AllTables,[string]$Pattern)

  $norm = Normalize-RequestedName $Pattern

  # Special TYPE tokens
  if ($norm -match '^(?i)\s*TYPE\s*:\s*SENTINEL\s*(?::\s*ANALYTICS\s*)?$') {
    $onlyAnalytics = ($norm -match '(?i):\s*ANALYTICS')
    Write-Info ("Pattern '$($Pattern)' resolved to TYPE:SENTINEL (onlyAnalytics=$($onlyAnalytics))")
    $ts = $AllTables | Where-Object { Test-IsSentinelTable -Table $_ }
    if ($onlyAnalytics) { $ts = $ts | Where-Object { $_.Plan -eq 'Analytics' } }
    Write-Done ("TYPE:SENTINEL matched $(@($ts).Count) tables.")
    return $ts
  }
  if ($norm -match '^(?i)\s*TYPE\s*:\s*CUST(OM)?\s*$') {
    Write-Info ("Pattern '$($Pattern)' resolved to TYPE:CUSTOM")
    $ts = $AllTables | Where-Object { Test-IsCustomTable -Table $_ }
    Write-Done ("TYPE:CUSTOM matched $(@($ts).Count) tables.")
    return $ts
  }
  if ($norm -match '^(?i)\s*TYPE\s*:\s*XDR\s*$') {
    Write-Info ("Pattern '$($Pattern)' resolved to TYPE:XDR (not in LA) → 0 matches by design")
    return @()
  }

  # Regular wildcard
  $regex = '^' + (Convert-WildcardToRegex $norm) + '$'
  Write-Info ("Pattern '$($Pattern)' -> regex '$($regex)'")
  $ts = $AllTables | Where-Object { $_.Name -match $regex }
  Write-Done ("Wildcard matched $(@($ts).Count) tables for pattern '$($Pattern)'.")
  return $ts
}

# Switch subscription context (with cross-tenant retry)
function Ensure-SubscriptionContext {
  param([string]$SubscriptionId)
  $ctx = Get-AzContext
  if ($ctx -and $ctx.Subscription -and $ctx.Subscription.Id -eq $SubscriptionId) {
    Write-Info ("Already in subscription context $($SubscriptionId).")
    return $true
  }
  try {
    Write-Step ("Setting context to subscription $($SubscriptionId)")
    Set-AzContext -Subscription $SubscriptionId -ErrorAction Stop | Out-Null
    Write-Done ("Context set to $($SubscriptionId).")
    return $true
  } catch {
    Write-Info ("Set-AzContext failed for $($SubscriptionId): $($_)")
    try {
      $subInfo   = Get-AzSubscription -SubscriptionId $SubscriptionId -ErrorAction Stop
      $subTenant = $subInfo.TenantId
      if (-not $subTenant) { throw "TenantId not found for subscription $($SubscriptionId)" }
      Write-Step ("Cross-tenant login to Tenant=$($subTenant) for Subscription=$($SubscriptionId)")
      Invoke-AzLogin -TenantToUse $subTenant
      Write-Step ("Retry Set-AzContext to subscription $($SubscriptionId)")
      Set-AzContext -Subscription $SubscriptionId -ErrorAction Stop | Out-Null
      Write-Done ("Context set to $($SubscriptionId) after cross-tenant login.")
      return $true
    } catch {
      Write-Err ("Cannot set context to subscription $($SubscriptionId): $($_)")
      return $false
    }
  }
}

# ---- Readability helpers ----
function Shorten([string]$s,[int]$max){
  if ([string]::IsNullOrEmpty($s)) { return $s }
  if ($s.Length -le $max) { return $s }
  return ($s.Substring(0,[Math]::Max(1,$max-1)) + '…')
}

# ---------------- MAIN ADVANCED FUNCTION ----------------
function Set-SentinelDataLakeRetentions {
  [CmdletBinding(SupportsShouldProcess = $true)]
  param([string]$CsvPath,[string]$TenantId)

  Write-Step ("Starting Set-SentinelDataLakeRetentions")
  Write-Info ("Defaults: CsvPath='$($DefaultCsvPath)', TenantId='$($DefaultTenantId)', DefaultWhatIf=$($DefaultWhatIf)")
  Write-Info ("LoginMode='$($LoginMode)', ForceLoginAtStart=$($ForceLoginAtStart)")

  if ($ConsoleBufferWidth -and $Host.UI -and $Host.UI.RawUI) {
    try {
      $raw = $Host.UI.RawUI
      $cur = $raw.BufferSize
      if ($cur.Width -lt $ConsoleBufferWidth) {
        Write-Info ("Increasing console buffer width to $($ConsoleBufferWidth)")
        $raw.BufferSize = New-Object Management.Automation.Host.Size ($ConsoleBufferWidth, [Math]::Max($cur.Height,5000))
      }
    } catch {
      Write-Info ("Console resize skipped: $($_)")
    }
  }

  if (-not $CsvPath)  { $CsvPath  = $DefaultCsvPath }
  if (-not $TenantId) { $TenantId = $DefaultTenantId }
  if (-not $PSBoundParameters.ContainsKey('WhatIf') -and $DefaultWhatIf) { $WhatIfPreference = $true }

  try {
    Ensure-Module -Name Az.Accounts
    Ensure-Module -Name Az.OperationalInsights
  } catch {
    Write-Err ("Failed to load Az modules: $($_)")
    return
  }

  if (-not (Test-Path $CsvPath)) { Write-Err ("CSV not found: $($CsvPath)"); return }

  try {
    if ($ForceLoginAtStart -or -not (Get-AzContext)) {
      Invoke-AzLogin -TenantToUse $TenantId
    } else {
      Write-Info ("Using existing Az context.")
    }
  } catch {
    Write-Err ("Azure login failed: $($_)")
    return
  }

  Write-Step ("Loading CSV from '$($CsvPath)'")
  $rows = Import-Csv -Path $CsvPath
  if (-not $rows) { Write-Err ("CSV is empty."); return }
  Write-Done ("Loaded $(@($rows).Count) CSV rows.")
  foreach ($r in $rows) {
    if ([string]::IsNullOrWhiteSpace($r.SubscriptionId)) { Write-Err ("Row with Workspace '$($r.Workspace)' is missing SubscriptionId."); return }
  }

  $groups   = $rows | Group-Object SubscriptionId, ResourceGroup, Workspace
  Write-Info ("CSV grouped into $(@($groups).Count) workspace scopes.")
  $summary  = @()
  $coverage = @()

  foreach ($g in $groups) {
    $sub, $rg, $ws = $g.Name -split ',\s*'
    Write-Step ("Scope: Sub='$($sub)' RG='$($rg)' WS='$($ws)'  (rows=$(@($g.Group).Count))")

    if (-not (Ensure-SubscriptionContext -SubscriptionId $sub)) {
      foreach ($row in $g.Group) {
        $summary += [pscustomobject]@{ SubscriptionId=$sub; ResourceGroup=$rg; Workspace=$ws; Table=$row.TablePattern; Plan=$null; AnalyticsRetentionInDays=$null; DataLakeTotalRetentionInDays=$null; Action="Error(SetContext)"; Change=$null }
      }
      continue
    }

    try { $tables = Get-WorkspaceTables -ResourceGroupName $rg -WorkspaceName $ws }
    catch {
      Write-Err ("Could not list tables for $($rg)/$($ws) in $($sub): $($_)")
      foreach ($row in $g.Group) {
        $summary += [pscustomobject]@{ SubscriptionId=$sub; ResourceGroup=$rg; Workspace=$ws; Table=$row.TablePattern; Plan=$null; AnalyticsRetentionInDays=$null; DataLakeTotalRetentionInDays=$null; Action="Error(GetTables)"; Change=$null }
      }
      continue
    }

    $totalTables  = @($tables).Count
    $matchedNames = New-Object System.Collections.Generic.HashSet[string]
    Write-Info ("Scope has $($totalTables) tables in workspace.")

    foreach ($row in $g.Group) {
      $pattern   = $row.TablePattern
      $planIn    = $row.Plan
      $retHotCsv = [int]$row.AnalyticsRetentionDays
      Write-Step ("Row: Pattern='$($pattern)' PlanIn='$($planIn)' AnalyticsRetentionDays='$($retHotCsv)'")

      # Data Lake: preferred + fallbacks
      $dlStr = $row.DataLakeTotalRetentionInDays
      if ([string]::IsNullOrWhiteSpace($dlStr)) { $dlStr = $row.DataLakeRetentionDays }
      if ([string]::IsNullOrWhiteSpace($dlStr)) { $dlStr = $row.TotalRetentionDays }
      if ([string]::IsNullOrWhiteSpace($dlStr)) {
        Write-Skip ("Missing DataLakeTotalRetentionInDays for pattern '$($pattern)' → Skipping row.")
        $summary += [pscustomobject]@{ SubscriptionId=$sub; ResourceGroup=$rg; Workspace=$ws; Table=$pattern; Plan=$planIn; AnalyticsRetentionInDays=$retHotCsv; DataLakeTotalRetentionInDays=$null; Action="Skipped(DataLakeMissing)"; Change=$null }
        continue
      }
      $retDataLakeCsv = [int]$dlStr
      Write-Info ("CSV targets: Analytics_Shortterm=$($retHotCsv)  DataLake_Longterm=$($retDataLakeCsv)")

      if ($retHotCsv -lt 4 -or $retHotCsv -gt 730) {
        Write-Skip ("AnalyticsRetentionDays '$($retHotCsv)' out-of-range (4..730) → Skipping row.")
        $summary += [pscustomobject]@{ SubscriptionId=$sub; ResourceGroup=$rg; Workspace=$ws; Table=$pattern; Plan=$planIn; AnalyticsRetentionInDays=$retHotCsv; DataLakeTotalRetentionInDays=$retDataLakeCsv; Action="Skipped(HotOutOfRange)"; Change=$null }
        continue
      }
      if ($retDataLakeCsv -lt 0) {
        Write-Skip ("DataLakeTotalRetentionInDays '$($retDataLakeCsv)' invalid (<0) → Skipping row.")
        $summary += [pscustomobject]@{ SubscriptionId=$sub; ResourceGroup=$rg; Workspace=$ws; Table=$pattern; Plan=$planIn; AnalyticsRetentionInDays=$retHotCsv; DataLakeTotalRetentionInDays=$retDataLakeCsv; Action="Skipped(DataLakeInvalid)"; Change=$null }
        continue
      }

      $matches = Match-TablesByPattern -AllTables ([System.Collections.Generic.List[object]]$tables) -Pattern $pattern
      if (-not $matches) {
        Write-Skip ("No tables matched pattern '$($pattern)'.")
        $summary += [pscustomobject]@{ SubscriptionId=$sub; ResourceGroup=$rg; Workspace=$ws; Table=$pattern; Plan=$planIn; AnalyticsRetentionInDays=$retHotCsv; DataLakeTotalRetentionInDays=$retDataLakeCsv; Action="NoMatch"; Change=$null }
        continue
      }

      Write-Info ("Pattern '$($pattern)' matched $(@($matches).Count) tables.")
      foreach ($t in $matches) {
        [void]$matchedNames.Add($t.Name)

        $currentPlan     = $t.Plan
        $currentHot      = [int]$t.RetentionInDays
        $currentDataLake = [int]$t.TotalRetentionInDays

        $isSentinel = Test-IsSentinelTable -Table $t
        $targetHot  = $retHotCsv
        if ($AutoUpgradeSentinelAnalyticsFrom30To90 -and $isSentinel -and $retHotCsv -eq 30) {
          Write-Info ("Auto-upgrade applies: Table '$($t.Name)' is Sentinel and CSV=30 → target 90.")
          $targetHot = 90
        }

        $targetPlan = if ([string]::IsNullOrWhiteSpace($planIn)) { $currentPlan } else { $planIn }

        $needPlanChange     = ($targetPlan -and $targetPlan -ne $currentPlan)
        $needHotChange      = ($targetHot -ne $currentHot)
        $needDataLakeChange = ($retDataLakeCsv -ne $currentDataLake)

        Write-Info ("Table '$($t.Name)' current: Plan=$($currentPlan) Analytics_Shortterm=$($currentHot) DataLake_Longterm=$($currentDataLake); target: Plan=$($targetPlan) Analytics_Shortterm=$($targetHot) DataLake_Longterm=$($retDataLakeCsv)")
        if (-not ($needPlanChange -or $needHotChange -or $needDataLakeChange)) {
          Write-Info ("No change required for '$($t.Name)'.")
          if ($IncludeNoChangeInSummary) {
            $summary += [pscustomobject]@{
              SubscriptionId=$sub; ResourceGroup=$rg; Workspace=$ws; Table=$t.Name; Plan=$currentPlan;
              AnalyticsRetentionInDays=$currentHot; DataLakeTotalRetentionInDays=$currentDataLake;
              Action="NoChange"; Change=$null
            }
          }
          continue
        }

        $changeDesc = @()
        if ($needPlanChange)     { $changeDesc += "Plan: $($currentPlan) -> $($targetPlan)" }
        if ($needHotChange)      { $changeDesc += "Analytics_Shortterm: $($currentHot) -> $($targetHot)" }
        if ($needDataLakeChange) { $changeDesc += "DataLake_Longterm: $($currentDataLake) -> $($retDataLakeCsv)" }
        $changeText = $changeDesc -join '; '
        $msg = "[$($sub)/$($rg)/$($ws)][$($t.Name)] $($changeText)"

        if ($PSCmdlet.ShouldProcess($t.Name, $msg)) {
          try {
            Write-Act ("Updating '$($t.Name)' with: $($changeText)")
            $args = @{ ResourceGroupName=$rg; WorkspaceName=$ws; TableName=$t.Name }
            if ($needPlanChange)     { $args['Plan'] = $targetPlan }
            if ($needHotChange)      { $args['RetentionInDays'] = $targetHot }
            if ($needDataLakeChange) { $args['TotalRetentionInDays'] = $retDataLakeCsv }
            Update-AzOperationalInsightsTable @args | Out-Null
            Write-Done ("Updated '$($t.Name)'.")
            $summary += [pscustomobject]@{
              SubscriptionId=$sub; ResourceGroup=$rg; Workspace=$ws; Table=$t.Name; Plan=$targetPlan;
              AnalyticsRetentionInDays=$targetHot; DataLakeTotalRetentionInDays=$retDataLakeCsv;
              Action="Updated"; Change=$changeText
            }
          } catch {
            Write-Info ("Single-call update failed for '$($t.Name)'. Trying two-step. Error: $($_)")
            $ok = $true
            if ($needPlanChange) {
              try {
                Write-Act ("Updating plan for '$($t.Name)' → $($targetPlan)")
                Update-AzOperationalInsightsTable -ResourceGroupName $rg -WorkspaceName $ws -TableName $t.Name -Plan $targetPlan | Out-Null
              } catch { Write-Err ("Plan update failed for '$($t.Name)': $($_)"); $ok = $false }
            }
            if ($ok -and ($needHotChange -or $needDataLakeChange)) {
              try {
                Write-Act ("Updating retention(s) for '$($t.Name)' (Analytics_Shortterm=$($targetHot) / DataLake_Longterm=$($retDataLakeCsv))")
                $args2 = @{ ResourceGroupName=$rg; WorkspaceName=$ws; TableName=$t.Name }
                if ($needHotChange)      { $args2['RetentionInDays'] = $targetHot }
                if ($needDataLakeChange) { $args2['TotalRetentionInDays'] = $retDataLakeCsv }
                Update-AzOperationalInsightsTable @args2 | Out-Null
              } catch { Write-Err ("Retention update failed for '$($t.Name)': $($_)"); $ok = $false }
            }
            $summary += [pscustomobject]@{
              SubscriptionId=$sub; ResourceGroup=$rg; Workspace=$ws; Table=$t.Name;
              Plan = if ($needPlanChange) { $targetPlan } else { $currentPlan };
              AnalyticsRetentionInDays = if ($needHotChange) { $targetHot } else { $currentHot };
              DataLakeTotalRetentionInDays = if ($needDataLakeChange) { $retDataLakeCsv } else { $currentDataLake };
              Action = if ($ok) { "Updated" } else { "Error" };
              Change = $changeText
            }
          }
        } else {
          Write-Sim ("Would update '$($t.Name)' → $($changeText)")
          $summary += [pscustomobject]@{
            SubscriptionId=$sub; ResourceGroup=$rg; Workspace=$ws; Table=$t.Name; Plan=$targetPlan;
            AnalyticsRetentionInDays=$targetHot; DataLakeTotalRetentionInDays=$retDataLakeCsv;
            Action="WouldUpdate"; Change=$changeText
          }
        }
      }
    }

    # ---- Save coverage info for UNMATCHED header ----
    $matchedCount   = $matchedNames.Count
    $unmatchedItems = $tables | Where-Object { -not $matchedNames.Contains($_.Name) } | Sort-Object Name
    $unmatchedNames = $unmatchedItems | Select-Object -ExpandProperty Name

    Write-Info ("Scope coverage: total=$($totalTables), matched=$($matchedCount), unmatched=$(@($unmatchedNames).Count)")
    $coverage += [pscustomobject]@{
      SubscriptionId = $sub
      ResourceGroup  = $rg
      Workspace      = $ws
      Total          = $totalTables
      Matched        = $matchedCount
      Unmatched      = @($unmatchedNames).Count
      UnmatchedNames = $unmatchedNames
    }
  }

  # ===================== 1) OUT-OF-SCOPE (UNMATCHED) =====================
  Write-Host ""
  Write-Host "Out-of-Scope tables (no match)"
  if ($coverage.Count -eq 0) {
    Write-Host "(no coverage data)"
  } else {
    foreach ($c in ($coverage | Sort-Object SubscriptionId, ResourceGroup, Workspace)) {
      Write-Host ""
      Write-Host ("Workspace: {0}/{1}/{2}  (total={3}, matched={4}, unmatched={5})" -f $c.SubscriptionId, $c.ResourceGroup, $c.Workspace, $c.Total, $c.Matched, $c.Unmatched)
      if ($c.Unmatched -gt 0) {
        Write-Host ("Out-of-Scope tables (no match) ({0}):" -f $c.Unmatched)
        foreach ($n in $c.UnmatchedNames) { Write-Host ("  - {0}" -f $n) }
      } else {
        Write-Host "Out-of-Scope tables (no match): (none)"
      }
    }
  }

  # ===================== 2) IN-SCOPE — SUMMARY (grouped headers) =====================
  $matchedSummary = $summary | Where-Object { $_.Action -in @('Updated','WouldUpdate','NoChange','Error') }
  Write-Host ""
  Write-Host "Retention Setting after Change (in-scope tables)"
  if ($matchedSummary.Count -gt 0) {
    $byWs = $matchedSummary | Group-Object SubscriptionId, ResourceGroup, Workspace
    foreach ($grp in ($byWs | Sort-Object Name)) {
      $sub, $rg, $ws = $grp.Name -split ',\s*'
      Write-Host ""
      Write-Host ("Workspace: {0}/{1}/{2}" -f $sub, $rg, $ws)
      $display = $grp.Group | Select-Object `
        @{n='Table';                e={ Shorten $_.'Table' $MaxTable }}, `
        @{n='Plan';                 e={ $_.'Plan' }}, `
        @{n='Analytics_Shortterm';  e={ $_.'AnalyticsRetentionInDays' }}, `
        @{n='DataLake_Longterm';    e={ $_.'DataLakeTotalRetentionInDays' }}, `
        @{n='Action';               e={ $_.'Action' }}
      $out = $display | Sort-Object Action, Table | Format-Table -AutoSize | Out-String -Width 4096
      Write-Host $out
    }
  } else {
    Write-Host "(no matched table entries)"
  }

  # ===================== 3) IN-SCOPE — WHATIF/CHANGES (grouped headers) =====================
  $changesOnly = $summary | Where-Object { $_.Action -in @('Updated','WouldUpdate') } | Sort-Object Workspace, Table
  Write-Host ""
  Write-Host "Retention Setting WhatIf Changes (in-scope tables)"
  if ($changesOnly.Count -gt 0) {
    $byWs2 = $changesOnly | Group-Object SubscriptionId, ResourceGroup, Workspace
    foreach ($grp in ($byWs2 | Sort-Object Name)) {
      $sub, $rg, $ws = $grp.Name -split ',\s*'
      Write-Host ""
      Write-Host ("Workspace: {0}/{1}/{2}" -f $sub, $rg, $ws)
      foreach ($row in ($grp.Group | Sort-Object Table)) {
        Write-Host ("  - [{0}] {1}" -f $row.Table, $row.Change)
      }
    }
  } else {
    Write-Host "(no changes to report)"
  }

  # ===================== FINAL COUNTS =====================
  $applied  = ($summary | Where-Object { $_.Action -eq 'Updated' }).Count
  $planned  = ($summary | Where-Object { $_.Action -eq 'WouldUpdate' }).Count
  $nochange = ($summary | Where-Object { $_.Action -eq 'NoChange' }).Count
  $skipped  = ($summary | Where-Object { $_.Action -like 'Skipped*' }).Count
  $nomatch  = ($summary | Where-Object { $_.Action -eq 'NoMatch' }).Count
  $errors   = ($summary | Where-Object { $_.Action -eq 'Error' }).Count

  $notChangedStrict  = $nochange
  $notChangedOverall = $nochange + $skipped + $nomatch

  Write-Host ""
  Write-Host "===== TOTALS ====="
  Write-Host ("  Changed (applied):            {0}" -f $applied)
  Write-Host ("  Changes planned (WhatIf):     {0}" -f $planned)
  Write-Host ("  Not changed:                  {0}" -f $notChangedStrict)
  Write-Host ("  Not changed (overall):        {0}   [Skipped={1}, NoMatch={2}]" -f $notChangedOverall, $skipped, $nomatch)
  Write-Host ("  Errors:                       {0}" -f $errors)

  # -------- CSV export --------
  if ($DefaultSummaryCsvPath) {
    $ts = Get-Date -Format 'yyyyMMdd_HHmmss'
    $csvOut = $DefaultSummaryCsvPath -replace '\{date\}', $ts
    try {
      Write-Step ("Exporting summary CSV to '$($csvOut)'")
      $summary | Export-Csv -Path $csvOut -NoTypeInformation -Encoding UTF8
      Write-Done ("Summary CSV: $csvOut")
    } catch {
      Write-Err ("Failed to export summary CSV to $($csvOut): $($_)")
    }
  }

  if ($EnableOutGridView -and $env:OS -like '*Windows*') {
    try { $matchedSummary | Out-GridView -Title "Retention Setting after Change (in-scope tables)" }
    catch { Write-Err ("Out-GridView failed (non-interactive session?): $($_)") }
  }

  Write-Done ("Set-SentinelDataLakeRetentions completed.")
}

# --------- RUN WITH STATIC DEFAULTS (params are optional) ---------
try {
  Ensure-Module -Name Az.Accounts
  Ensure-Module -Name Az.OperationalInsights
} catch {
  Write-Err ("Preloading Az modules failed: $($_)")
}
Set-SentinelDataLakeRetentions -CsvPath $DefaultCsvPath -TenantId $DefaultTenantId -WhatIf:$DefaultWhatIf
