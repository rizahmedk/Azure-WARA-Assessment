# =============================================================================
# Run-WARA-Assessment.ps1
# Well-Architected Reliability Assessment (WARA) - PowerShell Module Approach
# Uses the official WARA module from PowerShell Gallery (Install-Module WARA)
# Cross-platform: Windows / Linux / macOS (PowerShell 7+)
# Compatible with any Azure tenant / company
# =============================================================================

[CmdletBinding()]
param (
    # Optional: Specific subscription IDs. Leave empty to auto-discover ALL.
    [string[]]$SubscriptionIds = @(),

    # Optional: Filter by Management Group (recursive sub discovery)
    [string]$ManagementGroupId = "",

    # Optional: Filter to specific Azure regions
    [string[]]$Regions = @(),

    # Output folder for JSON and Excel files
    [string]$OutputDirectory = "",

    # Skip the report step (requires Word/PowerPoint — Windows only)
    [switch]$SkipReport,

    # Tenant ID (auto-detected from current login if omitted)
    [string]$TenantId = "",

    # Skip collector and use an existing JSON file directly (re-run analyzer only)
    [string]$UseExistingJSON = ""
)

# =============================================================================
# CROSS-PLATFORM OUTPUT PATH
# =============================================================================
$homeDir = if ($env:HOME) { $env:HOME } else { $env:USERPROFILE }
if ([string]::IsNullOrEmpty($OutputDirectory)) {
    $OutputDirectory = Join-Path $homeDir "WARA-Output"
}

# =============================================================================
# BANNER
# =============================================================================
Write-Host ""
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "  Azure Well-Architected Reliability Assessment (WARA) Runner   " -ForegroundColor Cyan
Write-Host "  PowerShell Module Edition — Cross-Platform                    " -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "  Output path : $OutputDirectory" -ForegroundColor DarkGray
Write-Host ""

# =============================================================================
# STEP 0 — INSTALL / IMPORT REQUIRED MODULES
# =============================================================================
Write-Host "[STEP 0] Installing required modules..." -ForegroundColor Yellow

# Az.Accounts
if (-not (Get-Module -ListAvailable -Name Az.Accounts)) {
    Write-Host "  Installing Az.Accounts..." -ForegroundColor Cyan
    Install-Module Az.Accounts -Scope CurrentUser -Force -AllowClobber
}

# Az.ResourceGraph — WARA requires a specific version; uninstall conflicting first
$rgMod = Get-Module -ListAvailable -Name Az.ResourceGraph | Sort-Object Version -Descending | Select-Object -First 1
if ($rgMod) {
    Write-Host "  Found Az.ResourceGraph $($rgMod.Version). WARA requires >= 1.0.0." -ForegroundColor DarkGray
    if ($rgMod.Version -lt [version]"1.0.0") {
        Write-Host "  Uninstalling old Az.ResourceGraph and reinstalling..." -ForegroundColor Yellow
        Uninstall-Module Az.ResourceGraph -AllVersions -Force
        Install-Module Az.ResourceGraph -Scope CurrentUser -Force
    }
} else {
    Write-Host "  Installing Az.ResourceGraph..." -ForegroundColor Cyan
    Install-Module Az.ResourceGraph -Scope CurrentUser -Force
}

# WARA module from PowerShell Gallery
if (-not (Get-Module -ListAvailable -Name WARA)) {
    Write-Host "  Installing WARA module from PSGallery..." -ForegroundColor Cyan
    Install-Module WARA -Scope CurrentUser -Force
} else {
    $waraVer = (Get-Module -ListAvailable -Name WARA | Sort-Object Version -Descending | Select-Object -First 1).Version
    Write-Host "  [OK] WARA module v$waraVer found." -ForegroundColor Green
    # Update to latest
    Write-Host "  Checking for updates..." -ForegroundColor DarkGray
    Update-Module WARA -Force -ErrorAction SilentlyContinue
}

# Import the module
Import-Module WARA -Force
Write-Host "  [OK] All modules ready." -ForegroundColor Green

# =============================================================================
# STEP 1 — AUTHENTICATE TO AZURE
# =============================================================================
Write-Host ""
Write-Host "[STEP 1] Authenticating to Azure..." -ForegroundColor Yellow

$currentContext = Get-AzContext -ErrorAction SilentlyContinue

if (-not $currentContext) {
    Write-Host "  No active session. Launching device-code login..." -ForegroundColor Yellow
    if ($TenantId) {
        Connect-AzAccount -UseDeviceAuthentication -TenantId $TenantId | Out-Null
    } else {
        Connect-AzAccount -UseDeviceAuthentication | Out-Null
    }
    $currentContext = Get-AzContext
}

$resolvedTenantId = $currentContext.Tenant.Id
$currentAccount   = $currentContext.Account.Id

Write-Host "  [OK] Logged in as : $currentAccount" -ForegroundColor Green
Write-Host "  [OK] Tenant ID    : $resolvedTenantId" -ForegroundColor Green

# =============================================================================
# STEP 2 — DISCOVER SUBSCRIPTIONS
# =============================================================================
Write-Host ""
Write-Host "[STEP 2] Discovering subscriptions..." -ForegroundColor Yellow

function Get-SubsFromMG {
    param ([string]$GroupName)
    $collected = @()
    try {
        $mg = Get-AzManagementGroup -GroupName $GroupName -Expand -Recurse -ErrorAction Stop
        foreach ($child in $mg.Children) {
            if ($child.Type -eq "Microsoft.Management/managementGroups") {
                $collected += Get-SubsFromMG -GroupName $child.Name
            } elseif ($child.Type -eq "/subscriptions") {
                $collected += "/subscriptions/$($child.Name)"
            }
        }
    } catch {
        Write-Host "  [WARN] Could not expand MG '$GroupName': $_" -ForegroundColor Yellow
    }
    return $collected
}

if ($SubscriptionIds.Count -gt 0) {
    # Ensure format is /subscriptions/<guid>
    $resolvedSubIds = $SubscriptionIds | ForEach-Object {
        if ($_ -notmatch "^/subscriptions/") { "/subscriptions/$_" } else { $_ }
    }
    Write-Host "  Using $($resolvedSubIds.Count) provided subscription IDs." -ForegroundColor Cyan

} elseif ($ManagementGroupId) {
    Write-Host "  Querying Management Group: $ManagementGroupId (recursive)" -ForegroundColor Cyan
    $resolvedSubIds = Get-SubsFromMG -GroupName $ManagementGroupId

    if ($resolvedSubIds.Count -eq 0) {
        Write-Host "  MG walk returned 0 — falling back to Get-AzSubscription..." -ForegroundColor Yellow
        $resolvedSubIds = (Get-AzSubscription -TenantId $resolvedTenantId |
            Where-Object { $_.State -eq "Enabled" }) |
            ForEach-Object { "/subscriptions/$($_.Id)" }
        Write-Host "  Fallback found $($resolvedSubIds.Count) subscriptions." -ForegroundColor Cyan
    } else {
        Write-Host "  Found $($resolvedSubIds.Count) subscriptions under MG '$ManagementGroupId'." -ForegroundColor Green
    }

} else {
    Write-Host "  Discovering ALL enabled subscriptions in tenant..." -ForegroundColor Cyan
    $resolvedSubIds = (Get-AzSubscription -TenantId $resolvedTenantId |
        Where-Object { $_.State -eq "Enabled" }) |
        ForEach-Object { "/subscriptions/$($_.Id)" }
    Write-Host "  Found $($resolvedSubIds.Count) subscriptions." -ForegroundColor Green
}

if ($resolvedSubIds.Count -eq 0) {
    Write-Host "  [ERROR] No subscriptions found. Check permissions (Reader role required)." -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "  Subscriptions to assess:" -ForegroundColor White
$resolvedSubIds | ForEach-Object { Write-Host "    - $_" -ForegroundColor Gray }

# =============================================================================
# STEP 3 — CREATE OUTPUT DIRECTORY
# =============================================================================
Write-Host ""
Write-Host "[STEP 3] Preparing output directory..." -ForegroundColor Yellow

if (-not (Test-Path $OutputDirectory)) {
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
}

$timestamp    = Get-Date -Format "yyyyMMdd-HHmm"
$runOutputDir = Join-Path $OutputDirectory "WARA-Run-$timestamp"
New-Item -ItemType Directory -Path $runOutputDir -Force | Out-Null

Write-Host "  [OK] Output: $runOutputDir" -ForegroundColor Green

# Change to output directory so WARA writes files here
Push-Location $runOutputDir
Write-Host "  Working directory set to: $(Get-Location)" -ForegroundColor DarkGray

# =============================================================================
# STEP 4 — RUN WARA COLLECTOR (or use existing JSON)
# =============================================================================
Write-Host ""

# If caller passed an existing JSON, skip the collector entirely
if (-not [string]::IsNullOrEmpty($UseExistingJSON)) {
    if (-not (Test-Path $UseExistingJSON)) {
        Write-Host "  [ERROR] Provided JSON file not found: $UseExistingJSON" -ForegroundColor Red
        Pop-Location
        exit 1
    }
    $jsonFile = Get-Item $UseExistingJSON
    Write-Host "[STEP 4] Skipping collector — using existing JSON:" -ForegroundColor Yellow
    Write-Host "  $($jsonFile.FullName)  [$([math]::Round($jsonFile.Length/1KB,1)) KB]" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Press ENTER to run the Analyzer and generate the Excel report..." -ForegroundColor Cyan
    Write-Host "  (or Ctrl+C to cancel)" -ForegroundColor DarkGray
    $null = Read-Host
} else {

Write-Host "[STEP 4] Running WARA Collector (Start-WARACollector)..." -ForegroundColor Yellow
Write-Host "  Queries Azure Resource Graph across $($resolvedSubIds.Count) subscriptions." -ForegroundColor Gray
Write-Host "  Estimated runtime: 5-20 minutes depending on estate size." -ForegroundColor Gray
Write-Host ""

$collectorParams = @{
    TenantID        = $resolvedTenantId
    SubscriptionIds = $resolvedSubIds
}

if ($Regions.Count -gt 0) {
    $collectorParams["Regions"] = $Regions
    Write-Host "  Region filter: $($Regions -join ', ')" -ForegroundColor Cyan
}

$startTime = Get-Date

try {
    Start-WARACollector @collectorParams
    $elapsed = [math]::Round(((Get-Date) - $startTime).TotalMinutes, 1)
    Write-Host ""
    Write-Host "  [OK] Collector finished in $elapsed minutes." -ForegroundColor Green
} catch {
    Write-Host "  [ERROR] Collector failed: $_" -ForegroundColor Red
    Pop-Location
    exit 1
}

# Move any WARA files written to cwd into the run output dir (WARA always writes to cwd)
Get-ChildItem -Path (Get-Location) -Filter "WARA*.json" | ForEach-Object {
    if ($_.DirectoryName -ne $runOutputDir) {
        Move-Item $_.FullName -Destination $runOutputDir -Force
        Write-Host "  Moved $($_.Name) → $runOutputDir" -ForegroundColor DarkGray
    }
}

# Find the JSON output
# Start-WARACollector writes to the PWD at launch time, not necessarily $runOutputDir
# Search: runOutputDir, home dir, and the script's invocation directory
$searchPaths = @(
    $runOutputDir,
    $homeDir,
    $PSScriptRoot,
    (Get-Location).Path
) | Select-Object -Unique

$jsonFile = $null
foreach ($searchPath in $searchPaths) {
    if (Test-Path $searchPath) {
        $jsonFile = Get-ChildItem -Path $searchPath -Filter "WARA*.json" -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($jsonFile) {
            Write-Host "  Found JSON in: $searchPath" -ForegroundColor DarkGray
            break
        }
    }
}

# Last resort: find most recent WARA JSON anywhere under home
if (-not $jsonFile) {
    Write-Host "  Searching for WARA JSON under $homeDir ..." -ForegroundColor Yellow
    $jsonFile = Get-ChildItem -Path $homeDir -Filter "WARA*.json" -Recurse -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
}

if (-not $jsonFile) {
    Write-Host "  [ERROR] No WARA JSON output found. Collector may have failed silently." -ForegroundColor Red
    Pop-Location
    exit 1
}

# Move the JSON into runOutputDir for tidy output (if it's not already there)
if ($jsonFile.DirectoryName -ne $runOutputDir) {
    Copy-Item $jsonFile.FullName -Destination $runOutputDir
    $jsonFile = Get-Item (Join-Path $runOutputDir $jsonFile.Name)
    Write-Host "  Moved JSON to output directory." -ForegroundColor DarkGray
}

Write-Host ""
Write-Host "  ✔  JSON file located:" -ForegroundColor Green
Write-Host "     $($jsonFile.FullName)" -ForegroundColor White
Write-Host "     Size: $([math]::Round($jsonFile.Length/1KB,1)) KB" -ForegroundColor DarkGray
Write-Host ""

# Confirm before proceeding to analyzer
Write-Host "  Press ENTER to run the Analyzer and generate the Excel report..." -ForegroundColor Cyan
Write-Host "  (or Ctrl+C to stop here and use the JSON manually)" -ForegroundColor DarkGray
$null = Read-Host

} # end if UseExistingJSON else block

# =============================================================================
# STEP 5 — RUN WARA ANALYZER (generates Excel Action Plan)
# =============================================================================
Write-Host ""
Write-Host "[STEP 5] Running WARA Analyzer (Start-WARAAnalyzer)..." -ForegroundColor Yellow
Write-Host "  Input : $($jsonFile.FullName)" -ForegroundColor DarkGray
Write-Host "  Output: Excel Action Plan → $runOutputDir" -ForegroundColor DarkGray
Write-Host "  This generates the Excel Action Plan (your primary deliverable)." -ForegroundColor Gray

try {
    Start-WARAAnalyzer -JSONFile $jsonFile.FullName
    Write-Host "  [OK] Analyzer complete." -ForegroundColor Green
} catch {
    Write-Host "  [ERROR] Analyzer failed: $_" -ForegroundColor Red
    Write-Host "  JSON still available: $($jsonFile.FullName)" -ForegroundColor Yellow
}

# Move Excel into runOutputDir and print exact path
Get-ChildItem -Path (Get-Location) -Filter "Expert-Analysis*.xlsx" | ForEach-Object {
    if ($_.DirectoryName -ne $runOutputDir) {
        Move-Item $_.FullName -Destination $runOutputDir -Force
    }
}
$excelResult = Get-ChildItem -Path $runOutputDir -Filter "Expert-Analysis*.xlsx" |
    Sort-Object LastWriteTime -Descending | Select-Object -First 1
if ($excelResult) {
    Write-Host ""
    Write-Host "  ✔  Excel Action Plan ready:" -ForegroundColor Green
    Write-Host "     $($excelResult.FullName)" -ForegroundColor White
    Write-Host "     Size: $([math]::Round($excelResult.Length/1KB,1)) KB" -ForegroundColor DarkGray
}

# =============================================================================
# STEP 6 — RUN WARA REPORT GENERATOR (Word/PPT — Windows only)
# =============================================================================
if (-not $SkipReport) {
    $excelFile = $null
    foreach ($searchPath in $searchPaths) {
        if (Test-Path $searchPath) {
            $excelFile = Get-ChildItem -Path $searchPath -Filter "Expert-Analysis*.xlsx" -ErrorAction SilentlyContinue |
                Sort-Object LastWriteTime -Descending | Select-Object -First 1
            if ($excelFile) { break }
        }
    }
    if (-not $excelFile) {
        $excelFile = Get-ChildItem -Path $homeDir -Filter "Expert-Analysis*.xlsx" -Recurse -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending | Select-Object -First 1
    }
    # Move into runOutputDir if needed
    if ($excelFile -and $excelFile.DirectoryName -ne $runOutputDir) {
        Copy-Item $excelFile.FullName -Destination $runOutputDir
        $excelFile = Get-Item (Join-Path $runOutputDir $excelFile.Name)
    }

    if ($excelFile) {
        Write-Host ""
        Write-Host "[STEP 6] Running WARA Report Generator (Start-WARAReport)..." -ForegroundColor Yellow
        Write-Host "  Note: Requires Microsoft Word/PowerPoint. Skipped on Linux automatically." -ForegroundColor DarkGray
        try {
            Start-WARAReport -ExpertAnalysisFile $excelFile.FullName
            Write-Host "  [OK] Word/PPT report generated." -ForegroundColor Green
        } catch {
            Write-Host "  [WARN] Report generator skipped (requires Word/PPT on Windows): $_" -ForegroundColor Yellow
            Write-Host "  Your Excel Action Plan is the primary deliverable on Linux." -ForegroundColor Cyan
        }
    } else {
        Write-Host ""
        Write-Host "[STEP 6] No Expert-Analysis Excel found — skipping report step." -ForegroundColor Yellow
    }
} else {
    Write-Host ""
    Write-Host "[STEP 6] Report generation skipped (-SkipReport)." -ForegroundColor Gray
}

Pop-Location

# =============================================================================
# STEP 7 — SUMMARY
# =============================================================================
Write-Host ""
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "  WARA Assessment Complete!" -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Output Directory : $runOutputDir" -ForegroundColor Green
Write-Host "  Tenant           : $resolvedTenantId" -ForegroundColor Green
Write-Host "  Subscriptions    : $($resolvedSubIds.Count)" -ForegroundColor Green
Write-Host "  Completed At     : $(Get-Date -Format 'yyyy-MM-dd HH:mm')" -ForegroundColor Green
Write-Host ""

$outputFiles = Get-ChildItem -Path $runOutputDir -ErrorAction SilentlyContinue
if ($outputFiles) {
    Write-Host "  Output Files:" -ForegroundColor White
    $outputFiles | ForEach-Object {
        Write-Host "    $($_.Name)  [$([math]::Round($_.Length/1KB, 1)) KB]" -ForegroundColor Gray
    }
}

Write-Host ""
Write-Host "  Open the Excel file to review your findings." -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host ""

<#
USAGE EXAMPLES
--------------

Full tenant sweep (all subscriptions):
  ./Run-WARA-Assessment.ps1

By Management Group (recursive):
  ./Run-WARA-Assessment.ps1 -ManagementGroupId "jpshealthdc"

Specific subscriptions only:
  ./Run-WARA-Assessment.ps1 -SubscriptionIds "sub-id-1","sub-id-2"

Filter by region:
  ./Run-WARA-Assessment.ps1 -ManagementGroupId "jpshealthdc" -Regions "southcentralus","eastus"

Custom output path:
  ./Run-WARA-Assessment.ps1 -ManagementGroupId "jpshealthdc" -OutputDirectory "/home/riyaz_hussain/reports/contoso"

Skip Word/PPT report (Excel only — recommended on Linux):
  ./Run-WARA-Assessment.ps1 -ManagementGroupId "jpshealthdc" -SkipReport

Re-run analyzer only using existing JSON (skip collector):
  ./Run-WARA-Assessment.ps1 -UseExistingJSON "/home/riyaz_hussain/WARA-File-2026-07-28-21-25.json" -SkipReport

REQUIRED PERMISSIONS
--------------------
  Reader on each subscription (minimum)
  Management Group Reader if using -ManagementGroupId

OUTPUT FILES (in ~/WARA-Output/WARA-Run-<timestamp>/)
-------------------------------------------------------
  WARA_File_<date>.json           Raw collector data
  Expert-Analysis-<date>.xlsx     Excel Action Plan (primary deliverable)
  Assessment Report.docx          Word report (Windows/PPT only)
  Executive Summary.pptx          PowerPoint (Windows only)
#>
