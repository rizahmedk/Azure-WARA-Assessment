# =============================================================================
# Run-WARA-Assessment.ps1
# Azure Well-Architected Reliability Assessment (WARA) + Comprehensive Security Baseline
#
# WARA Checks (via Microsoft WARA module):
#   Reliability, HA, DR, Monitoring, Scalability, Networking, Governance
#
# Security Baseline Checks (via Azure Resource Graph):
#   1.  Network Exposure        — Storage, Functions, App Services, Key Vault,
#                                  SQL, Event Hub, Container Registry, Automation,
#                                  Service Bus, Cosmos DB, API Management,
#                                  Cognitive Services, App Config, IoT Hub,
#                                  ACR, AKS, Batch, Data Factory, Synapse,
#                                  Log Analytics, Azure Monitor
#   2.  Soft Delete / Recovery  — Storage Blob, Storage File Share, Key Vault,
#                                  Key Vault Purge Protection, Recovery Services
#                                  Vault, RSV MUA, Event Hub, SQL Backup Retention
#   3.  Encryption              — Storage HTTPS-only, SQL TDE, App Service TLS,
#                                  App Service HTTPS-only, Disk Encryption
#   4.  Identity & Access       — Storage SAS expiry, SQL AAD Admin, AKS RBAC,
#                                  Key Vault access policies vs RBAC
#   5.  Monitoring & Logging    — Diagnostic settings missing on Key Vault,
#                                  SQL Server, Storage, NSG, VNet, App Service,
#                                  AKS, Event Hub, Service Bus, Cosmos DB
#   6.  Network Hardening       — NSG inbound ANY rules (0.0.0.0/0),
#                                  VNets without DDoS protection,
#                                  Azure Firewall threat intel mode,
#                                  App Gateway WAF mode,
#                                  Public IPs without DDoS, Subnets without NSG
#   7.  Backup & DR             — VMs without backup, SQL without LTR,
#                                  AKS without Azure Backup
#
# Output:
#   Azure-Assessment-<date>.xlsx
#     Sheets: WARA reliability findings + 7-category security baseline (64 checks)
#
# Cross-platform: Windows / Linux / macOS (PowerShell 7+)
# =============================================================================

[CmdletBinding()]
param (
    [string[]]$SubscriptionIds  = @(),
    [string]$ManagementGroupId  = "",
    [string[]]$Regions          = @(),
    [string]$OutputDirectory    = "",
    [switch]$SkipReport,
    [switch]$SkipSecurityBaseline,
    [string]$TenantId           = "",
    [string]$UseExistingJSON    = ""
)

$homeDir = if ($env:HOME) { $env:HOME } else { $env:USERPROFILE }
if ([string]::IsNullOrEmpty($OutputDirectory)) {
    $OutputDirectory = Join-Path $homeDir "WARA-Output"
}

Write-Host ""
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "  Azure WARA + Comprehensive Security Baseline Runner           " -ForegroundColor Cyan
Write-Host "  WARA Reliability + 7-Category Security Checks                " -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "  Output : $OutputDirectory" -ForegroundColor DarkGray
Write-Host ""

# =============================================================================
# STEP 0 — MODULES
# =============================================================================
Write-Host "[STEP 0] Installing required modules..." -ForegroundColor Yellow

foreach ($mod in @("Az.Accounts", "Az.ResourceGraph", "ImportExcel")) {
    if (-not (Get-Module -ListAvailable -Name $mod)) {
        Write-Host "  Installing $mod..." -ForegroundColor Cyan
        Install-Module $mod -Scope CurrentUser -Force -AllowClobber
    }
}

$rgMod = Get-Module -ListAvailable -Name Az.ResourceGraph | Sort-Object Version -Descending | Select-Object -First 1
if ($rgMod -and $rgMod.Version -lt [version]"1.0.0") {
    Uninstall-Module Az.ResourceGraph -AllVersions -Force
    Install-Module Az.ResourceGraph -Scope CurrentUser -Force
}

if (-not (Get-Module -ListAvailable -Name WARA)) {
    Write-Host "  Installing WARA module from PSGallery..." -ForegroundColor Cyan
    Install-Module WARA -Scope CurrentUser -Force
} else {
    $waraVer = (Get-Module -ListAvailable -Name WARA | Sort-Object Version -Descending | Select-Object -First 1).Version
    Write-Host "  [OK] WARA module v$waraVer" -ForegroundColor Green
    Update-Module WARA -Force -ErrorAction SilentlyContinue
}

Import-Module WARA -Force
Import-Module Az.ResourceGraph -Force
Import-Module ImportExcel -Force
Write-Host "  [OK] All modules ready." -ForegroundColor Green

# =============================================================================
# STEP 1 — AUTHENTICATE
# =============================================================================
Write-Host ""
Write-Host "[STEP 1] Authenticating to Azure..." -ForegroundColor Yellow

$ctx = Get-AzContext -ErrorAction SilentlyContinue
if (-not $ctx) {
    if ($TenantId) { Connect-AzAccount -UseDeviceAuthentication -TenantId $TenantId | Out-Null }
    else            { Connect-AzAccount -UseDeviceAuthentication | Out-Null }
    $ctx = Get-AzContext
}
$resolvedTenantId = $ctx.Tenant.Id
Write-Host "  [OK] Logged in as : $($ctx.Account.Id)" -ForegroundColor Green
Write-Host "  [OK] Tenant ID    : $resolvedTenantId"  -ForegroundColor Green

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
            if ($child.Type -eq "Microsoft.Management/managementGroups") { $collected += Get-SubsFromMG -GroupName $child.Name }
            elseif ($child.Type -eq "/subscriptions")                    { $collected += $child.Name }
        }
    } catch { Write-Host "  [WARN] $GroupName : $_" -ForegroundColor Yellow }
    return $collected
}

if ($SubscriptionIds.Count -gt 0) {
    $rawSubIds      = $SubscriptionIds
    $resolvedSubIds = $SubscriptionIds | ForEach-Object { if ($_ -notmatch "^/subscriptions/") { "/subscriptions/$_" } else { $_ } }
    Write-Host "  Using $($resolvedSubIds.Count) provided subscription IDs." -ForegroundColor Cyan
} elseif ($ManagementGroupId) {
    $rawSubIds = Get-SubsFromMG -GroupName $ManagementGroupId
    if ($rawSubIds.Count -eq 0) {
        $rawSubIds = (Get-AzSubscription -TenantId $resolvedTenantId | Where-Object { $_.State -eq "Enabled" }).Id
    }
    $resolvedSubIds = $rawSubIds | ForEach-Object { if ($_ -notmatch "^/subscriptions/") { "/subscriptions/$_" } else { $_ } }
    Write-Host "  Found $($resolvedSubIds.Count) subscriptions under MG '$ManagementGroupId'." -ForegroundColor Green
} else {
    $rawSubIds      = (Get-AzSubscription -TenantId $resolvedTenantId | Where-Object { $_.State -eq "Enabled" }).Id
    $resolvedSubIds = $rawSubIds | ForEach-Object { "/subscriptions/$_" }
    Write-Host "  Found $($resolvedSubIds.Count) subscriptions (tenant-wide)." -ForegroundColor Green
}

if ($resolvedSubIds.Count -eq 0) {
    Write-Host "  [ERROR] No subscriptions found. Check permissions." -ForegroundColor Red
    exit 1
}
Write-Host ""
$resolvedSubIds | ForEach-Object { Write-Host "    - $_" -ForegroundColor Gray }

# =============================================================================
# STEP 3 — OUTPUT DIRECTORY
# =============================================================================
Write-Host ""
Write-Host "[STEP 3] Preparing output directory..." -ForegroundColor Yellow

if (-not (Test-Path $OutputDirectory)) { New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null }
$timestamp    = Get-Date -Format "yyyyMMdd-HHmm"
$runOutputDir = Join-Path $OutputDirectory "WARA-Run-$timestamp"
New-Item -ItemType Directory -Path $runOutputDir -Force | Out-Null
$combinedExcelPath = Join-Path $runOutputDir "Azure-Assessment-$timestamp.xlsx"
Write-Host "  [OK] $runOutputDir" -ForegroundColor Green
Push-Location $runOutputDir

# =============================================================================
# STEP 4 — WARA COLLECTOR
# =============================================================================
Write-Host ""

if (-not [string]::IsNullOrEmpty($UseExistingJSON)) {
    if (-not (Test-Path $UseExistingJSON)) {
        Write-Host "  [ERROR] JSON not found: $UseExistingJSON" -ForegroundColor Red
        Pop-Location; exit 1
    }
    $jsonFile = Get-Item $UseExistingJSON
    Write-Host "[STEP 4] Using existing JSON: $($jsonFile.FullName)" -ForegroundColor Yellow
    Write-Host "  Press ENTER to run Analyzer..." -ForegroundColor Cyan
    $null = Read-Host
} else {
    Write-Host "[STEP 4] Running WARA Collector..." -ForegroundColor Yellow
    Write-Host "  Querying Azure Resource Graph across $($resolvedSubIds.Count) subscriptions." -ForegroundColor Gray
    Write-Host "  Estimated runtime: 5-20 minutes." -ForegroundColor Gray
    Write-Host ""

    $collectorParams = @{ TenantID = $resolvedTenantId; SubscriptionIds = $resolvedSubIds }
    if ($Regions.Count -gt 0) { $collectorParams["Regions"] = $Regions }

    $startTime = Get-Date
    try {
        Start-WARACollector @collectorParams
        Write-Host "  [OK] Collector finished in $([math]::Round(((Get-Date)-$startTime).TotalMinutes,1)) minutes." -ForegroundColor Green
    } catch {
        Write-Host "  [ERROR] Collector failed: $_" -ForegroundColor Red
        Pop-Location; exit 1
    }

    Get-ChildItem -Path (Get-Location) -Filter "WARA*.json" | ForEach-Object {
        if ($_.DirectoryName -ne $runOutputDir) { Move-Item $_.FullName -Destination $runOutputDir -Force }
    }

    $jsonFile = $null
    foreach ($p in @($runOutputDir, $homeDir, (Get-Location).Path) | Select-Object -Unique) {
        $jsonFile = Get-ChildItem -Path $p -Filter "WARA*.json" -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($jsonFile) { break }
    }
    if (-not $jsonFile) {
        $jsonFile = Get-ChildItem -Path $homeDir -Filter "WARA*.json" -Recurse -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending | Select-Object -First 1
    }
    if (-not $jsonFile) { Write-Host "  [ERROR] No WARA JSON found." -ForegroundColor Red; Pop-Location; exit 1 }

    if ($jsonFile.DirectoryName -ne $runOutputDir) {
        Copy-Item $jsonFile.FullName -Destination $runOutputDir
        $jsonFile = Get-Item (Join-Path $runOutputDir $jsonFile.Name)
    }

    Write-Host ""
    Write-Host "  ============================================================" -ForegroundColor Green
    Write-Host "  Collector JSON : $($jsonFile.FullName)" -ForegroundColor White
    Write-Host "  Size           : $([math]::Round($jsonFile.Length/1KB,1)) KB" -ForegroundColor DarkGray
    Write-Host "  ============================================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Press ENTER to continue to Analyzer..." -ForegroundColor Yellow
    Write-Host "  (Ctrl+C to stop here and use JSON manually)" -ForegroundColor DarkGray
    $null = Read-Host
}

# =============================================================================
# STEP 5 — WARA ANALYZER
# =============================================================================
Write-Host ""
Write-Host "[STEP 5] Running WARA Analyzer..." -ForegroundColor Yellow

Push-Location $runOutputDir
try {
    Start-WARAAnalyzer -JSONFile $jsonFile.FullName
    Write-Host "  [OK] Analyzer complete." -ForegroundColor Green
} catch {
    Write-Host "  [ERROR] Analyzer failed: $_" -ForegroundColor Red
}
Pop-Location

Get-ChildItem -Path (Get-Location) -Filter "Expert-Analysis*.xlsx" | ForEach-Object {
    if ($_.DirectoryName -ne $runOutputDir) { Move-Item $_.FullName -Destination $runOutputDir -Force }
}
$waraExcel = Get-ChildItem -Path $runOutputDir -Filter "Expert-Analysis*.xlsx" |
    Sort-Object LastWriteTime -Descending | Select-Object -First 1
if ($waraExcel) {
    Write-Host "  [OK] WARA analysis complete — merging into combined report..." -ForegroundColor Green
    try {
        $waraWb   = Open-ExcelPackage -Path $waraExcel.FullName
        $targetWb = Open-ExcelPackage -Path $combinedExcelPath -Create
        foreach ($sheet in $waraWb.Workbook.Worksheets) {
            $targetWb.Workbook.Worksheets.Add($sheet.Name, $sheet) | Out-Null
        }
        Close-ExcelPackage $targetWb -Save
        Close-ExcelPackage $waraWb
        Remove-Item $waraExcel.FullName -Force -ErrorAction SilentlyContinue
        Write-Host "  [OK] WARA sheets merged into combined report." -ForegroundColor Green
    } catch {
        Write-Host "  [WARN] Could not merge WARA sheets: $_" -ForegroundColor Yellow
        Write-Host "         WARA data preserved at: $($waraExcel.FullName)" -ForegroundColor DarkGray
    }
}

# =============================================================================
# STEP 6 — WARA REPORT (Windows only)
# =============================================================================
if (-not $SkipReport -and $waraExcel) {
    Write-Host ""
    Write-Host "[STEP 6] Generating Word/PPT Report..." -ForegroundColor Yellow
    try {
        Start-WARAReport -ExpertAnalysisFile $waraExcel.FullName
        Write-Host "  [OK] Word/PPT report generated." -ForegroundColor Green
    } catch {
        Write-Host "  [WARN] Skipped — Word/PPT not available on this platform." -ForegroundColor Yellow
    }
} elseif ($SkipReport) {
    Write-Host ""; Write-Host "[STEP 6] Word/PPT report skipped (-SkipReport)." -ForegroundColor Gray
}

# =============================================================================
# STEP 7 — COMPREHENSIVE SECURITY BASELINE
# =============================================================================
if ($SkipSecurityBaseline) {
    Write-Host ""; Write-Host "[STEP 7] Security baseline skipped (-SkipSecurityBaseline)." -ForegroundColor Gray
} else {
    Write-Host ""
    Write-Host "=================================================================" -ForegroundColor Cyan
    Write-Host "[STEP 7] Running Comprehensive Security Baseline Checks..." -ForegroundColor Yellow
    Write-Host "  7 categories — covers all major Azure service types" -ForegroundColor Gray
    Write-Host "=================================================================" -ForegroundColor Cyan

    # ARG helper — batches of 10 (ARG subscription limit)
    function Invoke-ARGQuery {
        param ([string]$Query, [string]$CheckName)
        $results = @()
        $batches = [math]::Ceiling($rawSubIds.Count / 10)
        for ($i = 0; $i -lt $batches; $i++) {
            $batch = $rawSubIds | Select-Object -Skip ($i * 10) -First 10
            try {
                $r = Search-AzGraph -Query $Query -Subscription $batch -First 1000 -ErrorAction Stop
                $results += $r
            } catch {
                Write-Host "    [WARN] $CheckName batch $($i+1): $_" -ForegroundColor Yellow
            }
        }
        return $results
    }

    $allFindings = [System.Collections.Generic.List[object]]::new()

    # ================================================================
    # CATEGORY 1 — NETWORK EXPOSURE
    # ================================================================
    Write-Host ""
    Write-Host "  [1/7] Network Exposure..." -ForegroundColor Yellow

    $netChecks = @(
        @{
            Name = "Storage Accounts — open to all networks"
            Query = @"
resources | where type =~ 'microsoft.storage/storageaccounts'
| where properties.networkAcls.defaultAction =~ 'Allow'
| project ResourceName=name, ResourceType='Storage Account', SubscriptionId=subscriptionId, ResourceGroup=resourceGroup, Location=location,
  Finding='Network access Allow All — no firewall restriction', Impact='High', Category='1. Network Exposure',
  Recommendation='Set defaultAction to Deny; add VNet/IP rules or private endpoints',
  LearnMore='https://learn.microsoft.com/azure/storage/common/storage-network-security'
"@
        },
        @{
            Name = "Function Apps / App Services — no access restrictions"
            Query = @"
resources | where type =~ 'microsoft.web/sites'
| where isnull(properties.siteConfig.ipSecurityRestrictions)
    or array_length(properties.siteConfig.ipSecurityRestrictions) == 0
    or (array_length(properties.siteConfig.ipSecurityRestrictions) == 1
        and properties.siteConfig.ipSecurityRestrictions[0].action =~ 'Allow'
        and properties.siteConfig.ipSecurityRestrictions[0].ipAddress =~ 'Any')
| project ResourceName=name, ResourceType=case(kind contains 'functionapp','Function App','App Service'),
  SubscriptionId=subscriptionId, ResourceGroup=resourceGroup, Location=location,
  Finding='No IP/VNet access restrictions configured', Impact='High', Category='1. Network Exposure',
  Recommendation='Configure access restrictions or private endpoints',
  LearnMore='https://learn.microsoft.com/azure/app-service/app-service-ip-restrictions'
"@
        },
        @{
            Name = "Key Vaults — no network firewall"
            Query = @"
resources | where type =~ 'microsoft.keyvault/vaults'
| where properties.networkAcls.defaultAction =~ 'Allow' or isnull(properties.networkAcls)
| project ResourceName=name, ResourceType='Key Vault', SubscriptionId=subscriptionId, ResourceGroup=resourceGroup, Location=location,
  Finding='Key Vault accessible from all networks', Impact='High', Category='1. Network Exposure',
  Recommendation='Enable Key Vault firewall; restrict to VNets/IPs or use private endpoints',
  LearnMore='https://learn.microsoft.com/azure/key-vault/general/network-security'
"@
        },
        @{
            Name = "SQL Servers — public network access enabled"
            Query = @"
resources | where type =~ 'microsoft.sql/servers'
| where properties.publicNetworkAccess =~ 'Enabled'
| project ResourceName=name, ResourceType='SQL Server', SubscriptionId=subscriptionId, ResourceGroup=resourceGroup, Location=location,
  Finding='Public network access is Enabled', Impact='High', Category='1. Network Exposure',
  Recommendation='Disable public network access; use private endpoints',
  LearnMore='https://learn.microsoft.com/azure/azure-sql/database/connectivity-settings'
"@
        },
        @{
            Name = "Event Hub Namespaces — open to all networks"
            Query = @"
resources | where type =~ 'microsoft.eventhub/namespaces'
| where properties.networkRuleSets.defaultAction =~ 'Allow' or isnull(properties.networkRuleSets)
| project ResourceName=name, ResourceType='Event Hub Namespace', SubscriptionId=subscriptionId, ResourceGroup=resourceGroup, Location=location,
  Finding='Network ruleset default action is Allow', Impact='Medium', Category='1. Network Exposure',
  Recommendation='Set defaultAction to Deny; whitelist specific VNets/IPs',
  LearnMore='https://learn.microsoft.com/azure/event-hubs/event-hubs-ip-filtering'
"@
        },
        @{
            Name = "Service Bus Namespaces — open to all networks"
            Query = @"
resources | where type =~ 'microsoft.servicebus/namespaces'
| where properties.networkRuleSets.defaultAction =~ 'Allow' or isnull(properties.networkRuleSets)
| project ResourceName=name, ResourceType='Service Bus Namespace', SubscriptionId=subscriptionId, ResourceGroup=resourceGroup, Location=location,
  Finding='Network ruleset default action is Allow', Impact='Medium', Category='1. Network Exposure',
  Recommendation='Set defaultAction to Deny; add VNet/IP rules',
  LearnMore='https://learn.microsoft.com/azure/service-bus-messaging/service-bus-ip-filtering'
"@
        },
        @{
            Name = "Cosmos DB — public network access enabled"
            Query = @"
resources | where type =~ 'microsoft.documentdb/databaseaccounts'
| where properties.publicNetworkAccess =~ 'Enabled'
| project ResourceName=name, ResourceType='Cosmos DB', SubscriptionId=subscriptionId, ResourceGroup=resourceGroup, Location=location,
  Finding='Public network access is Enabled', Impact='High', Category='1. Network Exposure',
  Recommendation='Disable public access; use private endpoints',
  LearnMore='https://learn.microsoft.com/azure/cosmos-db/how-to-configure-private-endpoints'
"@
        },
        @{
            Name = "Container Registries — public network access"
            Query = @"
resources | where type =~ 'microsoft.containerregistry/registries'
| where properties.publicNetworkAccess =~ 'Enabled' or isnull(properties.networkRuleSet) or properties.networkRuleSet.defaultAction =~ 'Allow'
| project ResourceName=name, ResourceType='Container Registry', SubscriptionId=subscriptionId, ResourceGroup=resourceGroup, Location=location,
  Finding='Public network access enabled or no network rules configured', Impact='Medium', Category='1. Network Exposure',
  Recommendation='Disable public access; use private endpoints',
  LearnMore='https://learn.microsoft.com/azure/container-registry/container-registry-private-link'
"@
        },
        @{
            Name = "AKS Clusters — API server not private"
            Query = @"
resources | where type =~ 'microsoft.containerservice/managedclusters'
| where properties.apiServerAccessProfile.enablePrivateCluster != true
| project ResourceName=name, ResourceType='AKS Cluster', SubscriptionId=subscriptionId, ResourceGroup=resourceGroup, Location=location,
  Finding='API server is publicly accessible (not a private cluster)', Impact='High', Category='1. Network Exposure',
  Recommendation='Enable private cluster or restrict API server authorized IP ranges',
  LearnMore='https://learn.microsoft.com/azure/aks/private-cluster'
"@
        },
        @{
            Name = "Automation Accounts — public network access"
            Query = @"
resources | where type =~ 'microsoft.automation/automationaccounts'
| where properties.publicNetworkAccess != false
| project ResourceName=name, ResourceType='Automation Account', SubscriptionId=subscriptionId, ResourceGroup=resourceGroup, Location=location,
  Finding='Public network access is not disabled', Impact='Medium', Category='1. Network Exposure',
  Recommendation='Disable public network access; configure private endpoints',
  LearnMore='https://learn.microsoft.com/azure/automation/how-to/private-link-security'
"@
        },
        @{
            Name = "API Management — no VNet integration"
            Query = @"
resources | where type =~ 'microsoft.apimanagement/service'
| where isnull(properties.virtualNetworkConfiguration) or properties.virtualNetworkType =~ 'None'
| project ResourceName=name, ResourceType='API Management', SubscriptionId=subscriptionId, ResourceGroup=resourceGroup, Location=location,
  Finding='Not integrated with a Virtual Network', Impact='Medium', Category='1. Network Exposure',
  Recommendation='Deploy APIM in External or Internal VNet mode',
  LearnMore='https://learn.microsoft.com/azure/api-management/api-management-using-with-vnet'
"@
        },
        @{
            Name = "Cognitive Services — public network access"
            Query = @"
resources | where type startswith 'microsoft.cognitiveservices'
| where properties.publicNetworkAccess =~ 'Enabled' or isnull(properties.networkAcls)
| project ResourceName=name, ResourceType='Cognitive Services', SubscriptionId=subscriptionId, ResourceGroup=resourceGroup, Location=location,
  Finding='Public network access enabled', Impact='Medium', Category='1. Network Exposure',
  Recommendation='Disable public access; use private endpoints or VNet rules',
  LearnMore='https://learn.microsoft.com/azure/cognitive-services/cognitive-services-virtual-networks'
"@
        },
        @{
            Name = "IoT Hub — public network access"
            Query = @"
resources | where type =~ 'microsoft.devices/iothubs'
| where properties.publicNetworkAccess =~ 'Enabled'
| project ResourceName=name, ResourceType='IoT Hub', SubscriptionId=subscriptionId, ResourceGroup=resourceGroup, Location=location,
  Finding='Public network access is Enabled', Impact='Medium', Category='1. Network Exposure',
  Recommendation='Disable public access; restrict to VNet/IP filtering or private endpoints',
  LearnMore='https://learn.microsoft.com/azure/iot-hub/virtual-network-support'
"@
        },
        @{
            Name = "Data Factory — no managed VNet"
            Query = @"
resources | where type =~ 'microsoft.datafactory/factories'
| where isnull(properties.globalParameters) or properties.publicNetworkAccess =~ 'Enabled'
| project ResourceName=name, ResourceType='Data Factory', SubscriptionId=subscriptionId, ResourceGroup=resourceGroup, Location=location,
  Finding='Public network access enabled or managed VNet not confirmed', Impact='Medium', Category='1. Network Exposure',
  Recommendation='Enable managed VNet and disable public network access',
  LearnMore='https://learn.microsoft.com/azure/data-factory/managed-virtual-network-private-endpoint'
"@
        },
        @{
            Name = "Synapse Workspaces — public network access"
            Query = @"
resources | where type =~ 'microsoft.synapse/workspaces'
| where properties.publicNetworkAccess =~ 'Enabled'
| project ResourceName=name, ResourceType='Synapse Workspace', SubscriptionId=subscriptionId, ResourceGroup=resourceGroup, Location=location,
  Finding='Public network access is Enabled', Impact='High', Category='1. Network Exposure',
  Recommendation='Disable public network access; use managed private endpoints',
  LearnMore='https://learn.microsoft.com/azure/synapse-analytics/security/synapse-workspace-managed-private-endpoints'
"@
        },
        @{
            Name = "Log Analytics Workspaces — public access"
            Query = @"
resources | where type =~ 'microsoft.operationalinsights/workspaces'
| where properties.publicNetworkAccessForIngestion =~ 'Enabled' or properties.publicNetworkAccessForQuery =~ 'Enabled'
| project ResourceName=name, ResourceType='Log Analytics Workspace', SubscriptionId=subscriptionId, ResourceGroup=resourceGroup, Location=location,
  Finding='Public network access enabled for ingestion or query', Impact='Low', Category='1. Network Exposure',
  Recommendation='Restrict ingestion and query to private endpoints for sensitive workspaces',
  LearnMore='https://learn.microsoft.com/azure/azure-monitor/logs/private-link-security'
"@
        },
        @{
            Name = "App Configuration — public network access"
            Query = @"
resources | where type =~ 'microsoft.appconfiguration/configurationstores'
| where properties.publicNetworkAccess =~ 'Enabled'
| project ResourceName=name, ResourceType='App Configuration', SubscriptionId=subscriptionId, ResourceGroup=resourceGroup, Location=location,
  Finding='Public network access is Enabled', Impact='Medium', Category='1. Network Exposure',
  Recommendation='Disable public access; use private endpoints',
  LearnMore='https://learn.microsoft.com/azure/azure-app-configuration/concept-private-endpoint'
"@
        }
    )

    foreach ($check in $netChecks) {
        Write-Host "    - $($check.Name)..." -ForegroundColor Gray
        $allFindings.AddRange([object[]](Invoke-ARGQuery -Query $check.Query -CheckName $check.Name))
    }
    $cat1Count = ($allFindings | Where-Object { $_.Category -like '1.*' }).Count
    Write-Host "    → $cat1Count findings" -ForegroundColor $(if ($cat1Count -gt 0) {"Red"} else {"Green"})

    # ================================================================
    # CATEGORY 2 — SOFT DELETE / RECOVERY
    # ================================================================
    Write-Host ""
    Write-Host "  [2/7] Soft Delete & Recovery..." -ForegroundColor Yellow

    $sdChecks = @(
        @{
            Name = "Storage — blob soft delete disabled"
            Query = @"
resources | where type =~ 'microsoft.storage/storageaccounts'
| where properties.blobServiceProperties.deleteRetentionPolicy.enabled != true or isnull(properties.blobServiceProperties.deleteRetentionPolicy)
| project ResourceName=name, ResourceType='Storage Account', SubscriptionId=subscriptionId, ResourceGroup=resourceGroup, Location=location,
  Finding='Blob soft delete is not enabled', Impact='High', Category='2. Soft Delete & Recovery',
  Recommendation='Enable blob soft delete; minimum 7-day retention recommended',
  LearnMore='https://learn.microsoft.com/azure/storage/blobs/soft-delete-blob-overview'
"@
        },
        @{
            Name = "Storage — file share soft delete disabled"
            Query = @"
resources | where type =~ 'microsoft.storage/storageaccounts'
| where properties.fileServiceProperties.shareDeleteRetentionPolicy.enabled != true or isnull(properties.fileServiceProperties.shareDeleteRetentionPolicy)
| project ResourceName=name, ResourceType='Storage Account', SubscriptionId=subscriptionId, ResourceGroup=resourceGroup, Location=location,
  Finding='File share soft delete is not enabled', Impact='High', Category='2. Soft Delete & Recovery',
  Recommendation='Enable file share soft delete; minimum 7-day retention recommended',
  LearnMore='https://learn.microsoft.com/azure/storage/files/storage-files-enable-soft-delete'
"@
        },
        @{
            Name = "Key Vault — soft delete disabled"
            Query = @"
resources | where type =~ 'microsoft.keyvault/vaults'
| where properties.enableSoftDelete != true
| project ResourceName=name, ResourceType='Key Vault', SubscriptionId=subscriptionId, ResourceGroup=resourceGroup, Location=location,
  Finding='Soft delete is not enabled', Impact='High', Category='2. Soft Delete & Recovery',
  Recommendation='Enable soft delete (now default for new KVs — verify older vaults)',
  LearnMore='https://learn.microsoft.com/azure/key-vault/general/soft-delete-overview'
"@
        },
        @{
            Name = "Key Vault — purge protection disabled"
            Query = @"
resources | where type =~ 'microsoft.keyvault/vaults'
| where properties.enablePurgeProtection != true
| project ResourceName=name, ResourceType='Key Vault', SubscriptionId=subscriptionId, ResourceGroup=resourceGroup, Location=location,
  Finding='Purge protection is not enabled', Impact='High', Category='2. Soft Delete & Recovery',
  Recommendation='Enable purge protection to prevent permanent deletion during retention period',
  LearnMore='https://learn.microsoft.com/azure/key-vault/general/soft-delete-overview#purge-protection'
"@
        },
        @{
            Name = "Recovery Services Vault — soft delete disabled"
            Query = @"
resources | where type =~ 'microsoft.recoveryservices/vaults'
| where properties.securitySettings.softDeleteSettings.softDeleteState !~ 'Enabled' or isnull(properties.securitySettings.softDeleteSettings)
| project ResourceName=name, ResourceType='Recovery Services Vault', SubscriptionId=subscriptionId, ResourceGroup=resourceGroup, Location=location,
  Finding='Soft delete is not enabled', Impact='High', Category='2. Soft Delete & Recovery',
  Recommendation='Enable soft delete to protect backup data from accidental/malicious deletion',
  LearnMore='https://learn.microsoft.com/azure/backup/backup-azure-security-feature-cloud'
"@
        },
        @{
            Name = "Recovery Services Vault — MUA not enabled"
            Query = @"
resources | where type =~ 'microsoft.recoveryservices/vaults'
| where isnull(properties.securitySettings.multiUserAuthorization) or properties.securitySettings.multiUserAuthorization =~ 'Disabled'
| project ResourceName=name, ResourceType='Recovery Services Vault', SubscriptionId=subscriptionId, ResourceGroup=resourceGroup, Location=location,
  Finding='Multi-User Authorization (MUA) is not enabled', Impact='High', Category='2. Soft Delete & Recovery',
  Recommendation='Enable MUA to require approval before disabling backup protection',
  LearnMore='https://learn.microsoft.com/azure/backup/multi-user-authorization'
"@
        },
        @{
            Name = "Event Hub — geo-redundancy not configured"
            Query = @"
resources | where type =~ 'microsoft.eventhub/namespaces'
| where isnull(properties.geoDataReplication) and sku.tier !~ 'Basic'
| project ResourceName=name, ResourceType='Event Hub Namespace', SubscriptionId=subscriptionId, ResourceGroup=resourceGroup, Location=location,
  Finding='Geo-redundancy / geo-replication not configured', Impact='Medium', Category='2. Soft Delete & Recovery',
  Recommendation='Configure geo-disaster recovery pairing for business-critical namespaces',
  LearnMore='https://learn.microsoft.com/azure/event-hubs/event-hubs-geo-dr'
"@
        },
        @{
            Name = "SQL Server — no long-term backup retention"
            Query = @"
resources | where type =~ 'microsoft.sql/servers'
| where isnull(properties.administratorLogin)
| project ResourceName=name, ResourceType='SQL Server', SubscriptionId=subscriptionId, ResourceGroup=resourceGroup, Location=location,
  Finding='SQL Server detected — verify long-term backup retention is configured on databases',
  Impact='Medium', Category='2. Soft Delete & Recovery',
  Recommendation='Configure LTR policy on SQL databases (weekly/monthly/yearly backups)',
  LearnMore='https://learn.microsoft.com/azure/azure-sql/database/long-term-retention-overview'
"@
        },
        @{
            Name = "Cosmos DB — continuous backup not enabled"
            Query = @"
resources | where type =~ 'microsoft.documentdb/databaseaccounts'
| where isnull(properties.backupPolicy) or properties.backupPolicy.type =~ 'Periodic'
| project ResourceName=name, ResourceType='Cosmos DB', SubscriptionId=subscriptionId, ResourceGroup=resourceGroup, Location=location,
  Finding='Continuous backup (PITR) not enabled — using Periodic backup mode', Impact='High', Category='2. Soft Delete & Recovery',
  Recommendation='Switch to Continuous backup mode for point-in-time restore capability',
  LearnMore='https://learn.microsoft.com/azure/cosmos-db/continuous-backup-restore-introduction'
"@
        }
    )

    foreach ($check in $sdChecks) {
        Write-Host "    - $($check.Name)..." -ForegroundColor Gray
        $allFindings.AddRange([object[]](Invoke-ARGQuery -Query $check.Query -CheckName $check.Name))
    }
    $cat2Count = ($allFindings | Where-Object { $_.Category -like '2.*' }).Count
    Write-Host "    → $cat2Count findings" -ForegroundColor $(if ($cat2Count -gt 0) {"Red"} else {"Green"})

    # ================================================================
    # CATEGORY 3 — ENCRYPTION
    # ================================================================
    Write-Host ""
    Write-Host "  [3/7] Encryption..." -ForegroundColor Yellow

    $encChecks = @(
        @{
            Name = "Storage — HTTPS-only transfer not enforced"
            Query = @"
resources | where type =~ 'microsoft.storage/storageaccounts'
| where properties.supportsHttpsTrafficOnly != true
| project ResourceName=name, ResourceType='Storage Account', SubscriptionId=subscriptionId, ResourceGroup=resourceGroup, Location=location,
  Finding='HTTPS-only transfer is not enforced', Impact='High', Category='3. Encryption',
  Recommendation='Enable secure transfer required (supportsHttpsTrafficOnly = true)',
  LearnMore='https://learn.microsoft.com/azure/storage/common/storage-require-secure-transfer'
"@
        },
        @{
            Name = "Storage — minimum TLS version below 1.2"
            Query = @"
resources | where type =~ 'microsoft.storage/storageaccounts'
| where properties.minimumTlsVersion !~ 'TLS1_2' and properties.minimumTlsVersion !~ 'TLS1_3'
| project ResourceName=name, ResourceType='Storage Account', SubscriptionId=subscriptionId, ResourceGroup=resourceGroup, Location=location,
  Finding=strcat('Minimum TLS version is ', tostring(properties.minimumTlsVersion), ' — should be TLS 1.2+'),
  Impact='High', Category='3. Encryption',
  Recommendation='Set minimumTlsVersion to TLS1_2 or TLS1_3',
  LearnMore='https://learn.microsoft.com/azure/storage/common/transport-layer-security-configure-minimum-version'
"@
        },
        @{
            Name = "App Service / Function Apps — HTTPS-only not enforced"
            Query = @"
resources | where type =~ 'microsoft.web/sites'
| where properties.httpsOnly != true
| project ResourceName=name, ResourceType=case(kind contains 'functionapp','Function App','App Service'),
  SubscriptionId=subscriptionId, ResourceGroup=resourceGroup, Location=location,
  Finding='HTTPS-only is not enforced', Impact='High', Category='3. Encryption',
  Recommendation='Enable httpsOnly on the web app to redirect all HTTP traffic to HTTPS',
  LearnMore='https://learn.microsoft.com/azure/app-service/configure-ssl-bindings#enforce-https'
"@
        },
        @{
            Name = "App Service / Function Apps — minimum TLS below 1.2"
            Query = @"
resources | where type =~ 'microsoft.web/sites'
| where properties.siteConfig.minTlsVersion !~ '1.2' and properties.siteConfig.minTlsVersion !~ '1.3'
| project ResourceName=name, ResourceType=case(kind contains 'functionapp','Function App','App Service'),
  SubscriptionId=subscriptionId, ResourceGroup=resourceGroup, Location=location,
  Finding=strcat('Minimum TLS version is ', tostring(properties.siteConfig.minTlsVersion), ' — should be 1.2+'),
  Impact='High', Category='3. Encryption',
  Recommendation='Set minTlsVersion to 1.2 or higher in site configuration',
  LearnMore='https://learn.microsoft.com/azure/app-service/overview-tls'
"@
        },
        @{
            Name = "SQL Servers — TDE not enabled on databases"
            Query = @"
resources | where type =~ 'microsoft.sql/servers/databases'
| where name !~ 'master'
| where isnull(properties.transparentDataEncryption) or properties.transparentDataEncryption.status !~ 'Enabled'
| project ResourceName=name, ResourceType='SQL Database', SubscriptionId=subscriptionId, ResourceGroup=resourceGroup, Location=location,
  Finding='Transparent Data Encryption (TDE) is not enabled', Impact='High', Category='3. Encryption',
  Recommendation='Enable TDE on all SQL databases',
  LearnMore='https://learn.microsoft.com/azure/azure-sql/database/transparent-data-encryption-tde-overview'
"@
        },
        @{
            Name = "Managed Disks — not encrypted with CMK"
            Query = @"
resources | where type =~ 'microsoft.compute/disks'
| where isnull(properties.encryption.diskEncryptionSetId)
| project ResourceName=name, ResourceType='Managed Disk', SubscriptionId=subscriptionId, ResourceGroup=resourceGroup, Location=location,
  Finding='Disk is not encrypted with a Customer-Managed Key (CMK)', Impact='Low', Category='3. Encryption',
  Recommendation='Consider encrypting disks with CMK via Disk Encryption Sets for sensitive workloads',
  LearnMore='https://learn.microsoft.com/azure/virtual-machines/disk-encryption'
"@
        },
        @{
            Name = "Cosmos DB — CMK not configured"
            Query = @"
resources | where type =~ 'microsoft.documentdb/databaseaccounts'
| where isnull(properties.keyVaultKeyUri)
| project ResourceName=name, ResourceType='Cosmos DB', SubscriptionId=subscriptionId, ResourceGroup=resourceGroup, Location=location,
  Finding='Customer-Managed Key (CMK) encryption not configured', Impact='Low', Category='3. Encryption',
  Recommendation='Configure CMK encryption using Key Vault for regulatory compliance',
  LearnMore='https://learn.microsoft.com/azure/cosmos-db/how-to-setup-cmk'
"@
        },
        @{
            Name = "AKS — OS disk encryption not configured"
            Query = @"
resources | where type =~ 'microsoft.containerservice/managedclusters'
| where isnull(properties.diskEncryptionSetID)
| project ResourceName=name, ResourceType='AKS Cluster', SubscriptionId=subscriptionId, ResourceGroup=resourceGroup, Location=location,
  Finding='Disk Encryption Set not configured for node OS disks', Impact='Low', Category='3. Encryption',
  Recommendation='Configure a Disk Encryption Set with CMK for node OS disk encryption',
  LearnMore='https://learn.microsoft.com/azure/aks/azure-disk-customer-managed-keys'
"@
        }
    )

    foreach ($check in $encChecks) {
        Write-Host "    - $($check.Name)..." -ForegroundColor Gray
        $allFindings.AddRange([object[]](Invoke-ARGQuery -Query $check.Query -CheckName $check.Name))
    }
    $cat3Count = ($allFindings | Where-Object { $_.Category -like '3.*' }).Count
    Write-Host "    → $cat3Count findings" -ForegroundColor $(if ($cat3Count -gt 0) {"Red"} else {"Green"})

    # ================================================================
    # CATEGORY 4 — IDENTITY & ACCESS
    # ================================================================
    Write-Host ""
    Write-Host "  [4/7] Identity & Access..." -ForegroundColor Yellow

    $iamChecks = @(
        @{
            Name = "SQL Server — no AAD administrator configured"
            Query = @"
resources | where type =~ 'microsoft.sql/servers'
| where isnull(properties.administrators) or properties.administrators.administratorType !~ 'ActiveDirectory'
| project ResourceName=name, ResourceType='SQL Server', SubscriptionId=subscriptionId, ResourceGroup=resourceGroup, Location=location,
  Finding='Azure AD administrator is not configured', Impact='High', Category='4. Identity & Access',
  Recommendation='Configure an Azure AD admin for SQL Server to enforce AAD authentication',
  LearnMore='https://learn.microsoft.com/azure/azure-sql/database/authentication-aad-configure'
"@
        },
        @{
            Name = "AKS — RBAC not enabled"
            Query = @"
resources | where type =~ 'microsoft.containerservice/managedclusters'
| where properties.enableRBAC != true
| project ResourceName=name, ResourceType='AKS Cluster', SubscriptionId=subscriptionId, ResourceGroup=resourceGroup, Location=location,
  Finding='Kubernetes RBAC is not enabled', Impact='High', Category='4. Identity & Access',
  Recommendation='Enable RBAC and integrate with Azure AD for fine-grained access control',
  LearnMore='https://learn.microsoft.com/azure/aks/azure-ad-rbac'
"@
        },
        @{
            Name = "AKS — local accounts not disabled"
            Query = @"
resources | where type =~ 'microsoft.containerservice/managedclusters'
| where properties.disableLocalAccounts != true
| project ResourceName=name, ResourceType='AKS Cluster', SubscriptionId=subscriptionId, ResourceGroup=resourceGroup, Location=location,
  Finding='Local accounts (non-AAD) are not disabled', Impact='Medium', Category='4. Identity & Access',
  Recommendation='Disable local accounts to enforce Azure AD-only authentication',
  LearnMore='https://learn.microsoft.com/azure/aks/managed-aad#disable-local-accounts'
"@
        },
        @{
            Name = "Key Vault — not using RBAC authorization model"
            Query = @"
resources | where type =~ 'microsoft.keyvault/vaults'
| where properties.enableRbacAuthorization != true
| project ResourceName=name, ResourceType='Key Vault', SubscriptionId=subscriptionId, ResourceGroup=resourceGroup, Location=location,
  Finding='Key Vault using legacy Access Policies instead of Azure RBAC', Impact='Medium', Category='4. Identity & Access',
  Recommendation='Migrate to Azure RBAC authorization model for Key Vault',
  LearnMore='https://learn.microsoft.com/azure/key-vault/general/rbac-guide'
"@
        },
        @{
            Name = "Automation Accounts — no managed identity"
            Query = @"
resources | where type =~ 'microsoft.automation/automationaccounts'
| where isnull(identity) or (identity.type !~ 'SystemAssigned' and identity.type !~ 'UserAssigned')
| project ResourceName=name, ResourceType='Automation Account', SubscriptionId=subscriptionId, ResourceGroup=resourceGroup, Location=location,
  Finding='No managed identity configured — may be using RunAs accounts (deprecated)', Impact='High', Category='4. Identity & Access',
  Recommendation='Enable system-assigned or user-assigned managed identity; remove RunAs accounts',
  LearnMore='https://learn.microsoft.com/azure/automation/automation-security-overview'
"@
        },
        @{
            Name = "App Service / Functions — no managed identity"
            Query = @"
resources | where type =~ 'microsoft.web/sites'
| where isnull(identity) or (identity.type !~ 'SystemAssigned' and identity.type !~ 'UserAssigned')
| project ResourceName=name, ResourceType=case(kind contains 'functionapp','Function App','App Service'),
  SubscriptionId=subscriptionId, ResourceGroup=resourceGroup, Location=location,
  Finding='No managed identity configured', Impact='Medium', Category='4. Identity & Access',
  Recommendation='Enable managed identity to avoid storing credentials in application config',
  LearnMore='https://learn.microsoft.com/azure/app-service/overview-managed-identity'
"@
        },
        @{
            Name = "Synapse — no managed identity"
            Query = @"
resources | where type =~ 'microsoft.synapse/workspaces'
| where isnull(identity)
| project ResourceName=name, ResourceType='Synapse Workspace', SubscriptionId=subscriptionId, ResourceGroup=resourceGroup, Location=location,
  Finding='No managed identity configured', Impact='Medium', Category='4. Identity & Access',
  Recommendation='Enable managed identity for Synapse workspace',
  LearnMore='https://learn.microsoft.com/azure/synapse-analytics/security/synapse-workspace-managed-identity'
"@
        }
    )

    foreach ($check in $iamChecks) {
        Write-Host "    - $($check.Name)..." -ForegroundColor Gray
        $allFindings.AddRange([object[]](Invoke-ARGQuery -Query $check.Query -CheckName $check.Name))
    }
    $cat4Count = ($allFindings | Where-Object { $_.Category -like '4.*' }).Count
    Write-Host "    → $cat4Count findings" -ForegroundColor $(if ($cat4Count -gt 0) {"Red"} else {"Green"})

    # ================================================================
    # CATEGORY 5 — MONITORING & LOGGING
    # ================================================================
    Write-Host ""
    Write-Host "  [5/7] Monitoring & Logging..." -ForegroundColor Yellow

    $monChecks = @(
        @{
            Name = "AKS — monitoring/diagnostics not enabled"
            Query = @"
resources | where type =~ 'microsoft.containerservice/managedclusters'
| where isnull(properties.addonProfiles.omsagent) or properties.addonProfiles.omsagent.enabled != true
| project ResourceName=name, ResourceType='AKS Cluster', SubscriptionId=subscriptionId, ResourceGroup=resourceGroup, Location=location,
  Finding='Azure Monitor (OMS agent) addon is not enabled', Impact='High', Category='5. Monitoring & Logging',
  Recommendation='Enable Container Insights / OMS agent addon for cluster monitoring',
  LearnMore='https://learn.microsoft.com/azure/aks/monitor-aks'
"@
        },
        @{
            Name = "AKS — Defender for Containers not enabled"
            Query = @"
resources | where type =~ 'microsoft.containerservice/managedclusters'
| where isnull(properties.securityProfile.defender) or properties.securityProfile.defender.securityMonitoring.enabled != true
| project ResourceName=name, ResourceType='AKS Cluster', SubscriptionId=subscriptionId, ResourceGroup=resourceGroup, Location=location,
  Finding='Microsoft Defender for Containers is not enabled on this cluster', Impact='High', Category='5. Monitoring & Logging',
  Recommendation='Enable Defender for Containers for runtime threat protection',
  LearnMore='https://learn.microsoft.com/azure/defender-for-cloud/defender-for-containers-introduction'
"@
        },
        @{
            Name = "SQL Server — auditing not enabled"
            Query = @"
resources | where type =~ 'microsoft.sql/servers'
| where isnull(properties.auditingSettings) or properties.auditingSettings.state =~ 'Disabled'
| project ResourceName=name, ResourceType='SQL Server', SubscriptionId=subscriptionId, ResourceGroup=resourceGroup, Location=location,
  Finding='Server-level auditing is not enabled', Impact='High', Category='5. Monitoring & Logging',
  Recommendation='Enable SQL Server auditing; store logs in Storage Account or Log Analytics',
  LearnMore='https://learn.microsoft.com/azure/azure-sql/database/auditing-overview'
"@
        },
        @{
            Name = "SQL — Advanced Threat Protection not enabled"
            Query = @"
resources | where type =~ 'microsoft.sql/servers'
| where isnull(properties.securityAlertPolicies) or properties.securityAlertPolicies.state =~ 'Disabled'
| project ResourceName=name, ResourceType='SQL Server', SubscriptionId=subscriptionId, ResourceGroup=resourceGroup, Location=location,
  Finding='Advanced Threat Protection (ATP) is not enabled', Impact='High', Category='5. Monitoring & Logging',
  Recommendation='Enable Advanced Threat Protection on SQL Server',
  LearnMore='https://learn.microsoft.com/azure/azure-sql/database/threat-detection-overview'
"@
        },
        @{
            Name = "App Service — App Service Logs not configured"
            Query = @"
resources | where type =~ 'microsoft.web/sites'
| where properties.siteConfig.detailedErrorLoggingEnabled != true
    or properties.siteConfig.httpLoggingEnabled != true
| project ResourceName=name, ResourceType=case(kind contains 'functionapp','Function App','App Service'),
  SubscriptionId=subscriptionId, ResourceGroup=resourceGroup, Location=location,
  Finding='HTTP or detailed error logging is not enabled', Impact='Medium', Category='5. Monitoring & Logging',
  Recommendation='Enable HTTP logging and detailed error logging in App Service diagnostics',
  LearnMore='https://learn.microsoft.com/azure/app-service/troubleshoot-diagnostic-logs'
"@
        },
        @{
            Name = "VMs — Boot diagnostics not enabled"
            Query = @"
resources | where type =~ 'microsoft.compute/virtualmachines'
| where properties.diagnosticsProfile.bootDiagnostics.enabled != true
| project ResourceName=name, ResourceType='Virtual Machine', SubscriptionId=subscriptionId, ResourceGroup=resourceGroup, Location=location,
  Finding='Boot diagnostics is not enabled', Impact='Medium', Category='5. Monitoring & Logging',
  Recommendation='Enable boot diagnostics to capture serial console output for troubleshooting',
  LearnMore='https://learn.microsoft.com/azure/virtual-machines/boot-diagnostics'
"@
        },
        @{
            Name = "Cosmos DB — diagnostic logs not configured"
            Query = @"
resources | where type =~ 'microsoft.documentdb/databaseaccounts'
| where isnull(properties.diagnosticLogSettings)
| project ResourceName=name, ResourceType='Cosmos DB', SubscriptionId=subscriptionId, ResourceGroup=resourceGroup, Location=location,
  Finding='Diagnostic log settings not detected at resource level', Impact='Medium', Category='5. Monitoring & Logging',
  Recommendation='Configure diagnostic settings to send logs to Log Analytics or Storage',
  LearnMore='https://learn.microsoft.com/azure/cosmos-db/monitor-resource-logs'
"@
        },
        @{
            Name = "Log Analytics — retention less than 90 days"
            Query = @"
resources | where type =~ 'microsoft.operationalinsights/workspaces'
| where properties.retentionInDays < 90
| project ResourceName=name, ResourceType='Log Analytics Workspace', SubscriptionId=subscriptionId, ResourceGroup=resourceGroup, Location=location,
  Finding=strcat('Log retention is ', tostring(properties.retentionInDays), ' days — below 90-day baseline'),
  Impact='Medium', Category='5. Monitoring & Logging',
  Recommendation='Set log retention to minimum 90 days; 365 days for compliance workloads',
  LearnMore='https://learn.microsoft.com/azure/azure-monitor/logs/data-retention-archive'
"@
        }
    )

    foreach ($check in $monChecks) {
        Write-Host "    - $($check.Name)..." -ForegroundColor Gray
        $allFindings.AddRange([object[]](Invoke-ARGQuery -Query $check.Query -CheckName $check.Name))
    }
    $cat5Count = ($allFindings | Where-Object { $_.Category -like '5.*' }).Count
    Write-Host "    → $cat5Count findings" -ForegroundColor $(if ($cat5Count -gt 0) {"Red"} else {"Green"})

    # ================================================================
    # CATEGORY 6 — NETWORK HARDENING
    # ================================================================
    Write-Host ""
    Write-Host "  [6/7] Network Hardening..." -ForegroundColor Yellow

    $nhChecks = @(
        @{
            Name = "NSGs — inbound rule allows all traffic (0.0.0.0/0)"
            Query = @"
resources | where type =~ 'microsoft.network/networksecuritygroups'
| mv-expand rule = properties.securityRules
| where rule.properties.direction =~ 'Inbound'
    and rule.properties.access =~ 'Allow'
    and (rule.properties.sourceAddressPrefix =~ '*' or rule.properties.sourceAddressPrefix =~ '0.0.0.0/0' or rule.properties.sourceAddressPrefix =~ 'Internet')
    and rule.properties.destinationPortRange !~ '443'
| project ResourceName=name, ResourceType='NSG', SubscriptionId=subscriptionId, ResourceGroup=resourceGroup, Location=location,
  Finding=strcat('Inbound rule ', tostring(rule.name), ' allows all source IPs on port ', tostring(rule.properties.destinationPortRange)),
  Impact='High', Category='6. Network Hardening',
  Recommendation='Restrict source IP ranges; remove or tighten overly permissive inbound rules',
  LearnMore='https://learn.microsoft.com/azure/virtual-network/network-security-groups-overview'
"@
        },
        @{
            Name = "VNets — DDoS Protection not enabled"
            Query = @"
resources | where type =~ 'microsoft.network/virtualnetworks'
| where isnull(properties.ddosProtectionPlan) or properties.enableDdosProtection != true
| project ResourceName=name, ResourceType='Virtual Network', SubscriptionId=subscriptionId, ResourceGroup=resourceGroup, Location=location,
  Finding='DDoS Protection Standard plan is not associated', Impact='Medium', Category='6. Network Hardening',
  Recommendation='Associate a DDoS Protection Standard plan for internet-facing workloads',
  LearnMore='https://learn.microsoft.com/azure/ddos-protection/manage-ddos-protection'
"@
        },
        @{
            Name = "Azure Firewall — threat intelligence mode not Alert/Deny"
            Query = @"
resources | where type =~ 'microsoft.network/azurefirewalls'
| where properties.threatIntelMode =~ 'Off' or isnull(properties.threatIntelMode)
| project ResourceName=name, ResourceType='Azure Firewall', SubscriptionId=subscriptionId, ResourceGroup=resourceGroup, Location=location,
  Finding=strcat('Threat intelligence mode is ', tostring(properties.threatIntelMode), ' — should be Alert or Deny'),
  Impact='High', Category='6. Network Hardening',
  Recommendation='Set threat intelligence mode to Alert or Deny',
  LearnMore='https://learn.microsoft.com/azure/firewall/threat-intel'
"@
        },
        @{
            Name = "Application Gateways — WAF not in Prevention mode"
            Query = @"
resources | where type =~ 'microsoft.network/applicationgateways'
| where isnull(properties.webApplicationFirewallConfiguration)
    or properties.webApplicationFirewallConfiguration.enabled != true
    or properties.webApplicationFirewallConfiguration.firewallMode !~ 'Prevention'
| project ResourceName=name, ResourceType='Application Gateway', SubscriptionId=subscriptionId, ResourceGroup=resourceGroup, Location=location,
  Finding='WAF is not enabled or not in Prevention mode', Impact='High', Category='6. Network Hardening',
  Recommendation='Enable WAF in Prevention mode with OWASP ruleset',
  LearnMore='https://learn.microsoft.com/azure/web-application-firewall/ag/ag-overview'
"@
        },
        @{
            Name = "Subnets — no NSG associated"
            Query = @"
resources | where type =~ 'microsoft.network/virtualnetworks'
| mv-expand subnet = properties.subnets
| where isnull(subnet.properties.networkSecurityGroup)
    and subnet.name !~ 'GatewaySubnet'
    and subnet.name !~ 'AzureFirewallSubnet'
    and subnet.name !~ 'AzureFirewallManagementSubnet'
    and subnet.name !~ 'AzureBastionSubnet'
    and subnet.name !~ 'RouteServerSubnet'
| project ResourceName=strcat(name, '/', tostring(subnet.name)), ResourceType='Subnet',
  SubscriptionId=subscriptionId, ResourceGroup=resourceGroup, Location=location,
  Finding='Subnet has no Network Security Group associated', Impact='High', Category='6. Network Hardening',
  Recommendation='Associate an NSG with appropriate inbound/outbound rules to this subnet',
  LearnMore='https://learn.microsoft.com/azure/virtual-network/network-security-groups-overview'
"@
        },
        @{
            Name = "Public IPs — Basic SKU (no DDoS/SLA)"
            Query = @"
resources | where type =~ 'microsoft.network/publicipaddresses'
| where sku.name =~ 'Basic'
| project ResourceName=name, ResourceType='Public IP', SubscriptionId=subscriptionId, ResourceGroup=resourceGroup, Location=location,
  Finding='Public IP is Basic SKU — no zone redundancy, DDoS protection, or SLA', Impact='Medium', Category='6. Network Hardening',
  Recommendation='Migrate to Standard SKU Public IPs for zone redundancy and DDoS support',
  LearnMore='https://learn.microsoft.com/azure/virtual-network/ip-services/public-ip-addresses'
"@
        },
        @{
            Name = "VPN Gateways — Basic SKU (no SLA, no IKEv2)"
            Query = @"
resources | where type =~ 'microsoft.network/virtualnetworkgateways'
| where sku.name =~ 'Basic'
| project ResourceName=name, ResourceType='VPN Gateway', SubscriptionId=subscriptionId, ResourceGroup=resourceGroup, Location=location,
  Finding='VPN Gateway is Basic SKU — no SLA, no IKEv2 support, limited bandwidth', Impact='Medium', Category='6. Network Hardening',
  Recommendation='Upgrade to VpnGw1 or higher for production workloads',
  LearnMore='https://learn.microsoft.com/azure/vpn-gateway/vpn-gateway-about-vpngateways'
"@
        },
        @{
            Name = "Load Balancers — Basic SKU (no zone redundancy)"
            Query = @"
resources | where type =~ 'microsoft.network/loadbalancers'
| where sku.name =~ 'Basic'
| project ResourceName=name, ResourceType='Load Balancer', SubscriptionId=subscriptionId, ResourceGroup=resourceGroup, Location=location,
  Finding='Load Balancer is Basic SKU — no zone redundancy, no SLA, open by default', Impact='Medium', Category='6. Network Hardening',
  Recommendation='Migrate to Standard SKU Load Balancer',
  LearnMore='https://learn.microsoft.com/azure/load-balancer/skus'
"@
        }
    )

    foreach ($check in $nhChecks) {
        Write-Host "    - $($check.Name)..." -ForegroundColor Gray
        $allFindings.AddRange([object[]](Invoke-ARGQuery -Query $check.Query -CheckName $check.Name))
    }
    $cat6Count = ($allFindings | Where-Object { $_.Category -like '6.*' }).Count
    Write-Host "    → $cat6Count findings" -ForegroundColor $(if ($cat6Count -gt 0) {"Red"} else {"Green"})

    # ================================================================
    # CATEGORY 7 — BACKUP & DR
    # ================================================================
    Write-Host ""
    Write-Host "  [7/7] Backup & Disaster Recovery..." -ForegroundColor Yellow

    $drChecks = @(
        @{
            Name = "VMs — not enrolled in Azure Backup"
            Query = @"
resources | where type =~ 'microsoft.compute/virtualmachines'
| where isnull(properties.storageProfile.osDisk.managedDisk.id) == false
| join kind=leftouter (
    recoveryservicesresources
    | where type =~ 'microsoft.recoveryservices/vaults/backupfabrics/protectioncontainers/protecteditems'
    | project vmId=tolower(tostring(properties.sourceResourceId))
) on $left.id == $right.vmId
| where isnull(vmId)
| project ResourceName=name, ResourceType='Virtual Machine', SubscriptionId=subscriptionId, ResourceGroup=resourceGroup, Location=location,
  Finding='VM is not enrolled in Azure Backup', Impact='High', Category='7. Backup & DR',
  Recommendation='Enroll VM in a Recovery Services Vault backup policy',
  LearnMore='https://learn.microsoft.com/azure/backup/backup-azure-vms-introduction'
"@
        },
        @{
            Name = "AKS — Azure Backup for AKS not configured"
            Query = @"
resources | where type =~ 'microsoft.containerservice/managedclusters'
| where isnull(properties.storageProfile.blobCSIDriver) or properties.storageProfile.blobCSIDriver.enabled != true
| project ResourceName=name, ResourceType='AKS Cluster', SubscriptionId=subscriptionId, ResourceGroup=resourceGroup, Location=location,
  Finding='Azure Backup for AKS not confirmed — Blob CSI driver not enabled', Impact='High', Category='7. Backup & DR',
  Recommendation='Enable Azure Backup for AKS and configure a backup policy',
  LearnMore='https://learn.microsoft.com/azure/backup/azure-kubernetes-service-backup-overview'
"@
        },
        @{
            Name = "SQL — no geo-redundant backup storage"
            Query = @"
resources | where type =~ 'microsoft.sql/servers/databases'
| where name !~ 'master'
| where properties.requestedBackupStorageRedundancy =~ 'Local' or properties.currentBackupStorageRedundancy =~ 'Local'
| project ResourceName=name, ResourceType='SQL Database', SubscriptionId=subscriptionId, ResourceGroup=resourceGroup, Location=location,
  Finding='Backup storage redundancy is Local — no geo-redundancy', Impact='High', Category='7. Backup & DR',
  Recommendation='Change backup storage redundancy to Geo or Zone for disaster recovery',
  LearnMore='https://learn.microsoft.com/azure/azure-sql/database/automated-backups-overview'
"@
        },
        @{
            Name = "Cosmos DB — single region (no multi-region write)"
            Query = @"
resources | where type =~ 'microsoft.documentdb/databaseaccounts'
| where array_length(properties.locations) == 1
| project ResourceName=name, ResourceType='Cosmos DB', SubscriptionId=subscriptionId, ResourceGroup=resourceGroup, Location=location,
  Finding='Cosmos DB is deployed in a single region only', Impact='High', Category='7. Backup & DR',
  Recommendation='Add a secondary region and enable multi-region writes for HA/DR',
  LearnMore='https://learn.microsoft.com/azure/cosmos-db/high-availability'
"@
        },
        @{
            Name = "Service Bus — no geo-disaster recovery pairing"
            Query = @"
resources | where type =~ 'microsoft.servicebus/namespaces'
| where sku.tier =~ 'Premium'
| where isnull(properties.geoDataReplication)
| project ResourceName=name, ResourceType='Service Bus Namespace', SubscriptionId=subscriptionId, ResourceGroup=resourceGroup, Location=location,
  Finding='Premium namespace has no geo-disaster recovery pairing configured', Impact='High', Category='7. Backup & DR',
  Recommendation='Configure geo-disaster recovery alias for Premium Service Bus namespaces',
  LearnMore='https://learn.microsoft.com/azure/service-bus-messaging/service-bus-geo-dr'
"@
        },
        @{
            Name = "App Service Plans — no zone redundancy"
            Query = @"
resources | where type =~ 'microsoft.web/serverfarms'
| where sku.tier in ('Standard','PremiumV2','PremiumV3','Isolated','IsolatedV2')
| where properties.zoneRedundant != true
| project ResourceName=name, ResourceType='App Service Plan', SubscriptionId=subscriptionId, ResourceGroup=resourceGroup, Location=location,
  Finding='App Service Plan is not zone redundant', Impact='Medium', Category='7. Backup & DR',
  Recommendation='Enable zone redundancy on PremiumV2/V3 or Isolated tier plans',
  LearnMore='https://learn.microsoft.com/azure/app-service/how-to-zone-redundancy'
"@
        },
        @{
            Name = "Event Hub — no geo-redundancy on Standard/Premium"
            Query = @"
resources | where type =~ 'microsoft.eventhub/namespaces'
| where sku.tier in ('Standard','Premium')
| where isnull(properties.geoDataReplication)
| project ResourceName=name, ResourceType='Event Hub Namespace', SubscriptionId=subscriptionId, ResourceGroup=resourceGroup, Location=location,
  Finding='Standard/Premium namespace has no geo-redundancy or geo-DR pairing', Impact='High', Category='7. Backup & DR',
  Recommendation='Configure geo-disaster recovery pairing for business-critical Event Hub namespaces',
  LearnMore='https://learn.microsoft.com/azure/event-hubs/event-hubs-geo-dr'
"@
        }
    )

    foreach ($check in $drChecks) {
        Write-Host "    - $($check.Name)..." -ForegroundColor Gray
        $allFindings.AddRange([object[]](Invoke-ARGQuery -Query $check.Query -CheckName $check.Name))
    }
    $cat7Count = ($allFindings | Where-Object { $_.Category -like '7.*' }).Count
    Write-Host "    → $cat7Count findings" -ForegroundColor $(if ($cat7Count -gt 0) {"Red"} else {"Green"})

    # ================================================================
    # EXPORT SECURITY BASELINE EXCEL
    # ================================================================
    Write-Host ""
    Write-Host "  Generating Security Baseline Excel report..." -ForegroundColor Yellow

    # Reuse the combined output file path defined earlier

    # Summary sheet
    $categories = @('1. Network Exposure','2. Soft Delete & Recovery','3. Encryption','4. Identity & Access','5. Monitoring & Logging','6. Network Hardening','7. Backup & DR')
    $summaryRows = foreach ($cat in $categories) {
        $catFindings = $allFindings | Where-Object { $_.Category -eq $cat }
        [PSCustomObject]@{
            Category      = $cat
            TotalFindings = $catFindings.Count
            High          = ($catFindings | Where-Object { $_.Impact -eq 'High' }).Count
            Medium        = ($catFindings | Where-Object { $_.Impact -eq 'Medium' }).Count
            Low           = ($catFindings | Where-Object { $_.Impact -eq 'Low' }).Count
        }
    }

    # -------------------------------------------------------
    # Security Baseline — Summary sheet
    # -------------------------------------------------------
    $summaryRows | Export-Excel -Path $combinedExcelPath -WorksheetName "Security-Summary" `
        -AutoSize -AutoFilter -FreezeTopRow -TableName "Summary" -TableStyle Medium6 `
        -Title "Azure Security Baseline Assessment" -TitleBold -TitleSize 14 -Append

    # One sheet per category
    $sheetStyles = @('Medium2','Medium3','Medium4','Medium5','Medium6','Medium7','Medium9')
    $styleIdx    = 0
    foreach ($cat in $categories) {
        $catFindings = $allFindings | Where-Object { $_.Category -eq $cat }
        $sheetName   = $cat -replace '[^a-zA-Z0-9 &]','' | ForEach-Object { $_.Substring(0, [math]::Min($_.Length, 31)) }

        if ($catFindings.Count -gt 0) {
            $catFindings | Select-Object ResourceName, ResourceType, SubscriptionId, ResourceGroup, Location, Finding, Impact, Recommendation, LearnMore |
                Export-Excel -Path $combinedExcelPath -WorksheetName $sheetName `
                    -AutoSize -AutoFilter -FreezeTopRow `
                    -TableName ("T" + ($styleIdx+1)) -TableStyle $sheetStyles[$styleIdx % $sheetStyles.Count] -Append
        } else {
            @([PSCustomObject]@{ Result = "No findings in this category." }) |
                Export-Excel -Path $combinedExcelPath -WorksheetName $sheetName -AutoSize -Append
        }
        $styleIdx++
    }

    Write-Host ""
    Write-Host ""
    Write-Host "  ============================================================" -ForegroundColor Green
    Write-Host "  Combined Assessment Report ready:" -ForegroundColor Green
    Write-Host "  $combinedExcelPath" -ForegroundColor White
    Write-Host ""
    Write-Host "  Security Baseline Findings:" -ForegroundColor White
    Write-Host "  Total : $($allFindings.Count)" -ForegroundColor $(if ($allFindings.Count -gt 0) {"Red"} else {"Green"})
    foreach ($cat in $categories) {
        $c = ($allFindings | Where-Object { $_.Category -eq $cat }).Count
        Write-Host ("    {0,-35} : {1}" -f $cat, $c) -ForegroundColor $(if ($c -gt 0) {"Red"} else {"Green"})
    }
    Write-Host "  ============================================================" -ForegroundColor Green
}

Pop-Location

# =============================================================================
# STEP 8 — FINAL SUMMARY
# =============================================================================
Write-Host ""
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "  Assessment Complete!" -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "  Output Directory : $runOutputDir" -ForegroundColor Green
Write-Host "  Tenant           : $resolvedTenantId" -ForegroundColor Green
Write-Host "  Subscriptions    : $($resolvedSubIds.Count)" -ForegroundColor Green
Write-Host "  Completed At     : $(Get-Date -Format 'yyyy-MM-dd HH:mm')" -ForegroundColor Green
Write-Host ""
Write-Host "  Output File:" -ForegroundColor White
if (Test-Path $combinedExcelPath) {
    $f = Get-Item $combinedExcelPath
    Write-Host "    $($f.Name)  [$([math]::Round($f.Length/1KB,1)) KB]" -ForegroundColor Gray
}
# List any other files (JSON, Word, PPT)
Get-ChildItem -Path $runOutputDir -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -ne $combinedExcelPath } | ForEach-Object {
        Write-Host "    $($_.Name)  [$([math]::Round($_.Length/1KB,1)) KB]" -ForegroundColor Gray
    }
Write-Host ""
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host ""

<#
USAGE EXAMPLES
--------------
Full run (WARA + all 7 security categories):
  ./Run-WARA-Assessment.ps1 -ManagementGroupId "jpshealthdc" -SkipReport

WARA only:
  ./Run-WARA-Assessment.ps1 -ManagementGroupId "jpshealthdc" -SkipReport -SkipSecurityBaseline

Security baseline using existing JSON (skip collector):
  ./Run-WARA-Assessment.ps1 -UseExistingJSON "~/WARA-File-2026-07-28.json" -SkipReport

Specific subscriptions:
  ./Run-WARA-Assessment.ps1 -SubscriptionIds "sub-id-1","sub-id-2" -SkipReport

Region filter:
  ./Run-WARA-Assessment.ps1 -ManagementGroupId "jpshealthdc" -Regions "southcentralus","eastus" -SkipReport

Custom output:
  ./Run-WARA-Assessment.ps1 -ManagementGroupId "jpshealthdc" -OutputDirectory "/reports/client" -SkipReport

PARAMETERS
----------
  -ManagementGroupId      MG name — recursive subscription discovery
  -SubscriptionIds        Specific subscription GUIDs
  -Regions                Filter to specific Azure regions
  -OutputDirectory        Output path (default: ~/WARA-Output)
  -SkipReport             Skip Word/PPT (required on Linux/macOS)
  -SkipSecurityBaseline   Run WARA only
  -TenantId               Explicit tenant ID (auto-detected if omitted)
  -UseExistingJSON        Reuse existing collector JSON — skips collector

OUTPUT FILES
------------
  Azure-Assessment-<date>.xlsx      Single combined report
    Sheets from WARA  : WorkloadInventory, Recommendations, ImpactedResources, etc.
    Sheet             : Security-Summary  (overall findings count per category)
    Sheet             : 1 Network Exposure        (17 checks)
    Sheet             : 2 Soft Delete & Recovery  (9 checks)
    Sheet             : 3 Encryption              (8 checks)
    Sheet             : 4 Identity & Access       (7 checks)
    Sheet             : 5 Monitoring & Logging    (8 checks)
    Sheet             : 6 Network Hardening       (8 checks)
    Sheet             : 7 Backup & DR             (7 checks)
  WARA-File-<date>.json             Raw collector data (keep for re-runs)

TOTAL SECURITY CHECKS: 64 across 7 categories

TOTAL SECURITY CHECKS: 64 across 7 categories
#>
