# Azure WARA Assessment Runner

A PowerShell script that automates the end-to-end execution of Microsoft's
**Well-Architected Reliability Assessment (WARA)** against any Azure tenant.
Automatically discovers subscriptions, runs the collector, and produces an
Excel Action Plan with all findings — no manual steps required.

Built and maintained by [Riyaz Hussain](https://github.com/riyazhussain) —
Associate Director of Infrastructure & Cloud Architecture at Kyndryl.

---

## What It Does

```
Auto-discover subscriptions  →  WARA Collector  →  WARA Analyzer  →  Excel Action Plan
        (MG recursive)            (Azure ARG)        (findings)       (.xlsx report)
```

The Excel output contains:
- **Dashboard** — summary by pillar (Reliability, Monitoring, DR, Networking, etc.)
- **Recommendations** — every APRL finding with impact level and remediation guidance
- **Impacted Resources** — specific Azure resource IDs per finding
- **Workload Inventory** — full resource inventory across all subscriptions

---

## Prerequisites

| Requirement | Notes |
|---|---|
| PowerShell 7+ | [Install guide](https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell) |
| Azure Reader role | On each subscription or at Management Group level |
| Internet access | To install modules from PSGallery |

The script auto-installs these PowerShell modules on first run:
- `Az.Accounts`
- `Az.ResourceGraph`
- `WARA` (Microsoft's official module from PSGallery)
- `ImportExcel`

---

## Quick Start

```powershell
# 1. Clone this repo
git clone https://github.com/<your-username>/wara-azure-assessment.git
cd wara-azure-assessment

# 2. Run against a Management Group (recommended)
./Run-WARA-Assessment.ps1 -ManagementGroupId "your-mg-name"

# 3. On Linux/macOS — skip the Word/PPT report step
./Run-WARA-Assessment.ps1 -ManagementGroupId "your-mg-name" -SkipReport
```

Output lands in `~/WARA-Output/WARA-Run-<timestamp>/`

---

## Usage Examples

```powershell
# Full tenant sweep — all enabled subscriptions
./Run-WARA-Assessment.ps1

# Scope to a Management Group (recursive — picks up all nested subs)
./Run-WARA-Assessment.ps1 -ManagementGroupId "mg-production"

# Specific subscriptions only
./Run-WARA-Assessment.ps1 -SubscriptionIds "sub-id-1","sub-id-2","sub-id-3"

# Filter by Azure region
./Run-WARA-Assessment.ps1 -ManagementGroupId "mg-corp" -Regions "eastus","southcentralus"

# Custom output path (useful for client engagements)
./Run-WARA-Assessment.ps1 -ManagementGroupId "mg-corp" -OutputDirectory "/reports/contoso"

# Skip Word/PPT report — Excel only (required on Linux/macOS)
./Run-WARA-Assessment.ps1 -ManagementGroupId "mg-corp" -SkipReport

# Multi-tenant: specify tenant explicitly
./Run-WARA-Assessment.ps1 -TenantId "your-tenant-guid" -ManagementGroupId "mg-corp"
```

---

## Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-ManagementGroupId` | string | — | MG name for recursive sub discovery |
| `-SubscriptionIds` | string[] | — | Specific subscription GUIDs |
| `-Regions` | string[] | — | Filter to specific Azure regions |
| `-OutputDirectory` | string | `~/WARA-Output` | Where to write JSON and Excel |
| `-SkipReport` | switch | false | Skip Word/PPT step (use on Linux/macOS) |
| `-TenantId` | string | auto-detected | Explicit tenant ID for multi-tenant use |

---

## How It Works

The script runs Microsoft's official WARA toolchain in sequence:

### Step 1 — Subscription Discovery
Recursively walks the Management Group hierarchy to collect all subscription IDs.
Falls back to `Get-AzSubscription` if MG walk returns empty.

### Step 2 — WARA Collector (`Start-WARACollector`)
Queries **Azure Resource Graph** across all subscriptions using APRL
(Azure Proactive Resiliency Library) KQL queries. Produces a JSON file
with raw findings data. Runtime: ~5–20 minutes depending on estate size.

### Step 3 — WARA Analyzer (`Start-WARAAnalyzer`)
Processes the JSON and generates the **Expert-Analysis Excel workbook** —
this is your primary deliverable. The script pauses after the collector
and shows you the JSON path before proceeding, so you can verify.

### Step 4 — WARA Report Generator (`Start-WARAReport`) *(Windows only)*
Generates a Word assessment report and PowerPoint executive summary.
Automatically skipped on Linux/macOS (use `-SkipReport` to be explicit).

---

## Output Files

```
~/WARA-Output/
└── WARA-Run-20260728-2125/
    ├── WARA-File-2026-07-28-21-25.json       ← raw collector data
    ├── Expert-Analysis-2026-07-28.xlsx        ← PRIMARY DELIVERABLE (Excel)
    ├── Assessment-Report-2026-07-28.docx      ← Windows only
    └── Executive-Summary-2026-07-28.pptx      ← Windows only
```

---

## Permissions Required

| Scope | Role | Purpose |
|---|---|---|
| Subscription | Reader | Query resource graph |
| Management Group | Management Group Reader | Recursive sub discovery |

No write permissions needed — this is a read-only assessment.

---

## Platform Support

| Platform | Collector | Analyzer (Excel) | Report (Word/PPT) |
|---|---|---|---|
| Windows | ✅ | ✅ | ✅ |
| Linux | ✅ | ✅ | ❌ (skip with `-SkipReport`) |
| macOS | ✅ | ✅ | ❌ (skip with `-SkipReport`) |

---

## Troubleshooting

**`Found 0 subscriptions under MG`**
The MG may only contain child MGs, not direct subscriptions. The script
handles this recursively. If it still returns 0, check your account has
Management Group Reader role.

**`Logged in as MSI@50342`**
You're authenticated via a Managed Service Identity (VM/container). This
works as long as the MSI has Reader scope. If subscriptions aren't found,
run `Connect-AzAccount -UseDeviceAuthentication` to log in as yourself.

**`No WARA JSON output found`**
The collector may have written the file to a different directory. The
script searches `runOutputDir`, current directory, and `$HOME` automatically.
You can also run the analyzer manually:
```powershell
Import-Module WARA
Start-WARAAnalyzer -JSONFile "/path/to/WARA-File-<date>.json"
```

**`Report generator failed`**
Expected on Linux/macOS — Word and PowerPoint COM automation is Windows-only.
Your Excel Action Plan is the equivalent deliverable.

---

## Credits

- **Microsoft WARA Module** — [PSGallery: WARA](https://www.powershellgallery.com/packages/WARA)
- **Azure Proactive Resiliency Library** — [GitHub: Azure/Azure-Proactive-Resiliency-Library-v2](https://github.com/Azure/Azure-Proactive-Resiliency-Library-v2)

---

## License

MIT — free to use, modify, and distribute for any Azure tenant or client engagement.
