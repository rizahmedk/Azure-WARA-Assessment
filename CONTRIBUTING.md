# Contributing

Contributions welcome — bug fixes, new parameters, better error handling, documentation.

## How to contribute

1. Fork the repo
2. Create a branch: `git checkout -b fix/your-description`
3. Make your changes to `Run-WARA-Assessment.ps1`
4. Test against a real Azure tenant (Reader access required)
5. Open a pull request with a description of what you changed and why

## Testing checklist before PR

- [ ] Script runs on **Linux** (PowerShell 7+)
- [ ] Script runs on **Windows** (PowerShell 7+)
- [ ] `-ManagementGroupId` parameter works
- [ ] `-SubscriptionIds` parameter works
- [ ] `-SkipReport` works on Linux without errors
- [ ] JSON is found after collector and path is printed clearly
- [ ] Excel is produced by the analyzer and path is printed clearly
- [ ] No hardcoded paths or tenant-specific values

## Reporting issues

Open a GitHub Issue with:
- PowerShell version (`$PSVersionTable.PSVersion`)
- OS (Windows / Linux / macOS)
- Full error output
- Which parameter combination you used
