# Microsoft-Purview-Information-Protection-Scanner-Automation
## Overview

This repository contains a customer-focused deployment toolkit for the Microsoft Purview Information Protection Scanner.

The toolkit is designed to simplify and standardize scanner deployments by automating:

- Microsoft Purview Information Protection Client installation
- Trusted Sites configuration
- Scanner installation
- SQL database creation
- Microsoft Entra App Registration creation
- Scanner authentication
- Optional Azure Rights Management Super User configuration
- Deployment validation
- Initial scan readiness testing

---

## Supported Scenarios

✅ Discovery Mode Deployments

✅ Auto-Labeling Deployments

✅ Azure RMS Protected Content Scanning

✅ Single Scanner Deployments

✅ Multi-Node Scanner Clusters

✅ SQL Express, Standard, and Enterprise

✅ SMB Repositories

✅ SharePoint Server Repositories

---

## Repository Contents

| Item | Description |
|--------|------------|
| Install-PurviewScanner.ps1 | Main deployment script |
| Deployment Guide | Complete deployment instructions |

---

## Deployment Workflow

### Phase 1 - Preparation

- Review prerequisites
- Complete deployment worksheet
- Verify SQL access
- Verify service account permissions
- Confirm labels and policies are published

### Phase 2 - Client Validation

- Install Purview Information Protection client
- Configure Trusted Sites
- Sign in using scanner account
- Validate label visibility

### Phase 3 - Scanner Installation

- Install scanner service
- Create SQL database
- Verify scanner service status

### Phase 4 - Authentication

- Create App Registration
- Configure API permissions
- Grant admin consent
- Create client secret
- Execute Set-Authentication

### Phase 5 - Validation

- Run diagnostics
- Verify scanner health
- Start discovery scan

---

## Requirements

### Windows Server

- Windows Server 2016+
- 4 CPU cores minimum
- 8 GB RAM minimum

### SQL Server

- SQL Express
- SQL Standard
- SQL Enterprise

### Microsoft Roles

One of:

- Compliance Administrator
- Compliance Data Administrator
- Security Administrator
- Organization Management

---

## Recommended Deployment Strategy

1. Start in Discovery Mode.
2. Review scanner reports.
3. Validate detections.
4. Confirm exclusions.
5. Review customer findings.
6. Enable enforcement only after approval.

---

## Troubleshooting

### Failed To Access Scanner Database

See:

```text
Troubleshooting/ScannerDatabaseIssues.md
```

### Set-Authentication Fails

See:

```text
Troubleshooting/AuthenticationIssues.md
```

### Labels Not Appearing

Verify:

- Label publication
- Scanner account assignment
- Policy download
- Trusted Sites configuration

---

## Validation Commands

```powershell
Get-Service MIPScanner

Get-ScannerConfiguration

Get-ScanStatus

Start-ScannerDiagnostics
```

Run a test scan:

```powershell
Start-Scan

Get-ScanStatus
```

---

## Documentation

Full deployment guide:

```text
Docs/Microsoft-Purview-Scanner-Deployment-Guide.docx
```

---

## Disclaimer

This project is provided as a deployment accelerator for Microsoft Purview Information Protection Scanner installations.

Always validate configuration, permissions, and security requirements against the latest Microsoft Learn documentation before production deployment.
