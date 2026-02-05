# TenantReports

A PowerShell module for generating Microsoft 365 and Azure security reports.

## Why This Module?

After years in the MSP space as a SysAdmin and Consultant, I noticed a growing trend: clients increasingly want periodic security and compliance reports for their Microsoft 365 tenants. What started as manual data gathering became repetitive, time-consuming work.

TenantReports automates this process. Connect once, run a single command, and get a complete security posture assessment—Secure Score, Conditional Access, Intune compliance, privileged access, and more.

## Quick Start

Get your first report in under a minute—no app registration required.

> **Requires PowerShell 7.** Run `$PSVersionTable.PSVersion` to check. [Download PowerShell 7](https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell)

```powershell
Install-Module TenantReports -Scope CurrentUser
Import-Module TenantReports

$Report = Invoke-TntReport -Interactive
```

A browser window opens for sign-in. **Make usre to authenticate with an account that has Global Administrator permissions.** The module handles permissions, authentication, and session management automatically.

> **Don't worry about errors.** If a section fails due to missing permissions or disabled features, the report continues. Check `$Report.ReportMetadata.SectionStatus` to see what succeeded—most sections will work out of the box.

## What You Get

- **24 report functions** covering identity, devices, email security, and cloud infrastructure
- **One command** (`Invoke-TntReport`) runs everything and consolidates results
- **Flexible output** — pipe to JSON, CSV, or use directly in scripts
- **Graceful error handling** — missing permissions or disabled features won't break your report; affected sections return warnings while everything else continues
- **Multiple auth methods** — interactive sign-in for quick runs, app registration for automation

### Interactive Mode Limitations

Two sections require application-level permissions and are skipped in interactive mode:

| Section | Reason |
|---------|--------|
| `RiskyUsers` | Requires `IdentityRiskyUser.Read.All` application permission |
| `Defender` | Requires application-level Defender for Office 365 permissions |

Everything else works with interactive authentication.

## Installation

### From PowerShell Gallery

```powershell
Install-Module TenantReports -Scope CurrentUser
```

### Dependencies

The module requires several Microsoft Graph modules. Install them once:

```powershell
# Required modules
$Modules = @(
    'ExchangeOnlineManagement'
    'Microsoft.Graph.Applications'
    'Microsoft.Graph.Authentication'
    'Microsoft.Graph.Beta.Security'
    'Microsoft.Graph.Beta.Users'
    'Microsoft.Graph.DeviceManagement'
    'Microsoft.Graph.Groups'
    'Microsoft.Graph.Identity.DirectoryManagement'
    'Microsoft.Graph.Identity.Governance'
    'Microsoft.Graph.Identity.SignIns'
    'Microsoft.Graph.Reports'
    'Microsoft.Graph.Security'
    'Microsoft.Graph.Users'
)

$Modules | ForEach-Object { Install-Module $_ -Scope CurrentUser -Force }
```

> **Note:** The first `Import-Module TenantReports` may take 10-20 seconds as all dependencies are loaded via the module manifest. Subsequent imports in the same session are instant.

## Web Viewer

The JSON output from `Invoke-TntReport` can be visualized with the **TenantReports Web Viewer**—a static web application that transforms your report into interactive dashboards.

Check it out: https://report.systom.dev

![Report](https://publish-01.obsidian.md/access/3c68c4742e522d2b43b9a86ed6f0f7de/posts/msedge_B1Av7TkWMX.gif)

### Features

- Interactive charts and visualizations
- Filterable data tables
- Executive summary views
- Export to PDF for client deliverables
- Works entirely client-side—no data leaves your browser

### Generate and View

```powershell
# Generate the report
$Report = Invoke-TntReport -Interactive

# Export to JSON
$Report | ConvertTo-Json -Depth 20 | Out-File 'TenantReport.json'
```

Visit https://report.systom.dev and load the JSON file. Your security dashboard is ready.

> **Blog post coming soon** — A detailed walkthrough of the Web Viewer and how to use it for client reporting.

## Automation

Interactive mode is great for ad-hoc reports. For scheduled or unattended runs, set up an Azure AD App Registration.

### Quick Setup

The module includes a setup script that creates and configures everything:

```powershell
.\Setup\New-TenantReportsAppRegistration.ps1 -TenantId "your-tenant-id" -CreateClientSecret -AssignDirectoryRoles
```

This creates an app registration with all required permissions, grants admin consent, and outputs a client secret.

> **Save the output!** The client secret is only displayed once.

### Running Automated Reports

```powershell
$ReportParams = @{
    TenantId     = 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'
    ClientId     = 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'
    ClientSecret = ConvertTo-SecureString 'your-secret' -AsPlainText -Force
}

$Report = Invoke-TntReport @ReportParams
```

### Additional Options

Include audit logs and mailbox analysis for deeper insights:

```powershell
$Report = Invoke-TntReport @ReportParams -IncludeAuditReports -IncludeMailboxPermissions -IncludeCalendarPermissions
```

Run specific sections only:

```powershell
# Include only what you need
$Report = Invoke-TntReport @ReportParams -IncludeSections @('SecureScore', 'ConditionalAccess', 'Users')

# Or exclude specific sections
$Report = Invoke-TntReport @ReportParams -ExcludeSections @('MailboxPermissions', 'CalendarPermissions')
```

## Available Reports

| Function | Description |
|----------|-------------|
| `Invoke-TntReport` | Runs all reports and consolidates results |
| **Tenant & Configuration** | |
| `Get-TntOrganizationReport` | Tenant details and directory statistics |
| `Get-TntConfigurationReport` | Tenant-wide settings and policies |
| `Get-TntLicenseReport` | License allocation and usage |
| `Get-TntLicenseChangeAuditReport` | License assignment and removal history |
| **Identity & Access** | |
| `Get-TntM365UserReport` | User accounts, sign-in activity, MFA status |
| `Get-TntM365RiskyUserReport` | Risky users from Identity Protection |
| `Get-TntPrivilegedRoleReport` | Privileged role assignments and break-glass accounts |
| `Get-TntPIMReport` | Privileged Identity Management configuration |
| `Get-TntConditionalAccessReport` | Conditional Access policy analysis |
| **App Registrations & Service Principals** | |
| `Get-TntServicePrincipalPermissionReport` | App registrations and permission grants |
| `Get-TntAppRegistrationExpiryReport` | Credential and certificate expiration |
| **Security Scores** | |
| `Get-TntM365SecureScoreReport` | Microsoft 365 Secure Score with trends |
| `Get-TntAzureSecureScoreReport` | Azure Security Center score |
| **Devices** | |
| `Get-TntIntuneDeviceComplianceReport` | Device compliance status |
| `Get-TntIntuneAppleCertificateReport` | Apple DEP/APNS certificate expiration |
| **Email & Exchange** | |
| `Get-TntDefenderEmailThreatReport` | Email threats from Defender for Office 365 |
| `Get-TntExchangeMailboxPermissionReport` | Mailbox delegation permissions |
| `Get-TntExchangeCalendarPermissionReport` | Calendar folder permissions |
| `Get-TntSharedMailboxComplianceReport` | Shared mailbox compliance |
| `Get-TntInboxForwardingRuleReport` | External forwarding rules |
| **Security & Audit** | |
| `Get-TntM365AuditEvent` | Microsoft 365 and Azure AD audit events |
| `Get-TntDefenderIncidentReport` | Defender incidents |

Run any report individually with `-Interactive` or with app registration credentials.

## Troubleshooting

### Some report sections returned `$null`

This is normal. Check what succeeded and what didn't:

```powershell
$Report.ReportMetadata.SectionStatus
```

Common reasons for skipped sections:
- **Exchange reports** — Requires Exchange Administrator role
- **Defender reports** — Requires Defender for Office 365 to be enabled
- **Azure Secure Score** — Requires Azure subscriptions linked to the tenant
- **RiskyUsers** — Requires application permissions (not available in interactive mode)

### Microsoft Graph module conflicts

If you see assembly loading errors like `Could not load file or assembly 'Microsoft.Graph.Authentication'`, you likely have multiple versions installed.

Clean up and reinstall:

```powershell
# Remove all Graph modules
Get-InstalledModule Microsoft.Graph* | Uninstall-Module -AllVersions -Force

# Restart PowerShell, then reinstall
$Modules = @(
    'Microsoft.Graph.Applications'
    'Microsoft.Graph.Authentication'
    # ... (see Installation section for full list)
)
$Modules | ForEach-Object { Install-Module $_ -Scope CurrentUser -Force }
```

### App registration errors

| Error | Solution |
|-------|----------|
| `AADSTS700016: Application not found` | Verify ClientId matches your app registration |
| `AADSTS7000215: Invalid client secret` | Secret may be expired—create a new one in Azure Portal |
| `Insufficient privileges` | Grant admin consent for all API permissions |

## Contributing

Found a bug or have a feature request? Open an issue on [GitHub](https://github.com/systommy/TenantReports/issues).

Pull requests are welcome.

## Author

**Tom de Leeuw**

- Website: [systom.dev](https://systom.dev)
- GitHub: [@systommy](https://github.com/systommy)

## License

MIT License — see [LICENSE](LICENSE) for details.
