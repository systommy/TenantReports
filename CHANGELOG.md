# Changelog

All notable changes to TenantReports will be documented in this file.

## 1.1.1 - 2026-02-23

### Fixed

- Fix interactive auth: replace Connect-MgGraph device code with REST-based flow

## Updated

- Get-TntDefenderEmailThreatReport: Split Email activity data into new function: Get-TntM365EmailActivityReport
- Renamed Incidents property to Alerts in Get-TntDefenderEmailThreatReport return object (variable $IncidentData → $Alerts); updated .DESCRIPTION and .OUTPUTS accordingly
- Updated .DESCRIPTION of Get-TntDefenderEmailThreatReport to clarify it returns individual alert-level detections from /security/alerts_v2, not Defender incidents; added cross-reference to Get-TntDefenderIncidentReport
- Updated .DESCRIPTION of Get-TntDefenderIncidentReport to clarify incidents are correlated attack investigations spanning email, endpoint, and identity; added cross-reference to Get-TntDefenderEmailThreatReport
- Expanded Get-TntDefenderIncidentReport incident detail object with six new properties: Determination, AssignedTo, LastModifiedDateTime, IncidentUrl, Tags, TenantId; updated .DESCRIPTION and .OUTPUTS to reflect richer output

## 1.1.0 - 2026-02-10

### Added
- Certificate authentication support
- Certificate credential support in setup script (`New-TenantReportsAppRegistration.ps1`)
- `CertificateThumbprint` parameter set on `Get-GraphToken` for token acquisition using client certificate credentials
- JWT bearer assertion construction in `Get-GraphToken`: RSA-SHA256 signing, x5t/x5t#S256 thumbprint headers, secure memory cleanup
- Certificate-specific troubleshooting guidance in token error messages
- Tenant domain resolution for Exchange Online certificate auth in `Get-TntExchangeMailboxPermissionReport`, `Get-TntInboxForwardingRuleReport`, and `Get-TntSharedMailboxComplianceReport` (Exchange requires a domain name, not a GUID, when using certificate auth)
- Shared mailbox coverage in `Get-TntInboxForwardingRuleReport` — now checks both `UserMailbox` and `SharedMailbox` for external forwarding rules

### Fixed
- Exchange Online connection failures when using certificate auth in 3 of 4 Exchange functions (MailboxPermission, InboxForwarding, SharedMailboxCompliance) — `-Organization` was passed a tenant GUID instead of a domain name
- `Get-TntExchangeCalendarPermissionReport` no longer resolves tenant domain unnecessarily for client secret auth (domain resolution now only runs for certificate auth)
- Misleading summary message in `Get-TntInboxForwardingRuleReport` ("across 0 mailboxes") replaced with total checked and rules found
- Summary message in `Get-TntLicenseChangeAuditReport` simplified to avoid misleading count

### Performance
- Replaced in-memory pipeline filters/transforms (`Where-Object` / `ForEach-Object`) with `.Where()` / `.ForEach()` or `foreach` where appropriate.
- Kept intentional pipeline usage for `ForEach-Object -Parallel` and example-only snippets.
- Cached current time in loop-heavy paths (`[DateTime]::Now` / `[datetime]::UtcNow`) to reduce repeated `Get-Date` overhead.
- Replaced array `+=` accumulation in loop paths with generic list `.Add()` / `.AddRange()`.
- Completed regex optimization for repeated loop matching with compiled regex patterns.

## Error-handling consistency
- Updated `Connect-TntGraphSession` to follow module-standard terminating error handling.
- Replaced ad-hoc `throw`/`Write-Error` patterns in key control paths with structured `ErrorRecord` creation and `$PSCmdlet.ThrowTerminatingError(...)`.
- Preserved existing diagnostic warnings and guidance while ensuring terminating behavior is consistent.

## Cleanups
- Cleaned up comment-based help (CBH) sections and removed obsolete/unneeded comments.

## 1.0 - 2026-02-06

Initial release

