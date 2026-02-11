# Changelog

All notable changes to TenantReports will be documented in this file.

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

