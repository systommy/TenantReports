# Changelog

All notable changes to TenantReports will be documented in this file.

## 1.1.0 - 2026-02-10

### Added
- Certificate authentication support for REST API connections (`Connect-TntGraphSession -ConnectionType RestApi`), enabling `Get-TntAzureSecureScoreReport` to work with certificate auth via JWT bearer assertion (RFC 7523)
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

## 1.0 - 2026-02-06

Initial release

