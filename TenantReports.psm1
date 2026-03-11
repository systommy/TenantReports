# Get public and private function definition files.
$Private = (Get-ChildItem -Path (Join-Path $PSScriptRoot 'Private') -Filter *.ps1 -Recurse)
$Public = (Get-ChildItem -Path (Join-Path $PSScriptRoot 'Public') -Filter *.ps1 -Recurse)

# Load private scripts first
$Private | ForEach-Object {
    try {
        Write-Verbose "Loading $($_.FullName)"
        . $_.FullName
    } catch {
        Write-Warning $_.Exception.Message
    }
}

$Public | ForEach-Object {
    try {
        Write-Verbose "Loading $($_.FullName)"
        . $_.FullName
    } catch {
        Write-Warning $_.Exception.Message
    }
}

# Script variables used across multiple functions
$script:ValidConnectionParams = @(
    'TenantId'
    'ClientId'
    'ClientSecret'
    'CertificateThumbprint'
    'ApplicationId'
    'Scopes'
    'WithSecureClientId'
    'WithSecureClientSecret'
    'TenantName'
    'UseManagedIdentity'
    'Interactive'
)

# User cache for cross-function sharing (tenant-aware)
$script:UserCache = @{}

# Privileged role names for PIM and role assignment reports
$script:PrivilegedRoleNames = @(
    'Global Administrator',
    'Privileged Role Administrator',
    'Security Administrator',
    'Exchange Administrator',
    'SharePoint Administrator',
    'User Administrator',
    'Application Administrator',
    'Cloud Application Administrator',
    'Authentication Administrator',
    'Privileged Authentication Administrator',
    'Conditional Access Administrator'
)

# Well-known Microsoft application IDs (no API call needed for display name resolution)
$script:WellKnownAppIds = @{
    '00000002-0000-0000-c000-000000000000' = 'Azure AD Graph (Legacy)'
    '00000003-0000-0000-c000-000000000000' = 'Microsoft Graph'
    '00000002-0000-0ff1-ce00-000000000000' = 'Office 365 Exchange Online'
    '00000003-0000-0ff1-ce00-000000000000' = 'Office 365 SharePoint Online'
    '00000004-0000-0ff1-ce00-000000000000' = 'Office 365 Lync Online'
    '797f4846-ba00-4fd7-ba43-dac1f8f63013' = 'Azure Service Management'
    'c5393580-f805-4401-95e8-94b7a6ef2fc2' = 'Office 365 Management APIs'
    '0000000c-0000-0000-c000-000000000000' = 'Azure AD'
    '00000001-0000-0000-c000-000000000000' = 'Microsoft Graph (Classic)'
}

# Security cleanup on module removal
$ExecutionContext.SessionState.Module.OnRemove = {
    Write-Verbose 'TenantReports module being removed - performing security cleanup'
    try {
        # Clear any remaining secure tokens and user cache
        Clear-SecureMemory -Variables @('AccessToken', 'GraphHeader', 'TokenInfo', 'SecureAccessToken', 'GetSecureAuthHeader', 'TokenCache', 'UserCache') -Scope Script
        Write-Verbose 'Security cleanup completed successfully'
    } catch {
        Write-Warning "Error during security cleanup: $($_.Exception.Message)"
    }
}

Export-ModuleMember -Function $Public.Basename