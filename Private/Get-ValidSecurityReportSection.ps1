function Get-ValidSecurityReportSection {
    <#
    .SYNOPSIS
        Returns list of valid security report sections.

    .DESCRIPTION
        Provides enumeration of all available report sections for use with
        -IncludeSections and -ExcludeSections parameters in Invoke-SecurityReport.

        This function is primarily used for parameter validation and tab completion.

    .OUTPUTS
        System.String[]
        Returns an array of valid section names.

    .EXAMPLE
        Get-ValidSecurityReportSection

        Returns all available section names.

    .NOTES
        Website: https://systom.dev
        Module: TenantReports

        This list should be updated whenever new report functions are added to the module.

    .LINK
        https://systom.dev
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param()

    @(
        'TenantInfo',
        'LicenseAllocation',
        'ConditionalAccess',
        'SecureScore',
        'AzureSecureScore',
        'Users',
        'RiskyUsers',
        'PrivilegedAccess',
        'ServicePrincipals',
        'Intune',
        'DefenderIncidents',
        'Defender',
        'Apple',
        'GroupMembershipAudit',
        'UserCreationAudit',
        'MailboxPermissions',
        'CalendarPermissions',
        'SharedMailboxCompliance',
        'InboxForwardingRules',
        'LicenseChangeAudit',
        'AppRegistrationExpiry',
        'WithSecureEndpoints'
    )
}
