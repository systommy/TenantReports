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

    # These MUST match the section keys defined in Invoke-TntReport's $AvailableSections.
    # Always-available sections first, then the parameter-gated sections.
    @(
        'TenantInfo',
        'TenantConfiguration',
        'LicenseAllocation',
        'ConditionalAccess',
        'SecureScore',
        'AzureSecureScore',
        'Users',
        'RiskyUsers',
        'PrivilegedRoles',
        'PIM',
        'Intune',
        'ServicePrincipals',
        'DefenderIncidents',
        'DefenderEmail',
        'EmailActivity',
        'Apple',
        'LicenseChangeAudit',
        'AppRegistrationExpiry',

        # Added only when -IncludeAuditReports is specified
        'GroupMembershipAudit',
        'UserCreationAudit',

        # Added only when -IncludeMailboxPermissions is specified
        'MailboxPermissions',
        'SharedMailboxCompliance',
        'InboxForwardingRules',

        # Added only when -IncludeCalendarPermissions is specified
        'CalendarPermissions'
    )
}
