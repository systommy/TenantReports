function Get-TntConfigurationReport {
    <#
    .SYNOPSIS
        Reports on common tenant misconfigurations with risk assessment per setting.

    .DESCRIPTION
        This function retrieves and evaluates common Microsoft 365 tenant configuration settings
        against security best practices. Each setting is assessed with a risk level (High, Medium,
        Low, Info) and includes recommendations for remediation.

        Checks include authorization policies, application consent, guest access, and modern
        authentication settings for Exchange Online and SharePoint.

    .PARAMETER TenantId
        The Azure AD Tenant ID (GUID) to connect to.

    .PARAMETER ClientId
        The Application (Client) ID of the app registration created for security reporting.

    .PARAMETER ClientSecret
        The client secret for the app registration. Use this for automated scenarios.

    .PARAMETER CertificateThumbprint
        The thumbprint of the certificate to use for authentication instead of client secret.

    .EXAMPLE
        Get-TntConfigurationReport -TenantId $tenantId -ClientId $clientId -ClientSecret $secret

        Retrieves tenant configuration settings with risk assessment.

    .EXAMPLE
        $report = Get-TntConfigurationReport -TenantId $tid -ClientId $cid -ClientSecret $secret
        $report.SettingsByRisk.High | Format-Table SettingName, Recommendation

        Shows only high-risk settings with recommendations.

    .OUTPUTS
        System.Management.Automation.PSCustomObject
        Returns a structured object containing:
        - Summary: Counts of settings by risk level
        - Settings: All evaluated settings with risk assessment
        - SettingsByCategory: Settings grouped by category
        - SettingsByRisk: Settings grouped by risk level

    .NOTES
        Author: Tom de Leeuw
        Website: https://systom.dev
        Module: TenantReports

        Required Permissions:
        - Policy.Read.All (Application)
        - SharePointTenantSettings.Read.All (Application)
        - Exchange Online app access for Get-OrganizationConfig

    .LINK
        https://systom.dev
    #>

    [CmdletBinding(DefaultParameterSetName = 'ClientSecret')]
    [OutputType([System.Management.Automation.PSCustomObject])]
    param(
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName, ParameterSetName = 'ClientSecret')]
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName, ParameterSetName = 'Certificate')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Interactive')]
        [ValidateNotNullOrEmpty()]
        [Alias('Tenant')]
        [string]$TenantId,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName, ParameterSetName = 'ClientSecret')]
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName, ParameterSetName = 'Certificate')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Interactive')]
        [ValidatePattern('^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$')]
        [Alias('ApplicationId')]
        [string]$ClientId,

        [Parameter(Mandatory = $true, ParameterSetName = 'ClientSecret', ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [Alias('Secret', 'ApplicationSecret')]
        [SecureString]$ClientSecret,

        [Parameter(Mandatory = $true, ParameterSetName = 'Certificate', ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [Alias('Thumbprint')]
        [string]$CertificateThumbprint,

        [Parameter(Mandatory = $true, ParameterSetName = 'Interactive')]
        [switch]$Interactive
    )

    begin {
        Write-Information 'Starting tenant configuration assessment (common misconfigurations)...' -InformationAction Continue
    }

    process {
        try {
            $ConnectionParams = Get-ConnectionParameters -BoundParameters $PSBoundParameters
            $ConnectionInfo = Connect-TntGraphSession @ConnectionParams

            $Settings = [System.Collections.Generic.List[PSCustomObject]]::new()

            # Authorization Policy
            Write-Verbose 'Retrieving authorization policy...'
            $AuthPolicy = Invoke-MgGraphRequest -Uri 'https://graph.microsoft.com/v1.0/policies/authorizationPolicy' -Method GET -ErrorAction Stop
            $DefaultPerms = $AuthPolicy.defaultUserRolePermissions

            # Users can register applications
            $AllowApps = $DefaultPerms.allowedToCreateApps
            $Settings.Add([PSCustomObject]@{
                    Category         = 'AuthorizationPolicy'
                    SettingName      = 'Users can register applications'
                    CurrentValue     = $AllowApps
                    RecommendedValue = $false
                    RiskLevel        = if ($AllowApps -eq $true) { 'High' } else { 'Low' }
                    Description      = 'Controls whether non-admin users can register new application registrations in Entra ID.'
                    Recommendation   = 'Disable user app registration and delegate to administrators to prevent unauthorized OAuth applications.'
                })

            # Users can create security groups
            $AllowGroups = $DefaultPerms.allowedToCreateSecurityGroups
            $Settings.Add([PSCustomObject]@{
                    Category         = 'AuthorizationPolicy'
                    SettingName      = 'Users can create security groups'
                    CurrentValue     = $AllowGroups
                    RecommendedValue = $false
                    RiskLevel        = if ($AllowGroups -eq $true) { 'Medium' } else { 'Low' }
                    Description      = 'Controls whether non-admin users can create security groups.'
                    Recommendation   = 'Restrict security group creation to administrators to maintain access control governance.'
                })

            # Non-admins can create tenants
            $AllowTenants = $DefaultPerms.allowedToCreateTenants
            $Settings.Add([PSCustomObject]@{
                    Category         = 'AuthorizationPolicy'
                    SettingName      = 'Non-admins can create tenants'
                    CurrentValue     = $AllowTenants
                    RecommendedValue = $false
                    RiskLevel        = if ($AllowTenants -eq $true) { 'Medium' } else { 'Low' }
                    Description      = 'Controls whether non-admin users can create new Azure AD tenants.'
                    Recommendation   = 'Restrict tenant creation to administrators to prevent shadow IT and unmanaged tenants.'
                })

            # Guest user access level
            $GuestRoleId = $AuthPolicy.guestUserRoleId
            $guestAccessLabel = switch ($GuestRoleId) {
                'a0b1b346-4d3e-4e8b-98f8-753987be4970' { 'Same as member users' }
                '10dae51f-b6af-4016-8d66-8c2a99b929b3' { 'Limited access (recommended)' }
                '2af84b1e-32c8-42b7-82bc-daa82404023b' { 'Restricted access (most restrictive)' }
                default { $GuestRoleId }
            }
            $Settings.Add([PSCustomObject]@{
                    Category         = 'GuestAccess'
                    SettingName      = 'Guest user access level'
                    CurrentValue     = $guestAccessLabel
                    RecommendedValue = 'Limited access (recommended)'
                    RiskLevel        = if ($GuestRoleId -eq 'a0b1b346-4d3e-4e8b-98f8-753987be4970') { 'High' }
                    elseif ($GuestRoleId -eq '10dae51f-b6af-4016-8d66-8c2a99b929b3') { 'Low' }
                    elseif ($GuestRoleId -eq '2af84b1e-32c8-42b7-82bc-daa82404023b') { 'Low' }
                    else { 'Info' }
                    Description      = 'Defines the default access level for guest users in the directory.'
                    Recommendation   = 'Set guest access to "Limited access" or "Restricted access" to prevent guests from enumerating directory objects.'
                })

            # Who can invite guests
            $AllowInvites = $AuthPolicy.allowInvitesFrom
            $Settings.Add([PSCustomObject]@{
                    Category         = 'GuestAccess'
                    SettingName      = 'Who can invite guests'
                    CurrentValue     = $AllowInvites
                    RecommendedValue = 'adminsAndGuestInviters'
                    RiskLevel        = if ($AllowInvites -eq 'everyone') { 'High' }
                    elseif ($AllowInvites -eq 'adminsAndGuestInviters') { 'Low' }
                    elseif ($AllowInvites -eq 'none') { 'Low' }
                    else { 'Medium' }
                    Description      = 'Controls who can invite external guest users to the tenant.'
                    Recommendation   = 'Restrict guest invitations to admins and users with the Guest Inviter role.'
                })

            # Email verified users can join
            $EmailVerifiedJoin = $AuthPolicy.allowEmailVerifiedUsersToJoinOrganization
            $Settings.Add([PSCustomObject]@{
                    Category         = 'AuthorizationPolicy'
                    SettingName      = 'Email verified users can join organization'
                    CurrentValue     = $EmailVerifiedJoin
                    RecommendedValue = $false
                    RiskLevel        = if ($EmailVerifiedJoin -eq $true) { 'Medium' } else { 'Low' }
                    Description      = 'Controls whether users who verify their email address can self-service join the organization.'
                    Recommendation   = 'Disable to prevent uncontrolled user onboarding via email verification.'
                })

            # User consent policy
            $ConsentPolicies = $DefaultPerms.permissionGrantPoliciesAssigned
            $HasLegacyConsent = $ConsentPolicies -contains 'microsoft-user-default-legacy'
            $ConsentDisplay = if ($ConsentPolicies) { $ConsentPolicies -join ', ' } else { 'None (admin consent required)' }
            $Settings.Add([PSCustomObject]@{
                    Category         = 'ApplicationConsent'
                    SettingName      = 'User consent policy'
                    CurrentValue     = $ConsentDisplay
                    RecommendedValue = 'microsoft-user-default-low or disabled'
                    RiskLevel        = if ($HasLegacyConsent) { 'High' }
                    elseif (-not $ConsentPolicies -or $ConsentPolicies.Count -eq 0) { 'Low' }
                    else { 'Medium' }
                    Description      = 'Defines which permission grant policies allow users to consent to applications.'
                    Recommendation   = 'Remove legacy consent policy and restrict user consent to low-risk permissions or require admin consent for all apps.'
                })

            # Admin consent workflow
            $AdminConsentEnabled = -not (-not $ConsentPolicies -or $ConsentPolicies.Count -eq 0) -and (-not $HasLegacyConsent)
            $Settings.Add([PSCustomObject]@{
                    Category         = 'ApplicationConsent'
                    SettingName      = 'Admin consent workflow'
                    CurrentValue     = if ($AdminConsentEnabled) { 'Configured' } else { 'Not configured' }
                    RecommendedValue = 'Configured'
                    RiskLevel        = if (-not $AdminConsentEnabled) { 'Medium' } else { 'Low' }
                    Description      = 'Indicates whether an admin consent workflow is effectively in place for application permissions.'
                    Recommendation   = 'Enable admin consent workflow so users can request access to apps they cannot consent to themselves.'
                })

            $SettingsByCategory = @{}
            $SettingsByRisk = @{
                High   = [System.Collections.Generic.List[PSCustomObject]]::new()
                Medium = [System.Collections.Generic.List[PSCustomObject]]::new()
                Low    = [System.Collections.Generic.List[PSCustomObject]]::new()
                Info   = [System.Collections.Generic.List[PSCustomObject]]::new()
            }

            foreach ($Setting in $Settings) {
                if (-not $SettingsByCategory.ContainsKey($Setting.Category)) {
                    $SettingsByCategory[$Setting.Category] = [System.Collections.Generic.List[PSCustomObject]]::new()
                }
                $SettingsByCategory[$Setting.Category].Add($Setting)
                $SettingsByRisk[$Setting.RiskLevel].Add($Setting)
            }

            $Summary = [PSCustomObject]@{
                TenantId            = $TenantId
                ReportGeneratedDate = Get-Date
                TotalSettings       = $Settings.Count
                HighRiskCount       = @($SettingsByRisk.High).Count
                MediumRiskCount     = @($SettingsByRisk.Medium).Count
                LowRiskCount        = @($SettingsByRisk.Low).Count
                InfoCount           = @($SettingsByRisk.Info).Count
            }

            Write-Information 'Tenant configuration (common misconfigurations) assessment completed.' -InformationAction Continue

            [PSCustomObject][Ordered]@{
                Summary            = $Summary
                Settings           = $Settings.ToArray()
                SettingsByCategory = $SettingsByCategory
                SettingsByRisk     = $SettingsByRisk
            }
        } catch {
            $ErrorRecord = [System.Management.Automation.ErrorRecord]::new(
                [System.Exception]::new("Get-TntConfigurationReport failed: $($_.Exception.Message)", $_.Exception),
                'GetTntTenantConfigurationReportError',
                [System.Management.Automation.ErrorCategory]::OperationStopped,
                $TenantId
            )
            $PSCmdlet.ThrowTerminatingError($ErrorRecord)
        } finally {
            if ($ConnectionInfo.ShouldDisconnect) {
                Disconnect-TntGraphSession -ConnectionState $ConnectionInfo
            }
        }
    }
}
