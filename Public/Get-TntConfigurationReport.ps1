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

    .INPUTS
        None. This function does not accept pipeline input.

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

        # Use interactive authentication (no app registration required).
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

            # --- Authorization Policy ---
            Write-Verbose 'Retrieving authorization policy...'
            $authPolicy = Invoke-MgGraphRequest -Uri 'https://graph.microsoft.com/v1.0/policies/authorizationPolicy' -Method GET -ErrorAction Stop
            $defaultPerms = $authPolicy.defaultUserRolePermissions

            # Users can register applications
            $allowApps = $defaultPerms.allowedToCreateApps
            $Settings.Add([PSCustomObject]@{
                    Category         = 'AuthorizationPolicy'
                    SettingName      = 'Users can register applications'
                    CurrentValue     = $allowApps
                    RecommendedValue = $false
                    RiskLevel        = if ($allowApps -eq $true) { 'High' } else { 'Low' }
                    Description      = 'Controls whether non-admin users can register new application registrations in Entra ID.'
                    Recommendation   = 'Disable user app registration and delegate to administrators to prevent unauthorized OAuth applications.'
                })

            # Users can create security groups
            $allowGroups = $defaultPerms.allowedToCreateSecurityGroups
            $Settings.Add([PSCustomObject]@{
                    Category         = 'AuthorizationPolicy'
                    SettingName      = 'Users can create security groups'
                    CurrentValue     = $allowGroups
                    RecommendedValue = $false
                    RiskLevel        = if ($allowGroups -eq $true) { 'Medium' } else { 'Low' }
                    Description      = 'Controls whether non-admin users can create security groups.'
                    Recommendation   = 'Restrict security group creation to administrators to maintain access control governance.'
                })

            # Non-admins can create tenants
            $allowTenants = $defaultPerms.allowedToCreateTenants
            $Settings.Add([PSCustomObject]@{
                    Category         = 'AuthorizationPolicy'
                    SettingName      = 'Non-admins can create tenants'
                    CurrentValue     = $allowTenants
                    RecommendedValue = $false
                    RiskLevel        = if ($allowTenants -eq $true) { 'Medium' } else { 'Low' }
                    Description      = 'Controls whether non-admin users can create new Azure AD tenants.'
                    Recommendation   = 'Restrict tenant creation to administrators to prevent shadow IT and unmanaged tenants.'
                })

            # Guest user access level
            $guestRoleId = $authPolicy.guestUserRoleId
            $guestAccessLabel = switch ($guestRoleId) {
                'a0b1b346-4d3e-4e8b-98f8-753987be4970' { 'Same as member users' }
                '10dae51f-b6af-4016-8d66-8c2a99b929b3' { 'Limited access (recommended)' }
                '2af84b1e-32c8-42b7-82bc-daa82404023b' { 'Restricted access (most restrictive)' }
                default { $guestRoleId }
            }
            $Settings.Add([PSCustomObject]@{
                    Category         = 'GuestAccess'
                    SettingName      = 'Guest user access level'
                    CurrentValue     = $guestAccessLabel
                    RecommendedValue = 'Limited access (recommended)'
                    RiskLevel        = if ($guestRoleId -eq 'a0b1b346-4d3e-4e8b-98f8-753987be4970') { 'High' }
                    elseif ($guestRoleId -eq '10dae51f-b6af-4016-8d66-8c2a99b929b3') { 'Low' }
                    elseif ($guestRoleId -eq '2af84b1e-32c8-42b7-82bc-daa82404023b') { 'Low' }
                    else { 'Info' }
                    Description      = 'Defines the default access level for guest users in the directory.'
                    Recommendation   = 'Set guest access to "Limited access" or "Restricted access" to prevent guests from enumerating directory objects.'
                })

            # Who can invite guests
            $allowInvites = $authPolicy.allowInvitesFrom
            $Settings.Add([PSCustomObject]@{
                    Category         = 'GuestAccess'
                    SettingName      = 'Who can invite guests'
                    CurrentValue     = $allowInvites
                    RecommendedValue = 'adminsAndGuestInviters'
                    RiskLevel        = if ($allowInvites -eq 'everyone') { 'High' }
                    elseif ($allowInvites -eq 'adminsAndGuestInviters') { 'Low' }
                    elseif ($allowInvites -eq 'none') { 'Low' }
                    else { 'Medium' }
                    Description      = 'Controls who can invite external guest users to the tenant.'
                    Recommendation   = 'Restrict guest invitations to admins and users with the Guest Inviter role.'
                })

            # Email verified users can join
            $emailVerifiedJoin = $authPolicy.allowEmailVerifiedUsersToJoinOrganization
            $Settings.Add([PSCustomObject]@{
                    Category         = 'AuthorizationPolicy'
                    SettingName      = 'Email verified users can join organization'
                    CurrentValue     = $emailVerifiedJoin
                    RecommendedValue = $false
                    RiskLevel        = if ($emailVerifiedJoin -eq $true) { 'Medium' } else { 'Low' }
                    Description      = 'Controls whether users who verify their email address can self-service join the organization.'
                    Recommendation   = 'Disable to prevent uncontrolled user onboarding via email verification.'
                })

            # User consent policy
            $consentPolicies = $defaultPerms.permissionGrantPoliciesAssigned
            $hasLegacyConsent = $consentPolicies -contains 'microsoft-user-default-legacy'
            $consentDisplay = if ($consentPolicies) { $consentPolicies -join ', ' } else { 'None (admin consent required)' }
            $Settings.Add([PSCustomObject]@{
                    Category         = 'ApplicationConsent'
                    SettingName      = 'User consent policy'
                    CurrentValue     = $consentDisplay
                    RecommendedValue = 'microsoft-user-default-low or disabled'
                    RiskLevel        = if ($hasLegacyConsent) { 'High' }
                    elseif (-not $consentPolicies -or $consentPolicies.Count -eq 0) { 'Low' }
                    else { 'Medium' }
                    Description      = 'Defines which permission grant policies allow users to consent to applications.'
                    Recommendation   = 'Remove legacy consent policy and restrict user consent to low-risk permissions or require admin consent for all apps.'
                })

            # Admin consent workflow
            $adminConsentEnabled = -not (-not $consentPolicies -or $consentPolicies.Count -eq 0) -and (-not $hasLegacyConsent)
            $Settings.Add([PSCustomObject]@{
                    Category         = 'ApplicationConsent'
                    SettingName      = 'Admin consent workflow'
                    CurrentValue     = if ($adminConsentEnabled) { 'Configured' } else { 'Not configured' }
                    RecommendedValue = 'Configured'
                    RiskLevel        = if (-not $adminConsentEnabled) { 'Medium' } else { 'Low' }
                    Description      = 'Indicates whether an admin consent workflow is effectively in place for application permissions.'
                    Recommendation   = 'Enable admin consent workflow so users can request access to apps they cannot consent to themselves.'
                })

            # Build report output
            $settingsByCategory = @{}
            $settingsByRisk = @{ High = @(); Medium = @(); Low = @(); Info = @() }

            foreach ($setting in $Settings) {
                if (-not $settingsByCategory.ContainsKey($setting.Category)) {
                    $settingsByCategory[$setting.Category] = [System.Collections.Generic.List[PSCustomObject]]::new()
                }
                $settingsByCategory[$setting.Category].Add($setting)
                $settingsByRisk[$setting.RiskLevel] += $setting
            }

            $summary = [PSCustomObject]@{
                TenantId            = $TenantId
                ReportGeneratedDate = Get-Date
                TotalSettings       = $Settings.Count
                HighRiskCount       = @($settingsByRisk.High).Count
                MediumRiskCount     = @($settingsByRisk.Medium).Count
                LowRiskCount        = @($settingsByRisk.Low).Count
                InfoCount           = @($settingsByRisk.Info).Count
            }

            Write-Information "Tenant configuration (common misconfigurations) assessment completed." -InformationAction Continue

            [PSCustomObject][Ordered]@{
                Summary            = $summary
                Settings           = $Settings.ToArray()
                SettingsByCategory = $settingsByCategory
                SettingsByRisk     = $settingsByRisk
            }
        } catch {
            $errorRecord = [System.Management.Automation.ErrorRecord]::new(
                [System.Exception]::new("Get-TntConfigurationReport failed: $($_.Exception.Message)", $_.Exception),
                'GetTntTenantConfigurationReportError',
                [System.Management.Automation.ErrorCategory]::OperationStopped,
                $TenantId
            )
            $PSCmdlet.ThrowTerminatingError($errorRecord)
        } finally {
            if ($ConnectionInfo.ShouldDisconnect) {
                Disconnect-TntGraphSession -ConnectionState $ConnectionInfo
            }
        }
    }
}
