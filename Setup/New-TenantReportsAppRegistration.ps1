#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Applications, Microsoft.Graph.Identity.DirectoryManagement

<#
.SYNOPSIS
    Creates an Azure App Registration for Microsoft 365/Azure security reporting.

.DESCRIPTION
    This script creates an Azure App Registration specifically designed for generating periodic security reports
    for Microsoft 365/Azure tenants. It configures both Microsoft Graph and Office 365 Exchange Online
    Application permissions and grants admin consent automatically.

    The script supports:
    - Creating new app registrations or updating existing ones
    - Automatic admin consent for all configured API permissions
    - Optional client secret generation with configurable expiration
    - Optional Azure AD directory role assignment for Exchange Online management
    - Intelligent connection handling (reuses existing sessions when possible)
    - Idempotent permission grants (safe to re-run)

    Configured Microsoft Graph permissions include:
    - Directory, User, Group, and Organization read access
    - Audit logs and security events
    - Identity risk and protection data
    - Intune device management (read-only)
    - Mail and calendar access (read-only)
    - Reports and policies

    Configured Exchange Online permissions include:
    - Exchange.ManageAsApp for application-based management
    - Mailbox settings and calendar read access

.PARAMETER ApplicationName
    The display name for the Azure App Registration.
    Default: "TenantReports"

.PARAMETER TenantId
    The Azure AD Tenant ID where the app registration will be created.
    This parameter is mandatory.

.PARAMETER CreateClientSecret
    Switch parameter to create a client secret for service principal authentication.
    If specified, a client secret will be generated and included in the output.
    
    IMPORTANT: The secret value is only displayed once and cannot be retrieved later.

.PARAMETER ClientSecretDescription
    Description for the client secret, visible in the Azure portal.
    Default: "TenantReports Client Secret"

.PARAMETER ClientSecretExpirationMonths
    Number of months until the client secret expires.
    Valid range: 1-24 months.
    Default: 24 months

.PARAMETER AssignDirectoryRoles
    Switch parameter to assign Azure AD directory roles to the service principal.
    Required for Exchange Online management operations.

.PARAMETER DirectoryRoles
    Array of directory role names to assign when -AssignDirectoryRoles is specified.
    Default: @('Exchange Administrator')
    
    Common roles for security reporting:
    - 'Exchange Administrator' - Required for Exchange Online management
    - 'Security Administrator' - Access to security-related features
    - 'Security Reader' - Read-only access to security features
    - 'Global Reader' - Read-only access to all administrative features

.EXAMPLE
    .\New-TenantReportsAppRegistration.ps1 -TenantId "12345678-1234-1234-1234-123456789012"

    Creates an app registration named "TenantReports" with default permissions.
    No client secret is created.

.EXAMPLE
    .\New-TenantReportsAppRegistration.ps1 -ApplicationName "Contoso-SecurityReports" -TenantId "12345678-1234-1234-1234-123456789012" -CreateClientSecret

    Creates an app registration with a custom name and generates a client secret
    that expires in 24 months (default).

.EXAMPLE
    .\New-TenantReportsAppRegistration.ps1 -TenantId "12345678-1234-1234-1234-123456789012" -CreateClientSecret -ClientSecretExpirationMonths 12

    Creates an app registration with a client secret that expires in 12 months.

.EXAMPLE
    .\New-TenantReportsAppRegistration.ps1 -TenantId "12345678-1234-1234-1234-123456789012" -AssignDirectoryRoles

    Creates an app registration and assigns the default 'Exchange Administrator' role
    to the service principal.

.EXAMPLE
    .\New-TenantReportsAppRegistration.ps1 -TenantId "12345678-1234-1234-1234-123456789012" -AssignDirectoryRoles -DirectoryRoles @('Exchange Administrator', 'Security Reader')

    Creates an app registration and assigns multiple directory roles.

.EXAMPLE
    $result = .\New-TenantReportsAppRegistration.ps1 -TenantId "12345678-1234-1234-1234-123456789012" -CreateClientSecret
    $result | Export-Csv -Path ".\AppRegistration.csv" -NoTypeInformation

    Creates an app registration and exports the results to a CSV file for documentation.

.EXAMPLE
    .\New-TenantReportsAppRegistration.ps1 -TenantId "12345678-1234-1234-1234-123456789012" -WhatIf

    Shows what actions would be performed without making any changes.

.INPUTS
    None. This script does not accept pipeline input.

.OUTPUTS
    PSCustomObject
        Returns an object containing:
        - ApplicationName: Display name of the app registration
        - ApplicationId: The Application (client) ID
        - ObjectId: The Object ID of the app registration
        - TenantId: The Azure AD tenant ID
        - ServicePrincipal: The Service Principal Object ID
        - ClientSecret: The client secret value (if created)
        - SecretExpires: Client secret expiration date (if created)
        - GraphPermissions: Count of granted/total Graph permissions
        - ExoPermissions: Count of granted/total Exchange Online permissions
        - DirectoryRoles: Comma-separated list of assigned directory roles

.NOTES
    Author: Tom de Leeuw
    Website: https://systom.dev

    Prerequisites:
    - Microsoft Graph PowerShell SDK modules:
        - Microsoft.Graph.Authentication
        - Microsoft.Graph.Applications
        - Microsoft.Graph.Identity.DirectoryManagement
    
    Required Permissions (for the user running this script):
    - Application.ReadWrite.All
    - AppRoleAssignment.ReadWrite.All
    - RoleManagement.ReadWrite.Directory (if using -AssignDirectoryRoles)

    The script automatically handles:
    - Connection to Microsoft Graph (or reuses existing connection)
    - Service principal creation for the app registration
    - Admin consent for all API permissions
    - Directory role activation if not already active

.LINK
    https://systom.dev

.LINK
    https://learn.microsoft.com/en-us/graph/permissions-reference

.LINK
    https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
param(
    [Parameter(Position = 0, ValueFromPipelineByPropertyName = $true)]
    [ValidateNotNullOrEmpty()]
    [Alias('Name', 'DisplayName')]
    [string]$ApplicationName = 'TenantReports',

    [Parameter(Mandatory = $true, Position = 1, ValueFromPipelineByPropertyName = $true)]
    [ValidateNotNullOrEmpty()]
    [ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')]
    [Alias('Tenant')]
    [string]$TenantId,

    [Parameter(ValueFromPipelineByPropertyName = $true)]
    [switch]$CreateClientSecret,

    [Parameter(ValueFromPipelineByPropertyName = $true)]
    [string]$ClientSecretDescription = 'TenantReports Client Secret',

    [Parameter(ValueFromPipelineByPropertyName = $true)]
    [ValidateRange(1, 24)]
    [int]$ClientSecretExpirationMonths = 24,

    [Parameter(ValueFromPipelineByPropertyName = $true)]
    [switch]$AssignDirectoryRoles,

    [Parameter(ValueFromPipelineByPropertyName = $true)]
    [string[]]$DirectoryRoles = @('Exchange Administrator')
)

begin {
    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    $GraphAppId = '00000003-0000-0000-c000-000000000000'
    $ExoAppId   = '00000002-0000-0ff1-ce00-000000000000'

    $Permissions = @{
        $GraphAppId = @(
            '7ab1d382-f21e-4acd-a863-ba3e13f7da61' # Directory.Read.All
            'df021288-bdef-4463-88db-98f22de89214' # User.Read.All
            'b0afded3-3588-46d8-8b3d-9842eff778da' # AuditLog.Read.All
            '19dbc75e-c2e2-444c-a770-ec69d8559fc7' # DeviceManagementConfiguration.Read.All
            '5b567255-7703-4780-807c-7be8301ae99b' # Group.Read.All
            '483bed4a-2ad3-4361-a73b-c83ccdbdc53c' # RoleManagement.Read.All
            '6e472fd1-ad78-48da-a0f0-97ab2c6b769e' # IdentityRiskEvent.Read.All
            '607c7344-0eed-41e5-823a-9695ebe1b7b0' # IdentityRiskyServicePrincipal.Read.All
            'dc5007c0-2d7d-4c42-879c-2dab87571379' # IdentityRiskyUser.Read.All
            'bf394140-e372-4bf9-a898-299cfc7564e5' # SecurityEvents.Read.All
            '246dd0d5-5bd0-4def-940b-0421030a5b68' # Policy.Read.All
            '197ee4e9-b993-4066-898f-d6aecc55125b' # ThreatIndicators.Read.All
            'f8f035bb-2cce-47fb-8bf5-7baf3ecbee48' # ThreatAssessment.Read.All
            'd72bdbf4-a59b-405c-8b04-5995895819ac' # ThreatSubmission.ReadWrite.All
            '5e0edab9-c148-49d0-b423-ac253e121825' # SecurityActions.Read.All
            '810c84a8-4a9e-49e6-bf7d-12d183f40d01' # Mail.Read
            '2f51be20-0bb4-4fed-bf7b-db946066c75e' # DeviceManagementManagedDevices.Read.All
            '45cc0394-e837-488b-a098-1918f48d186c' # SecurityIncident.Read.All
            '38d9df27-64da-44fd-b7c5-a6fbac20248f' # UserAuthenticationMethod.Read.All
            '06a5fe6d-c49d-46a7-b082-56b1b14103c7' # DeviceManagementServiceConfig.Read.All
            '8ba4a692-bc31-4128-9094-475872af8a53' # Calendars.ReadBasic.All
            '230c1aed-a721-4c5d-9cb4-a90514e508ef' # Reports.Read.All
            '498476ce-e0fe-48b0-b801-37ba7e2685c6' # Organization.Read.All
        )
        $ExoAppId   = @(
            'dc50a0fb-09a3-484d-be87-e023b12c6440' # Exchange.ManageAsApp
            '2dfdc6dc-2fa7-4a2c-a922-dbd4f85d17be' # Calendars.Read
            'd45fa9f8-36e5-4cd2-b601-b063c7cf9ac2' # MailboxSettings.Read
            'bf24470f-10c1-436d-8d53-7b997eb473be' # User.Read.All
            '15f260d6-f874-4366-8672-6b3658c5a09b' # Organization.Read.All
        )
    }
}

process {
    #region Connection
    $Context = Get-MgContext -ErrorAction SilentlyContinue
    if (-not $Context -or $Context.TenantId -ne $TenantId) {
        Write-Host '[*] Connecting to tenant: ' -ForegroundColor Cyan -NoNewline
        Write-Host $TenantId -ForegroundColor White
        Connect-MgGraph -TenantId $TenantId -Scopes 'Application.ReadWrite.All', 'AppRoleAssignment.ReadWrite.All', 'RoleManagement.ReadWrite.Directory' -NoWelcome
    }
    else {
        Write-Host '[*] Using existing connection: ' -ForegroundColor Cyan -NoNewline
        Write-Host $TenantId -ForegroundColor White
    }
    #endregion

    #region App Registration
    $App = Get-MgApplication -Filter "displayName eq '$ApplicationName'" -ErrorAction SilentlyContinue
    if ($App) {
        Write-Host "[!] App '$ApplicationName' exists - updating permissions" -ForegroundColor Yellow

        $RequiredAccess = foreach ($AppId in $Permissions.Keys) {
            @{
                ResourceAppId  = $AppId
                ResourceAccess = $Permissions[$AppId] | ForEach-Object { @{ Id = $_; Type = 'Role' } }
            }
        }
        Update-MgApplication -ApplicationId $App.Id -RequiredResourceAccess $RequiredAccess
    }
    elseif ($PSCmdlet.ShouldProcess($ApplicationName, 'Create App Registration')) {
        Write-Host '[*] Creating app registration: ' -ForegroundColor Cyan -NoNewline
        Write-Host $ApplicationName -ForegroundColor White

        $RequiredAccess = foreach ($AppId in $Permissions.Keys) {
            @{
                ResourceAppId  = $AppId
                ResourceAccess = $Permissions[$AppId] | ForEach-Object { @{ Id = $_; Type = 'Role' } }
            }
        }
        $App = New-MgApplication -DisplayName $ApplicationName -SignInAudience 'AzureADMyOrg' -RequiredResourceAccess $RequiredAccess
    }
    #endregion

    #region Service Principal
    $Sp = Get-MgServicePrincipal -Filter "appId eq '$($App.AppId)'" -ErrorAction SilentlyContinue
    if (-not $Sp) {
        Write-Host '[*] Creating service principal...' -ForegroundColor Cyan
        $Sp = New-MgServicePrincipal -AppId $App.AppId
        Start-Sleep -Seconds 10
    }
    #endregion

    #region Client Secret
    $Secret = $null
    if ($CreateClientSecret -and $PSCmdlet.ShouldProcess('Client Secret', 'Create')) {
        Write-Host '[*] Creating client secret...' -ForegroundColor Cyan
        $Secret = Add-MgApplicationPassword -ApplicationId $App.Id -PasswordCredential @{
            DisplayName = $ClientSecretDescription
            EndDateTime = (Get-Date).AddMonths($ClientSecretExpirationMonths)
        }
    }
    #endregion

    #region Grant Permissions
    $GrantResults = @{
        Graph    = @{ Granted = 0; Failed = 0 }
        Exchange = @{ Granted = 0; Failed = 0 }
    }

    if ($PSCmdlet.ShouldProcess('API Permissions', 'Grant Admin Consent')) {
        Write-Host '[*] Granting admin consent...' -ForegroundColor Cyan

        foreach ($ResourceAppId in $Permissions.Keys) {
            $ResourceSp = Get-MgServicePrincipal -Filter "appId eq '$ResourceAppId'" -ErrorAction SilentlyContinue
            if (-not $ResourceSp) { continue }

            $KeyName = if ($ResourceAppId -eq $GraphAppId) { 'Graph' } else { 'Exchange' }
            $Existing = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $Sp.Id -All -ErrorAction SilentlyContinue

            foreach ($RoleId in $Permissions[$ResourceAppId]) {
                if ($Existing | Where-Object { $_.AppRoleId -eq $RoleId -and $_.ResourceId -eq $ResourceSp.Id }) {
                    $GrantResults[$KeyName].Granted++
                    continue
                }
                try {
                    $null = New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $Sp.Id -PrincipalId $Sp.Id -ResourceId $ResourceSp.Id -AppRoleId $RoleId -ErrorAction Stop
                    $GrantResults[$KeyName].Granted++
                }
                catch {
                    $GrantResults[$KeyName].Failed++
                    Write-Verbose "Failed to grant $RoleId : $_"
                }
            }
        }

        Write-Host '[+] Graph: ' -ForegroundColor Green -NoNewline
        Write-Host "$($GrantResults.Graph.Granted) granted, $($GrantResults.Graph.Failed) failed" -ForegroundColor White
        Write-Host '[+] Exchange: ' -ForegroundColor Green -NoNewline
        Write-Host "$($GrantResults.Exchange.Granted) granted, $($GrantResults.Exchange.Failed) failed" -ForegroundColor White
    }
    #endregion

    #region Directory Roles
    $RoleResults = @{ Assigned = @(); Failed = @() }

    if ($AssignDirectoryRoles -and $PSCmdlet.ShouldProcess('Directory Roles', 'Assign')) {
        Write-Host '[*] Assigning directory roles...' -ForegroundColor Cyan

        foreach ($RoleName in $DirectoryRoles) {
            try {
                $Role = Get-MgDirectoryRole -Filter "displayName eq '$RoleName'" -ErrorAction SilentlyContinue
                if (-not $Role) {
                    $Template = Get-MgDirectoryRoleTemplate -Filter "displayName eq '$RoleName'"
                    if (-not $Template) { throw "Directory Role Template '$RoleName' not found." }
                    $Role = New-MgDirectoryRole -RoleTemplateId $Template.Id
                    Start-Sleep -Seconds 5
                }

                # Fail-Soft Strategy: Attempt assignment and handle "Already Exists" error
                # This is more robust than checking membership which can fail due to API paging or object property mapping.
                try {
                    $null = New-MgDirectoryRoleMemberByRef -DirectoryRoleId $Role.Id -BodyParameter @{
                        '@odata.id' = "https://graph.microsoft.com/v1.0/directoryObjects/$($Sp.Id)"
                    } -ErrorAction Stop
                    
                    Write-Host "[+] $RoleName : " -ForegroundColor Green -NoNewline
                    Write-Host 'Assigned' -ForegroundColor White
                    $RoleResults.Assigned += $RoleName
                }
                catch {
                    # 400 BadRequest with "already exist" is a success state in an idempotent script
                    if ($_.Exception.Message -like "*already exist*" -or $_.Exception.Message -like "*400*") {
                        Write-Host "[+] $RoleName : " -ForegroundColor Green -NoNewline
                        Write-Host 'Already assigned' -ForegroundColor White
                        $RoleResults.Assigned += $RoleName
                    }
                    else {
                        # Re-throw genuine errors (Access Denied, etc.)
                        throw $_
                    }
                }
            }
            catch {
                Write-Host "[-] $RoleName : " -ForegroundColor Red -NoNewline
                Write-Host "Failed - $($_.Exception.Message)" -ForegroundColor White
                $RoleResults.Failed += $RoleName
            }
        }
    }
    #endregion

    #region Output
    [PSCustomObject]@{
        ApplicationName  = $App.DisplayName
        ApplicationId    = $App.AppId
        ObjectId         = $App.Id
        TenantId         = $TenantId
        ServicePrincipal = $Sp.Id
        ClientSecret     = if ($Secret) { $Secret.SecretText } else { $null }
        SecretExpires    = if ($Secret) { $Secret.EndDateTime } else { $null }
        GraphPermissions = "$($GrantResults.Graph.Granted)/$($Permissions[$GraphAppId].Count)"
        ExoPermissions   = "$($GrantResults.Exchange.Granted)/$($Permissions[$ExoAppId].Count)"
        DirectoryRoles   = if ($RoleResults.Assigned) { $RoleResults.Assigned -join ', ' } else { $null }
    }

    if ($Secret) {
        Write-Host "`n[!] SAVE YOUR SECRET NOW - it won't be shown again!" -ForegroundColor Yellow -BackgroundColor DarkRed
    }
    #endregion
}

end {
    Disconnect-MgGraph
}