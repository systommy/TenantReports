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
    - Optional certificate credential upload (existing or self-signed)
    - Optional Azure AD directory role assignment for Exchange Online management
    - Intelligent connection handling (reuses existing sessions when possible)
    - Idempotent permission grants (safe to re-run)

    Configured Microsoft Graph permissions include:
    - Directory, User, Group, and Organization read access
    - Application and domain read access
    - Audit logs and security events
    - Identity risk and protection data
    - Intune device management, apps, and configuration (read-only)
    - Mail and calendar access (read-only)
    - Reports, policies, and SharePoint tenant settings
    - Security alerts and incidents

    Configured Exchange Online permissions include:
    - Exchange.ManageAsApp for application-based management
    - Mailbox settings and calendar read access

    Configured Azure Service Management permissions include:
    - user_impersonation (delegated) for Azure Resource Manager access

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

.PARAMETER CertificateThumbprint
    Thumbprint of an existing certificate to upload to the app registration.
    The certificate must exist in Cert:\CurrentUser\My or Cert:\LocalMachine\My.
    Mutually exclusive with -CreateSelfSignedCertificate.

.PARAMETER CreateSelfSignedCertificate
    Switch parameter to create a new self-signed certificate and upload it to the app registration.
    The certificate is created in Cert:\CurrentUser\My with RSA 2048-bit key and SHA256 hash.
    Mutually exclusive with -CertificateThumbprint.

.PARAMETER CertificateSubject
    Subject name for the self-signed certificate.
    Default: "CN=TenantReports"
    Can only be used with -CreateSelfSignedCertificate.

.PARAMETER CertificateExpirationMonths
    Number of months until the self-signed certificate expires.
    Valid range: 1-24 months.
    Default: 24 months
    Can only be used with -CreateSelfSignedCertificate.

.PARAMETER AssignAzureRoles
    Switch parameter to assign Azure RBAC roles to the service principal on Azure subscriptions.
    Required for the Azure Secure Score report (Get-TntAzureSecureScoreReport) when using
    client credentials authentication.

    This triggers a separate device code flow for Azure Resource Manager authentication,
    as Microsoft Graph and Azure Resource Manager use different authorization planes.

.PARAMETER AzureRoles
    Array of Azure RBAC role names to assign when -AssignAzureRoles is specified.
    Default: @('Security Reader')

    The roles are assigned on each accessible subscription (or those specified by -SubscriptionIds).

.PARAMETER SubscriptionIds
    Optional array of Azure subscription IDs to scope Azure RBAC role assignments to.
    If not specified, roles are assigned on all subscriptions accessible to the authenticated user.
    Can only be used with -AssignAzureRoles.

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
    .\New-TenantReportsAppRegistration.ps1 -TenantId "12345678-1234-1234-1234-123456789012" -CertificateThumbprint "A1B2C3D4E5F6..."

    Creates an app registration and uploads an existing certificate from the local certificate store.

.EXAMPLE
    .\New-TenantReportsAppRegistration.ps1 -TenantId "12345678-1234-1234-1234-123456789012" -CreateSelfSignedCertificate

    Creates an app registration and generates a self-signed certificate (CN=TenantReports, 24 months expiry)
    in Cert:\CurrentUser\My, then uploads it to the app registration.

.EXAMPLE
    .\New-TenantReportsAppRegistration.ps1 -TenantId "12345678-1234-1234-1234-123456789012" -CreateSelfSignedCertificate -CertificateSubject "CN=Contoso-Reports" -CertificateExpirationMonths 12

    Creates an app registration with a self-signed certificate using a custom subject name
    and 12-month expiration.

.EXAMPLE
    .\New-TenantReportsAppRegistration.ps1 -TenantId "12345678-1234-1234-1234-123456789012" -CreateClientSecret -CreateSelfSignedCertificate

    Creates an app registration with both a client secret and a self-signed certificate,
    allowing users to choose either authentication method.

.EXAMPLE
    .\New-TenantReportsAppRegistration.ps1 -TenantId "12345678-1234-1234-1234-123456789012" -WhatIf

    Shows what actions would be performed without making any changes.

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
        - CertificateThumbprint: The certificate thumbprint (if uploaded)
        - CertificateExpires: Certificate expiration date (if uploaded)
        - GraphPermissions: Count of granted/total Graph permissions
        - ExoPermissions: Count of granted/total Exchange Online permissions
        - AzurePermissions: Count of granted/total Azure Service Management permissions
        - DirectoryRoles: Comma-separated list of assigned directory roles
        - AzureRbacRoles: Comma-separated list of assigned Azure RBAC roles per subscription

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
    - DelegatedPermissionGrant.ReadWrite.All
    - RoleManagement.ReadWrite.Directory (if using -AssignDirectoryRoles)
    - Owner or User Access Administrator on Azure subscriptions (if using -AssignAzureRoles)

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
    [string[]]$DirectoryRoles = @('Exchange Administrator'),

    [Parameter(ValueFromPipelineByPropertyName = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$CertificateThumbprint,

    [Parameter(ValueFromPipelineByPropertyName = $true)]
    [switch]$CreateSelfSignedCertificate,

    [Parameter(ValueFromPipelineByPropertyName = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$CertificateSubject = 'CN=TenantReports',

    [Parameter(ValueFromPipelineByPropertyName = $true)]
    [ValidateRange(1, 24)]
    [int]$CertificateExpirationMonths = 24,

    [Parameter(ValueFromPipelineByPropertyName = $true)]
    [switch]$AssignAzureRoles,

    [Parameter(ValueFromPipelineByPropertyName = $true)]
    [string[]]$AzureRoles = @('Security Reader'),

    [Parameter(ValueFromPipelineByPropertyName = $true)]
    [string[]]$SubscriptionIds
)

begin {
    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    if ($CertificateThumbprint -and $CreateSelfSignedCertificate) {
        throw '-CertificateThumbprint and -CreateSelfSignedCertificate are mutually exclusive.'
    }
    if (-not $CreateSelfSignedCertificate) {
        if ($PSBoundParameters.ContainsKey('CertificateSubject')) {
            throw '-CertificateSubject can only be used with -CreateSelfSignedCertificate.'
        }
        if ($PSBoundParameters.ContainsKey('CertificateExpirationMonths')) {
            throw '-CertificateExpirationMonths can only be used with -CreateSelfSignedCertificate.'
        }
    }
    if (-not $AssignAzureRoles) {
        if ($PSBoundParameters.ContainsKey('AzureRoles')) {
            throw '-AzureRoles can only be used with -AssignAzureRoles.'
        }
        if ($PSBoundParameters.ContainsKey('SubscriptionIds')) {
            throw '-SubscriptionIds can only be used with -AssignAzureRoles.'
        }
    }

    $GraphAppId           = '00000003-0000-0000-c000-000000000000'
    $ExoAppId             = '00000002-0000-0ff1-ce00-000000000000'
    $AzureManagementAppId = '797f4846-ba00-4fd7-ba43-dac1f8f63013'

    # Application permissions (Role type - granted via AppRoleAssignment)
    $AppPermissions = @{
        $GraphAppId = @(
            '7ab1d382-f21e-4acd-a863-ba3e13f7da61' # Directory.Read.All
            'df021288-bdef-4463-88db-98f22de89214' # User.Read.All
            'b0afded3-3588-46d8-8b3d-9842eff778da' # AuditLog.Read.All
            'dc377aa6-52d8-4e23-b271-2a7ae04cedf3' # DeviceManagementConfiguration.Read.All
            '5b567255-7703-4780-807c-7be8301ae99b' # Group.Read.All
            '483bed4a-2ad3-4361-a73b-c83ccdbdc53c' # RoleManagement.Read.Directory
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
            '9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30' # Application.Read.All
            '7438b122-aefc-4978-80ed-43db9fcc7715' # Device.Read.All
            '472e4a4d-bb4a-4026-98d1-0b0d74cb74a5' # SecurityAlert.Read.All
            '86632667-cd15-4845-ad89-48a88e8412e1' # ThreatSubmission.Read.All
            'dbb9058a-0e50-45d7-ae91-66909b5d4664' # Domain.Read.All
            '83d4163d-a2d8-4d3b-9695-4ae3ca98f888' # SharePointTenantSettings.Read.All
            '7a6ee1e7-141e-4cec-ae74-d9db155731ff' # DeviceManagementApps.Read.All
        )
        $ExoAppId = @(
            'dc50a0fb-09a3-484d-be87-e023b12c6440' # Exchange.ManageAsApp
            '2dfdc6dc-2fa7-4a2c-a922-dbd4f85d17be' # Calendars.Read
            'd45fa9f8-36e5-4cd2-b601-b063c7cf9ac2' # MailboxSettings.Read
            'bf24470f-10c1-436d-8d53-7b997eb473be' # User.Read.All
            '15f260d6-f874-4366-8672-6b3658c5a09b' # Organization.Read.All
        )
    }

    # Delegated permissions (Scope type - granted via OAuth2PermissionGrant)
    $DelegatedPermissions = @{
        $AzureManagementAppId = @(
            '41094075-9dad-400e-a0bd-54e686782033' # user_impersonation
        )
    }
}

process {
    #region Connection
    $Context = Get-MgContext -ErrorAction SilentlyContinue
    if (-not $Context -or $Context.TenantId -ne $TenantId) {
        Write-Host '[*] Connecting to tenant: ' -ForegroundColor Cyan -NoNewline
        Write-Host $TenantId -ForegroundColor White
        Connect-MgGraph -TenantId $TenantId -Scopes 'Application.ReadWrite.All', 'AppRoleAssignment.ReadWrite.All', 'RoleManagement.ReadWrite.Directory', 'DelegatedPermissionGrant.ReadWrite.All' -NoWelcome
    }
    else {
        Write-Host '[*] Using existing connection: ' -ForegroundColor Cyan -NoNewline
        Write-Host $TenantId -ForegroundColor White
    }
    #endregion

    #region App Registration
    $App = Get-MgApplication -Filter "displayName eq '$ApplicationName'" -ErrorAction SilentlyContinue

    # Build requiredResourceAccess using camelCase keys for -BodyParameter serialization.
    # The SDK's expanded parameter binding fails to convert nested hashtable collections
    # into IMicrosoftGraphResourceAccess[], so we bypass it with -BodyParameter.
    $RequiredAccess = @(
        foreach ($AppId in $AppPermissions.Keys) {
            @{
                resourceAppId  = $AppId
                resourceAccess = @(
                    foreach ($PermId in $AppPermissions[$AppId]) {
                        @{ id = $PermId; type = 'Role' }
                    }
                )
            }
        }
        foreach ($AppId in $DelegatedPermissions.Keys) {
            @{
                resourceAppId  = $AppId
                resourceAccess = @(
                    foreach ($PermId in $DelegatedPermissions[$AppId]) {
                        @{ id = $PermId; type = 'Scope' }
                    }
                )
            }
        }
    )

    if ($App) {
        Write-Host "[!] App '$ApplicationName' exists - updating permissions" -ForegroundColor Yellow
        Update-MgApplication -ApplicationId $App.Id -BodyParameter @{ requiredResourceAccess = $RequiredAccess }
    }
    elseif ($PSCmdlet.ShouldProcess($ApplicationName, 'Create App Registration')) {
        Write-Host '[*] Creating app registration: ' -ForegroundColor Cyan -NoNewline
        Write-Host $ApplicationName -ForegroundColor White
        $App = New-MgApplication -BodyParameter @{
            displayName            = $ApplicationName
            signInAudience         = 'AzureADMyOrg'
            requiredResourceAccess = $RequiredAccess
        }
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

    #region Certificate
    $CertificateInfo = $null
    if ($CreateSelfSignedCertificate -and $PSCmdlet.ShouldProcess('Self-Signed Certificate', 'Create')) {
        Write-Host '[*] Creating self-signed certificate...' -ForegroundColor Cyan

        $CertParams = @{
            Subject           = $CertificateSubject
            CertStoreLocation = 'Cert:\CurrentUser\My'
            KeyExportPolicy   = 'Exportable'
            KeySpec           = 'Signature'
            KeyLength         = 2048
            KeyAlgorithm      = 'RSA'
            HashAlgorithm     = 'SHA256'
            NotAfter          = (Get-Date).AddMonths($CertificateExpirationMonths)
        }
        $Certificate = New-SelfSignedCertificate @CertParams

        $CertificateInfo = @{
            Thumbprint = $Certificate.Thumbprint
            Expires    = $Certificate.NotAfter
        }
    }
    elseif ($CertificateThumbprint) {
        # Normalize thumbprint: remove whitespace, uppercase
        $NormalizedThumbprint = ($CertificateThumbprint -replace '\s', '').ToUpperInvariant()

        # Find certificate in local stores
        $Certificate = $null
        foreach ($StoreLocation in @('CurrentUser', 'LocalMachine')) {
            $CertPath = "Cert:\$StoreLocation\My\$NormalizedThumbprint"
            $Certificate = Get-Item -Path $CertPath -ErrorAction SilentlyContinue
            if ($Certificate) {
                Write-Host "[*] Found certificate in $StoreLocation store" -ForegroundColor Cyan
                break
            }
        }

        if (-not $Certificate) {
            throw "Certificate with thumbprint '$NormalizedThumbprint' not found in Cert:\CurrentUser\My or Cert:\LocalMachine\My."
        }

        $CertificateInfo = @{
            Thumbprint = $Certificate.Thumbprint
            Expires    = $Certificate.NotAfter
        }
    }

    # Upload public key to app registration
    if ($CertificateInfo -and $PSCmdlet.ShouldProcess('Certificate Key Credential', 'Upload to App Registration')) {
        Write-Host '[*] Uploading certificate to app registration...' -ForegroundColor Cyan

        $KeyCredential = @{
            Type               = 'AsymmetricX509Cert'
            Usage              = 'Verify'
            Key                = $Certificate.RawData
            DisplayName        = $Certificate.Subject
            StartDateTime      = $Certificate.NotBefore
            EndDateTime        = $Certificate.NotAfter
        }
        Update-MgApplication -ApplicationId $App.Id -KeyCredentials @($KeyCredential)

        Write-Host '[+] Certificate uploaded: ' -ForegroundColor Green -NoNewline
        Write-Host $CertificateInfo.Thumbprint -ForegroundColor White
    }
    #endregion

    #region Grant Permissions
    $GrantResults = @{
        Graph    = @{ Granted = 0; Failed = 0 }
        Exchange = @{ Granted = 0; Failed = 0 }
        Azure    = @{ Granted = 0; Failed = 0 }
    }

    if ($PSCmdlet.ShouldProcess('API Permissions', 'Grant Admin Consent')) {
        Write-Host '[*] Granting admin consent for application permissions...' -ForegroundColor Cyan

        # Grant application permissions (Role type) via AppRoleAssignment
        foreach ($ResourceAppId in $AppPermissions.Keys) {
            $ResourceSp = Get-MgServicePrincipal -Filter "appId eq '$ResourceAppId'" -ErrorAction SilentlyContinue
            if (-not $ResourceSp) { continue }

            $KeyName = if ($ResourceAppId -eq $GraphAppId) { 'Graph' } else { 'Exchange' }
            $Existing = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $Sp.Id -All -ErrorAction SilentlyContinue

            foreach ($RoleId in $AppPermissions[$ResourceAppId]) {
                if (@($Existing).Where({ $_.AppRoleId -eq $RoleId -and $_.ResourceId -eq $ResourceSp.Id }).Count -gt 0) {
                    $GrantResults[$KeyName].Granted++
                    continue
                }
                try {
                    $null = New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $Sp.Id -PrincipalId $Sp.Id -ResourceId $ResourceSp.Id -AppRoleId $RoleId -ErrorAction Stop
                    $GrantResults[$KeyName].Granted++
                }
                catch {
                    $GrantResults[$KeyName].Failed++
                    Write-Warning "Failed to grant permission '$RoleId': $_"
                }
            }
        }

        Write-Host '[+] Graph: ' -ForegroundColor Green -NoNewline
        Write-Host "$($GrantResults.Graph.Granted) granted, $($GrantResults.Graph.Failed) failed" -ForegroundColor White
        Write-Host '[+] Exchange: ' -ForegroundColor Green -NoNewline
        Write-Host "$($GrantResults.Exchange.Granted) granted, $($GrantResults.Exchange.Failed) failed" -ForegroundColor White

        # Grant delegated permissions (Scope type) via OAuth2PermissionGrant
        Write-Host '[*] Granting admin consent for delegated permissions...' -ForegroundColor Cyan

        foreach ($ResourceAppId in $DelegatedPermissions.Keys) {
            $ResourceSp = Get-MgServicePrincipal -Filter "appId eq '$ResourceAppId'" -ErrorAction SilentlyContinue
            if (-not $ResourceSp) { continue }

            $ScopeNames = switch ($ResourceAppId) {
                $AzureManagementAppId { 'user_impersonation' }
            }

            # Check for existing grant
            $ExistingGrant = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/oauth2PermissionGrants?`$filter=clientId eq '$($Sp.Id)' and resourceId eq '$($ResourceSp.Id)'" -ErrorAction SilentlyContinue

            if ($ExistingGrant.value -and $ExistingGrant.value.Count -gt 0) {
                # Update existing grant to ensure all scopes are included
                $ExistingScopes = $ExistingGrant.value[0].scope -split ' '
                $NewScopes = ($ScopeNames -split ' ').Where({ $_ -notin $ExistingScopes })
                if ($NewScopes.Count -gt 0) {
                    $UpdatedScope = (($ExistingScopes + $NewScopes) -join ' ').Trim()
                    try {
                        $null = Invoke-MgGraphRequest -Method PATCH -Uri "https://graph.microsoft.com/v1.0/oauth2PermissionGrants/$($ExistingGrant.value[0].id)" -Body @{ scope = $UpdatedScope } -ErrorAction Stop
                        $GrantResults.Azure.Granted++
                    }
                    catch {
                        $GrantResults.Azure.Failed++
                        Write-Verbose "Failed to update delegated grant: $_"
                    }
                }
                else {
                    $GrantResults.Azure.Granted++
                }
            }
            else {
                try {
                    $null = Invoke-MgGraphRequest -Method POST -Uri 'https://graph.microsoft.com/v1.0/oauth2PermissionGrants' -Body @{
                        clientId    = $Sp.Id
                        consentType = 'AllPrincipals'
                        resourceId  = $ResourceSp.Id
                        scope       = $ScopeNames
                    } -ErrorAction Stop
                    $GrantResults.Azure.Granted++
                }
                catch {
                    $GrantResults.Azure.Failed++
                    Write-Verbose "Failed to grant delegated permission: $_"
                }
            }
        }

        Write-Host '[+] Azure Service Management: ' -ForegroundColor Green -NoNewline
        Write-Host "$($GrantResults.Azure.Granted) granted, $($GrantResults.Azure.Failed) failed" -ForegroundColor White
    }
    #endregion

    #region Directory Roles
    $RoleResults = @{
        Assigned = [System.Collections.Generic.List[string]]::new()
        Failed   = [System.Collections.Generic.List[string]]::new()
    }

    if ($AssignDirectoryRoles -and $PSCmdlet.ShouldProcess('Directory Roles', 'Assign')) {
        Write-Host '[*] Assigning directory roles...' -ForegroundColor Cyan

        foreach ($RoleName in $DirectoryRoles) {
            try {
                $Role = Get-MgDirectoryRole -Filter "displayName eq '$RoleName'" -ErrorAction SilentlyContinue
                if (-not $Role) {
                    $Template = Get-MgDirectoryRoleTemplate -All | Where-Object { $_.DisplayName -eq $RoleName }
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
                    [void]$RoleResults.Assigned.Add($RoleName)
                }
                catch {
                    # 400 BadRequest with "already exist" is a success state in an idempotent script
                    if ($_.Exception.Message -like "*already exist*" -or $_.Exception.Message -like "*400*") {
                        Write-Host "[+] $RoleName : " -ForegroundColor Green -NoNewline
                        Write-Host 'Already assigned' -ForegroundColor White
                        [void]$RoleResults.Assigned.Add($RoleName)
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
                [void]$RoleResults.Failed.Add($RoleName)
            }
        }
    }
    #endregion

    #region Azure RBAC
    $AzureRbacResults = @{
        Assigned = [System.Collections.Generic.List[string]]::new()
        Failed   = [System.Collections.Generic.List[string]]::new()
    }

    if ($AssignAzureRoles -and $PSCmdlet.ShouldProcess('Azure RBAC Roles', 'Assign')) {
        Write-Host "`n[*] Assigning Azure RBAC roles..." -ForegroundColor Cyan
        Write-Host '    A separate login is required for Azure Resource Manager access.' -ForegroundColor Cyan

        # Acquire ARM token via device code flow using Azure CLI's well-known public client
        $AzureCliClientId = '04b07795-8ddb-461a-bbee-02f9e1bf7b46'
        $DeviceCodeResponse = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/devicecode" -Body @{
            client_id = $AzureCliClientId
            scope     = 'https://management.azure.com/.default offline_access'
        } -ErrorAction Stop

        Write-Host "`n$($DeviceCodeResponse.message)" -ForegroundColor Yellow

        $ArmToken  = $null
        $TokenExpiry = [datetime]::UtcNow.AddSeconds($DeviceCodeResponse.expires_in)
        while (-not $ArmToken -and [datetime]::UtcNow -lt $TokenExpiry) {
            Start-Sleep -Seconds $DeviceCodeResponse.interval
            try {
                $TokenResponse = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" -Body @{
                    grant_type  = 'urn:ietf:params:oauth:grant-type:device_code'
                    client_id   = $AzureCliClientId
                    device_code = $DeviceCodeResponse.device_code
                } -ErrorAction Stop
                $ArmToken = $TokenResponse.access_token
            }
            catch {
                $ErrorMsg = ($_.ErrorDetails.Message | ConvertFrom-Json -ErrorAction SilentlyContinue).error
                if ($ErrorMsg -ne 'authorization_pending') {
                    throw
                }
            }
        }

        if (-not $ArmToken) {
            Write-Warning 'Azure authentication timed out. Skipping Azure RBAC assignment.'
            Write-Warning "Manually assign roles via: New-AzRoleAssignment -ObjectId $($Sp.Id) -RoleDefinitionName 'Security Reader' -Scope /subscriptions/<SubscriptionId>"
        }
        else {
            Write-Host '[+] Azure authentication successful' -ForegroundColor Green
            $ArmHeaders = @{ Authorization = "Bearer $ArmToken" }

            # Get subscriptions (or use provided IDs)
            if ($SubscriptionIds) {
                $Subscriptions = foreach ($SubId in $SubscriptionIds) {
                    try {
                        Invoke-RestMethod -Uri "https://management.azure.com/subscriptions/${SubId}?api-version=2022-12-01" -Headers $ArmHeaders -ErrorAction Stop
                    }
                    catch {
                        Write-Warning "Subscription '$SubId' not found or not accessible."
                    }
                }
            }
            else {
                $Subscriptions = (Invoke-RestMethod -Uri 'https://management.azure.com/subscriptions?api-version=2022-12-01' -Headers $ArmHeaders -ErrorAction Stop).value
            }

            if (-not $Subscriptions) {
                Write-Warning 'No accessible Azure subscriptions found.'
            }
            else {
                Write-Host "[*] Found $(@($Subscriptions).Count) subscription(s)" -ForegroundColor Cyan
            }

            foreach ($RoleName in $AzureRoles) {
                foreach ($Sub in $Subscriptions) {
                    $SubId   = $Sub.subscriptionId
                    $SubName = $Sub.displayName

                    try {
                        # Look up role definition by name
                        $EncodedFilter = [System.Uri]::EscapeDataString("roleName eq '$RoleName'")
                        $RoleDefs = (Invoke-RestMethod -Uri "https://management.azure.com/subscriptions/${SubId}/providers/Microsoft.Authorization/roleDefinitions?`$filter=${EncodedFilter}&api-version=2022-04-01" -Headers $ArmHeaders -ErrorAction Stop).value

                        if (-not $RoleDefs) {
                            throw "Role definition '$RoleName' not found."
                        }

                        $AssignmentId = [guid]::NewGuid().ToString()
                        $AssignmentBody = @{
                            properties = @{
                                roleDefinitionId = $RoleDefs[0].id
                                principalId      = $Sp.Id
                                principalType    = 'ServicePrincipal'
                            }
                        } | ConvertTo-Json -Depth 5

                        $RoleAssignParams = @{
                            Method      = 'Put'
                            Uri         = "https://management.azure.com/subscriptions/${SubId}/providers/Microsoft.Authorization/roleAssignments/${AssignmentId}?api-version=2022-04-01"
                            Headers     = $ArmHeaders
                            Body        = $AssignmentBody
                            ContentType = 'application/json'
                            ErrorAction = 'Stop'
                        }
                        $null = Invoke-RestMethod @RoleAssignParams

                        Write-Host "[+] ${SubName}: " -ForegroundColor Green -NoNewline
                        Write-Host "$RoleName assigned" -ForegroundColor White
                        [void]$AzureRbacResults.Assigned.Add("$SubName - $RoleName")
                    }
                    catch {
                        if ($_.ErrorDetails.Message -match 'RoleAssignmentExists') {
                            Write-Host "[+] ${SubName}: " -ForegroundColor Green -NoNewline
                            Write-Host "$RoleName already assigned" -ForegroundColor White
                            [void]$AzureRbacResults.Assigned.Add("$SubName - $RoleName")
                        }
                        else {
                            Write-Host "[-] ${SubName}: " -ForegroundColor Red -NoNewline
                            Write-Host "Failed ($RoleName) - $($_.Exception.Message)" -ForegroundColor White
                            [void]$AzureRbacResults.Failed.Add("$SubName - $RoleName")
                        }
                    }
                }
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
        ClientSecret          = if ($Secret) { $Secret.SecretText } else { $null }
        SecretExpires         = if ($Secret) { $Secret.EndDateTime } else { $null }
        CertificateThumbprint = if ($CertificateInfo) { $CertificateInfo.Thumbprint } else { $null }
        CertificateExpires    = if ($CertificateInfo) { $CertificateInfo.Expires } else { $null }
        GraphPermissions      = "$($GrantResults.Graph.Granted)/$($AppPermissions[$GraphAppId].Count)"
        ExoPermissions        = "$($GrantResults.Exchange.Granted)/$($AppPermissions[$ExoAppId].Count)"
        AzurePermissions      = "$($GrantResults.Azure.Granted)/$($DelegatedPermissions.Values.ForEach({ $_.Count }) -join '')"
        DirectoryRoles        = if ($RoleResults.Assigned) { $RoleResults.Assigned -join ', ' } else { $null }
        AzureRbacRoles        = if ($AzureRbacResults.Assigned) { $AzureRbacResults.Assigned -join ', ' } else { $null }
    }

    if ($Secret) {
        Write-Host "`n[!] SAVE YOUR SECRET NOW - it won't be shown again!" -ForegroundColor Yellow -BackgroundColor DarkRed
    }

    if ($CertificateInfo -and $CreateSelfSignedCertificate) {
        Write-Host "`n[!] Self-signed certificate created:" -ForegroundColor Yellow
        Write-Host "    Thumbprint : $($CertificateInfo.Thumbprint)" -ForegroundColor Yellow
        Write-Host "    Expires    : $($CertificateInfo.Expires)" -ForegroundColor Yellow
        Write-Host "    Store      : Cert:\CurrentUser\My" -ForegroundColor Yellow
        Write-Host "    Remember to export the certificate (.pfx) for backup or deployment to other machines." -ForegroundColor Yellow
    }
    elseif ($CertificateInfo) {
        Write-Host "`n[+] Existing certificate uploaded:" -ForegroundColor Green
        Write-Host "    Thumbprint : $($CertificateInfo.Thumbprint)" -ForegroundColor Green
        Write-Host "    Expires    : $($CertificateInfo.Expires)" -ForegroundColor Green
    }
    #endregion
}

end {
    $null = Disconnect-MgGraph
}
