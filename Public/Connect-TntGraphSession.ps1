function Connect-TntGraphSession {
    <#
    .SYNOPSIS
        Establishes connections to Microsoft cloud services using app registration credentials with proper state management.

    .DESCRIPTION
        This internal helper function manages connections to Microsoft Graph and other Microsoft cloud services
        for the Security Reporting module. It checks for existing connections, validates tenant context, and
        establishes new connections as needed. The function returns connection state information to enable
        proper cleanup by calling functions.

    .PARAMETER TenantId
        The Azure AD Tenant ID to connect to.

    .PARAMETER ClientId
        The Application (Client) ID of the app registration.

    .PARAMETER ClientSecret
        The client secret for the app registration (for client secret authentication).

    .PARAMETER CertificateThumbprint
        The certificate thumbprint (for certificate-based authentication).

    .PARAMETER Scope
        The target service scope. Supports Graph, Azure, Teams, Exchange, Partner, or custom scope URIs.
        Defaults to 'Graph' for Microsoft Graph API.

    .PARAMETER Scopes
        Additional scopes to request for Microsoft Graph connections. Only used when Scope is 'Graph'.

    .PARAMETER ConnectionType
        Type of connection to establish. Valid values: 'Graph' (uses Connect-MgGraph), 'RestApi' (uses token-based auth).
        Defaults to 'Graph' for backward compatibility.

    .EXAMPLE
        $ConnectionInfo = Connect-TntGraphSession -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret

        Establishes a Microsoft Graph connection using client secret and returns connection state information.

    .EXAMPLE
        $ConnectionInfo = Connect-TntGraphSession -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret -Scope Azure -ConnectionType RestApi

        Establishes an Azure Resource Manager connection using REST API token-based authentication.

    .EXAMPLE
        $ConnectionInfo = Connect-TntGraphSession -TenantId $TenantId -ClientId $ClientId -CertificateThumbprint $Thumbprint -Scope Graph

        Establishes a Microsoft Graph connection using certificate authentication.

    .EXAMPLE
        $ConnectionInfo = Connect-TntGraphSession -TenantId $TenantId -ClientId $ClientId -CertificateThumbprint $Thumbprint -Scope Azure -ConnectionType RestApi

        Establishes an Azure Resource Manager REST API connection using certificate authentication with JWT bearer assertion.

    .EXAMPLE
        $ConnectionInfo = Connect-TntGraphSession -Interactive

        Establishes an interactive Microsoft Graph connection using device code flow.
        No app registration required - uses Microsoft's built-in multi-tenant app.
        A code is printed to the console; open the displayed URL in a browser to sign in.
        Device code flow is used to bypass WAM (Web Account Manager) on Windows, which
        would otherwise prompt for re-authentication on each individual Graph SDK call.

    .OUTPUTS
        PSCustomObject with connection state information:
        - ShouldDisconnect: Boolean indicating if the calling function should disconnect when finished
        - OriginalContext: The original MgContext before this function was called (Graph connections only)
        - Connected: Boolean indicating successful connection
        - TenantId: The connected tenant ID
        - Scope: The scope used for connection
        - ConnectionType: The type of connection established
        - AccessToken: The access token for REST API connections
        - Headers: HTTP headers for REST API connections

    .NOTES
        Author: Tom de Leeuw
        Website: https://systom.dev
        Module: TenantReports

        This is an internal helper function for the Security Reporting module.
        Calling functions are responsible for disconnecting if ShouldDisconnect is $true.

        SUPPORTED CONNECTION TYPES:
        - Graph: Uses Connect-MgGraph cmdlet (Microsoft Graph PowerShell SDK)
        - RestApi: Uses direct REST API calls with access tokens

    .LINK
        https://systom.dev
    #>

    [CmdletBinding(DefaultParameterSetName = 'ClientSecret')]
    [OutputType([System.Management.Automation.PSObject])]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = 'ClientSecret')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Certificate')]
        [Parameter(ParameterSetName = 'Interactive')]
        [ValidateNotNullOrEmpty()]
        [string]$TenantId,

        [Parameter(Mandatory = $true, ParameterSetName = 'ClientSecret')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Certificate')]
        [Parameter(ParameterSetName = 'Interactive')]
        [ValidatePattern('^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$')]
        [string]$ClientId,

        [Parameter(Mandatory = $true, ParameterSetName = 'ClientSecret')]
        [ValidateNotNullOrEmpty()]
        [SecureString]$ClientSecret,

        [Parameter(Mandatory = $true, ParameterSetName = 'Certificate')]
        [ValidateNotNullOrEmpty()]
        [string]$CertificateThumbprint,

        [Parameter(Mandatory = $true, ParameterSetName = 'Interactive')]
        [switch]$Interactive,

        [Parameter(ParameterSetName = 'ClientSecret')]
        [Parameter(ParameterSetName = 'Certificate')]
        [Parameter(ParameterSetName = 'Interactive')]
        [ValidateScript({
                $PredefinedScopes = @('Graph', 'Teams', 'Exchange', 'Partner', 'Azure')
                if ($_ -in $PredefinedScopes) {
                    return $true
                }
                try {
                    $Uri = [System.Uri]$_
                    return $Uri.IsAbsoluteUri -and $_.EndsWith('/.default')
                } catch {
                    throw "Scope must be one of: $($PredefinedScopes -join ', ') or a valid URI ending with '/.default'"
                }
            })]
        [string]$Scope = 'Graph',

        [Parameter()]
        [string[]]$Scopes = @('https://graph.microsoft.com/.default'),

        [Parameter(ParameterSetName = 'ClientSecret')]
        [Parameter(ParameterSetName = 'Certificate')]
        [Parameter(ParameterSetName = 'Interactive')]
        [ValidateSet('Graph', 'RestApi')]
        [string]$ConnectionType = 'Graph'
    )

    begin {
        # For non-interactive auth, TenantId and ClientId are required
        if (-not $Interactive) {
            if ([string]::IsNullOrWhiteSpace($TenantId) -or [string]::IsNullOrWhiteSpace($ClientId)) {
                $errorRecord = [System.Management.Automation.ErrorRecord]::new(
                    [System.Exception]::new('Connect-TntGraphSession failed: TenantId and ClientId are required parameters for non-interactive authentication.'),
                    'ConnectTntGraphSessionParameterValidationError',
                    [System.Management.Automation.ErrorCategory]::InvalidArgument,
                    $null
                )
                $PSCmdlet.ThrowTerminatingError($errorRecord)
            }
        }

        # Define valid connection parameters for filtering
        if (-not $script:ValidConnectionParams) {
            $script:ValidConnectionParams = @(
                'TenantId', 'ClientId', 'ClientSecret', 'CertificateThumbprint',
                'Scope', 'Scopes', 'ConnectionType', 'Interactive'
            )
        }
    }

    process {
        # Handle Interactive authentication separately
        if ($Interactive) {
            # First, check if there's already a valid MgGraph connection we can reuse
            $ExistingContext = Get-MgContext -ErrorAction SilentlyContinue
            if ($ExistingContext) {
                Write-Verbose "Reusing existing Microsoft Graph connection to tenant: $($ExistingContext.TenantId)"
                return [PSCustomObject]@{
                    ShouldDisconnect = $false
                    OriginalContext  = $ExistingContext
                    Connected        = $true
                    TenantId         = $ExistingContext.TenantId
                    ClientId         = $ExistingContext.ClientId
                    Scope            = 'Graph'
                    ConnectionType   = 'Graph'
                    AccessToken      = $null
                    Headers          = $null
                    ErrorMessage     = $null
                    ServiceType      = 'Microsoft Graph (Interactive)'
                    IsInteractive    = $true
                }
            }

            # No existing connection, need to establish one
            $ConnectionState = [PSCustomObject]@{
                ShouldDisconnect = $false
                OriginalContext  = $null
                Connected        = $false
                TenantId         = $null
                ClientId         = $null
                Scope            = 'Graph'
                ConnectionType   = 'Graph'
                AccessToken      = $null
                Headers          = $null
                ErrorMessage     = $null
                ServiceType      = $null
                IsInteractive    = $true
            }

            try {
                Write-Verbose 'Establishing new interactive Microsoft Graph connection...'

                # Define delegated scopes needed for TenantReports
                # NOTE: The interactive flow only acquires a Microsoft Graph token.
                # Azure Resource Manager (https://management.azure.com) requires a
                # separate token with a different audience/scope, so AzureSecureScore
                # is skipped in interactive mode until a dedicated ARM device-code flow
                # is implemented in this function.
                $DelegatedScopes = @(
                    'User.Read.All'
                    'AuditLog.Read.All'
                    'Directory.Read.All'
                    'Policy.Read.All'
                    'SecurityEvents.Read.All'
                    'SecurityIncident.Read.All'
                    'RoleManagement.Read.Directory'
                    'DeviceManagementManagedDevices.Read.All'
                    'DeviceManagementConfiguration.Read.All'
                    'DeviceManagementApps.Read.All'
                    'Application.Read.All'
                    'Organization.Read.All'
                    'Reports.Read.All'
                    'MailboxSettings.Read'
                    'Calendars.Read'
                )

                # Implement device code flow via REST to bypass two problems:
                # 1. WAM (Web Account Manager) - defers token acquisition per Graph SDK call,
                #    causing a re-authentication popup for each cmdlet (Get-MgGroup, etc.).
                # 2. PowerShell module-scope stream suppression - Connect-MgGraph's built-in
                #    -UseDeviceAuthentication writes the device code via WriteInformation(),
                #    which is suppressed by $InformationPreference = 'SilentlyContinue' in
                #    module function scope even when the caller's session has it set to Continue.
                # By requesting the device code ourselves and using Write-Host, the prompt is
                # always visible. The resulting access token is passed to Connect-MgGraph
                # directly, bypassing both WAM and the stream display issue.
                Write-Information 'STARTED  : interactive authentication - requesting device code...' -InformationAction Continue

                # 14d82eec-204b-4c2f-b7e8-296a70dab67e is the Microsoft Graph PowerShell SDK
                # public client app - the same app Connect-MgGraph -UseDeviceAuthentication uses.
                $PublicClientId = '14d82eec-204b-4c2f-b7e8-296a70dab67e'
                $DeviceCodeUri  = 'https://login.microsoftonline.com/common/oauth2/v2.0/devicecode'
                $TokenUri       = 'https://login.microsoftonline.com/common/oauth2/v2.0/token'
                $ScopeString    = (($DelegatedScopes | ForEach-Object { "https://graph.microsoft.com/$_" }) + @('openid', 'profile', 'offline_access')) -join ' '

                $DeviceCodeBody = @{
                    client_id = $PublicClientId
                    scope     = $ScopeString
                }
                $DeviceCodeResult = Invoke-RestMethod -Uri $DeviceCodeUri -Method Post -Body $DeviceCodeBody -ErrorAction Stop

                Write-Information "$($DeviceCodeResult.message)" -InformationAction Continue

                $TokenBody = @{
                    client_id   = $PublicClientId
                    grant_type  = 'urn:ietf:params:oauth:grant-type:device_code'
                    device_code = $DeviceCodeResult.device_code
                }

                $AccessToken  = $null
                $PollInterval = [int]$DeviceCodeResult.interval
                $ExpiresAt    = [DateTime]::UtcNow.AddSeconds([int]$DeviceCodeResult.expires_in)

                while ([DateTime]::UtcNow -lt $ExpiresAt) {
                    Start-Sleep -Seconds $PollInterval
                    try {
                        $TokenResult = Invoke-RestMethod -Uri $TokenUri -Method Post -Body $TokenBody -ErrorAction Stop
                        $AccessToken = $TokenResult.access_token
                        break
                    } catch {
                        $PollErrorBody = $_.ErrorDetails.Message | ConvertFrom-Json -ErrorAction SilentlyContinue
                        $PollErrorCode = if ($PollErrorBody) { $PollErrorBody.error } else { 'unknown' }

                        if ($PollErrorCode -eq 'authorization_pending') {
                            # Expected - user has not yet authenticated
                        } elseif ($PollErrorCode -eq 'slow_down') {
                            $PollInterval += 5
                        } elseif ($PollErrorCode -eq 'access_denied') {
                            throw 'Interactive authentication was denied or cancelled.'
                        } elseif ($PollErrorCode -eq 'expired_token') {
                            throw 'Device code expired. Please run the command again.'
                        } else {
                            $PollErrorMessage = if ($PollErrorBody) { $PollErrorBody.error_description } else { $_.Exception.Message }
                            throw "Authentication polling failed: $PollErrorMessage"
                        }
                    }
                }

                if (-not $AccessToken) {
                    throw 'Device code authentication timed out. Please run the command again.'
                }

                $SecureToken = ConvertTo-SecureString -String $AccessToken -AsPlainText -Force
                $ConnectParams = @{
                    AccessToken = $SecureToken
                    NoWelcome   = $true
                    ErrorAction = 'Stop'
                }
                Connect-MgGraph @ConnectParams

                $NewContext = Get-MgContext -ErrorAction Stop
                if ($NewContext) {
                    Write-Verbose "Successfully connected interactively to tenant: $($NewContext.TenantId)"
                    $ConnectionState.Connected = $true
                    $ConnectionState.TenantId = $NewContext.TenantId
                    $ConnectionState.ClientId = $NewContext.ClientId
                    $ConnectionState.ShouldDisconnect = $true
                    $ConnectionState.ServiceType = 'Microsoft Graph (Interactive)'
                    Write-Information "Connected to tenant: $($NewContext.TenantId)" -InformationAction Continue
                } else {
                    $errorRecord = [System.Management.Automation.ErrorRecord]::new(
                        [System.Exception]::new('Connect-TntGraphSession failed: Interactive authentication completed but no Graph context was established.'),
                        'ConnectTntGraphSessionInteractiveContextError',
                        [System.Management.Automation.ErrorCategory]::ConnectionError,
                        $TenantId
                    )
                    $PSCmdlet.ThrowTerminatingError($errorRecord)
                }

                return $ConnectionState
            } catch {
                $ConnectionState.Connected = $false
                $ConnectionState.ErrorMessage = $_.Exception.Message
                $errorRecord = [System.Management.Automation.ErrorRecord]::new(
                    [System.Exception]::new("Connect-TntGraphSession failed to establish interactive connection: $($_.Exception.Message)", $_.Exception),
                    'ConnectTntGraphSessionInteractiveConnectionError',
                    [System.Management.Automation.ErrorCategory]::ConnectionError,
                    $TenantId
                )
                $PSCmdlet.ThrowTerminatingError($errorRecord)
            }
        }

        $ConnectionState = [PSCustomObject]@{
            ShouldDisconnect = $false
            OriginalContext  = $null
            Connected        = $false
            TenantId         = $TenantId
            ClientId         = $ClientId
            Scope            = $Scope
            ConnectionType   = $ConnectionType
            AccessToken      = $null
            Headers          = $null
            ErrorMessage     = $null
            ServiceType      = $null
            IsInteractive    = $false
        }

        # Orchestrator-established connections are reused to avoid redundant auth calls
        # Only reuse for Graph SDK connections, not REST API token-based connections (e.g., Azure ARM)
        if ($script:ConnectionEstablishedByOrchestrator -and
            $ConnectionType -eq 'Graph' -and
            $Scope -eq 'Graph' -and
            (Get-MgContext -ErrorAction SilentlyContinue)) {
            $ExistingContext = Get-MgContext
            if ($ExistingContext.TenantId -eq $TenantId) {
                Write-Verbose 'Reusing orchestrator-established connection'
                $ConnectionState.Connected = $true
                $ConnectionState.ShouldDisconnect = $false
                $ConnectionState.ServiceType = 'Microsoft Graph (Orchestrator)'
                return $ConnectionState
            }
        }

        try {
            switch ($ConnectionType) {
                'Graph' {
                    $ConnectionState.OriginalContext = Get-MgContext -ErrorAction SilentlyContinue

                    # Check if already connected to the correct tenant for Graph
                    if ($ConnectionState.OriginalContext -and
                        $ConnectionState.OriginalContext.TenantId -eq $TenantId -and
                        $Scope -eq 'Graph') {
                        Write-Verbose 'Using existing Microsoft Graph connection'
                        $ConnectionState.Connected = $true
                        $ConnectionState.ShouldDisconnect = $false
                        $ConnectionState.ServiceType = 'Microsoft Graph'
                        return $ConnectionState
                    }

                    if ($ConnectionState.OriginalContext) {
                        Write-Verbose "Currently connected to different tenant: $($ConnectionState.OriginalContext.TenantId)"
                    } else {
                        Write-Verbose 'No existing Microsoft Graph connection found'
                    }

                    Write-Verbose "Establishing new Microsoft Graph SDK connection. Tenant ID: $($TenantId)"

                    if ($PSCmdlet.ParameterSetName -eq 'ClientSecret') {
                        Write-Verbose 'Using client secret authentication'

                        try {
                            $TokenParams = @{
                                TenantId     = $TenantId
                                ClientId     = $ClientId
                                ClientSecret = $ClientSecret
                                Scope        = $Scope
                            }

                            $AccessTokenInfo = Get-GraphToken @TokenParams -ErrorAction Stop

                            Connect-MgGraph -AccessToken $AccessTokenInfo.SecureAccessToken -NoWelcome -ErrorAction Stop
                        } catch {
                            throw "Failed to authenticate using client secret: $($_.Exception.Message)"
                        }

                    } elseif ($PSCmdlet.ParameterSetName -eq 'Certificate') {
                        Write-Verbose 'Using certificate authentication'

                        $ConnectParams = @{
                            TenantId              = $TenantId
                            ClientId              = $ClientId
                            CertificateThumbprint = $CertificateThumbprint
                            NoWelcome             = $true
                        }

                        if ($Scopes -and $Scopes.Count -gt 0 -and $Scopes[0] -ne 'https://graph.microsoft.com/.default') {
                            $ConnectParams['Scopes'] = $Scopes
                        }

                        Connect-MgGraph @ConnectParams -ErrorAction Stop
                    }

                    $NewContext = Get-MgContext -ErrorAction Stop
                    if ($NewContext.TenantId -eq $TenantId) {
                        Write-Verbose "Successfully connected to tenant: $($TenantId)"

                        $ConnectionState.Connected = $true
                        $ConnectionState.ShouldDisconnect = $true
                        $ConnectionState.ServiceType = 'Microsoft Graph'
                    } else {
                        throw "Connected to wrong tenant. Expected: $($TenantId), Actual: $($NewContext.TenantId)"
                    }
                }

                'RestApi' {
                    Write-Verbose "Establishing REST API token-based connection. Tenant ID: $($TenantId)"

                    try {
                        if ($PSCmdlet.ParameterSetName -eq 'Certificate') {
                            Write-Verbose 'Using Certificate authentication'
                            $TokenParams = @{
                                TenantId              = $TenantId
                                ClientId              = $ClientId
                                CertificateThumbprint = $CertificateThumbprint
                                Scope                 = $Scope
                            }
                        } else {
                            Write-Verbose 'Using Client Credentials authentication'
                            $TokenParams = @{
                                TenantId     = $TenantId
                                ClientId     = $ClientId
                                ClientSecret = $ClientSecret
                                Scope        = $Scope
                            }
                        }

                        $AccessTokenInfo = Get-GraphToken @TokenParams -ErrorAction Stop

                        $ConnectionState.AccessToken = $AccessTokenInfo.SecureAccessToken
                        $ConnectionState.Headers = $AccessTokenInfo.Header
                        $ConnectionState.Connected = $true
                        $ConnectionState.ShouldDisconnect = $false  # No explicit disconnect needed for tokens
                        $ConnectionState.ServiceType = $AccessTokenInfo.ServiceType

                        Write-Verbose "Successfully obtained secure access token for: $($AccessTokenInfo.ServiceType). Expires at: $($AccessTokenInfo.ExpiresAt)"
                    } catch {
                        throw "Failed to obtain access token: $($_.Exception.Message)"
                    }
                }
            }

            return $ConnectionState

        } catch {
            $ConnectionState.Connected = $false
            $ConnectionState.ErrorMessage = $_.Exception.Message
            $ErrorDetails = $_.Exception.Message

            if ($_.Exception.Message -match 'AADSTS700016|Invalid client_id') {
                Write-Warning @"
The application (client) ID was not found in the tenant. Please verify:
1. The Client ID is correct: $($ClientId)
2. The application exists in tenant: $($TenantId)
3. You're connecting to the correct tenant
"@
            } elseif ($_.Exception.Message -match 'AADSTS7000215|Invalid client secret') {
                Write-Warning @'
The client secret is invalid. Please verify:
1. The client secret has not expired
2. The secret value is entered correctly
3. You're using the secret value, not the secret ID
'@
            } elseif ($_.Exception.Message -match 'AADSTS700027|Certificate') {
                Write-Warning @"
Certificate authentication failed. Please verify:
1. The certificate is installed in the current user or local machine store
2. The certificate thumbprint is correct: $($CertificateThumbprint)
3. The certificate has not expired
4. The certificate is associated with the app registration
"@
            } elseif ($ErrorDetails -match 'AADSTS65001|consent') {
                Write-Warning @"
The application lacks required permissions. Please ensure:
1. Required API permissions are configured for scope: $($Scope)
2. Admin consent has been granted for all permissions
3. Permissions are application permissions, not delegated
"@
            } else {
                $GuidanceMessage = @"
Common causes for connection failures:
1. Incorrect Client ID or Tenant ID
2. Expired or invalid credentials
3. Network connectivity issues
4. Required permissions not granted
5. Conditional Access policies blocking the connection

Verify your app registration at:
https://portal.azure.com/#blade/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/Overview/appId/$($ClientId)
"@

                # Add scope-specific guidance
                if ($Scope -eq 'Azure') {
                    $GuidanceMessage += @"

For Azure Resource Manager access:
- App registration needs 'Azure Service Management' API permissions
- Service principal requires RBAC role assignments on target resources
- Verify role assignments: Get-AzRoleAssignment -ServicePrincipalName $($ClientId)
"@
                }

                Write-Warning $GuidanceMessage
            }

            $ErrorCategory = switch -Regex ($ErrorDetails) {
                'AADSTS700016|Invalid client_id|AADSTS7000215|Invalid client secret|AADSTS700027|Certificate|AADSTS65001|consent' {
                    [System.Management.Automation.ErrorCategory]::AuthenticationError
                    break
                }
                default {
                    [System.Management.Automation.ErrorCategory]::ConnectionError
                }
            }

            $errorRecord = [System.Management.Automation.ErrorRecord]::new(
                [System.Exception]::new("Connect-TntGraphSession failed to establish $ConnectionType connection for scope '$Scope' in tenant '$TenantId': $ErrorDetails", $_.Exception),
                'ConnectTntGraphSessionConnectionError',
                $ErrorCategory,
                $TenantId
            )
            $PSCmdlet.ThrowTerminatingError($errorRecord)
        }
    }
}
