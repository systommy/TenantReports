function Get-GraphToken {
    <#
    .SYNOPSIS
        Retrieves access tokens for Microsoft Graph API and other Microsoft cloud services.

    .DESCRIPTION
        This function obtains OAuth2 access tokens using client credentials flow for various Microsoft cloud services
        including Microsoft Graph, Teams, Exchange, Partner Center, and Azure Resource Manager. It supports both
        legacy scope names and direct scope URIs for maximum flexibility.

    .PARAMETER TenantId
        The Azure AD Tenant ID to authenticate against.

    .PARAMETER ClientId
        The Application (Client) ID of the Azure AD app registration.

    .PARAMETER ClientSecret
        The client secret for the Azure AD app registration.

    .PARAMETER Scope
        The target service scope. Supports predefined values (Graph, Teams, Exchange, Partner, Azure)
        or direct scope URIs (e.g., 'https://management.azure.com/.default').

    .EXAMPLE
        $Token = Get-GraphToken -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret -Scope Graph
        Retrieves a Microsoft Graph access token.

    .EXAMPLE
        $ArmToken = Get-GraphToken -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret -Scope Azure
        Retrieves an Azure Resource Manager access token.

    .EXAMPLE
        $CustomToken = Get-GraphToken -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret -Scope 'https://vault.azure.net/.default'
        Retrieves a token for Azure Key Vault using direct scope URI.

    .OUTPUTS
        System.Management.Automation.PSObject
        Returns a token information object with SecureAccessToken, AccessToken, TokenType, ExpiresIn, ExpiresAt, Scope, TenantId, ClientId, Header, and GetSecureHeader properties.

    .NOTES
        Author: Tom de Leeuw
        Website: https://systom.dev
        Module: TenantReports

        SUPPORTED SCOPES:
        - Graph: Microsoft Graph API (https://graph.microsoft.com/.default)
        - Teams: Microsoft Teams API (https://api.spaces.skype.com/.default)
        - Exchange: Exchange Online API (https://outlook.office365.com/.default)
        - Partner: Partner Center API (https://api.partnercenter.microsoft.com/.default)
        - Azure: Azure Resource Manager API (https://management.azure.com/.default)
        - Custom: Any valid scope URI

    .LINK
        https://systom.dev
    #>

    [CmdletBinding(DefaultParameterSetName = 'ClientCredentials')]
    [OutputType([System.Management.Automation.PSObject])]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'ClientCredentials')]
        [Parameter(Mandatory = $false, ParameterSetName = 'ManagedIdentity')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Interactive')]
        [ValidateNotNullOrEmpty()]
        [string]$TenantId,

        [Parameter(Mandatory = $true, ParameterSetName = 'ClientCredentials')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Interactive')]
        [Alias('ApplicationId')]
        [ValidatePattern('^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$')]
        [string]$ClientId,

        [Parameter(Mandatory = $true, ParameterSetName = 'ClientCredentials')]
        [Alias('ApplicationSecret')]
        [ValidateNotNullOrEmpty()]
        [SecureString]$ClientSecret,

        [Parameter(Mandatory = $true, ParameterSetName = 'ManagedIdentity')]
        [switch]$UseManagedIdentity,

        [Parameter(Mandatory = $true, ParameterSetName = 'Interactive')]
        [switch]$Interactive,

        [Parameter(Mandatory = $false)]
        [ValidateScript({
                # Allow predefined scope names or valid URIs
                $PredefinedScopes = @('Graph', 'Teams', 'Exchange', 'Partner', 'Azure')
                if ($_ -in $PredefinedScopes) {
                    return $true
                }
                # Validate URI format for custom scopes
                try {
                    $Uri = [System.Uri]$_
                    return $Uri.IsAbsoluteUri -and $_.EndsWith('/.default')
                } catch {
                    throw "Scope must be one of: $($PredefinedScopes -join ', ') or a valid URI ending with '/.default'"
                }
            })]
        [string]$Scope = 'Graph'
    )

    begin {
        if (-not $script:TokenCache) {
            $script:TokenCache = @{}
        }

        $ScopeMapping = @{
            'Graph'    = 'https://graph.microsoft.com/.default'
            'Teams'    = 'https://api.spaces.skype.com/.default'
            'Exchange' = 'https://outlook.office365.com/.default'
            'Partner'  = 'https://api.partnercenter.microsoft.com/.default'
            'Azure'    = 'https://management.azure.com/.default'
        }
    }

    process {
        try {
            # Determine the actual scope URI
            $ScopeUri = if ($ScopeMapping.ContainsKey($Scope)) {
                $ScopeMapping[$Scope]
            } else {
                # Assume it's a direct URI
                $Scope
            }

            # Create cache key
            $CacheKey = if ($Interactive) {
                "$ScopeUri-Interactive"
            } elseif ($UseManagedIdentity) {
                "$ScopeUri-ManagedIdentity"
            } else {
                "$ScopeUri-$ClientId-$TenantId"
            }

            # Refresh tokens 5 minutes before expiration to prevent mid-operation failures
            if ($script:TokenCache.ContainsKey($CacheKey)) {
                $CachedToken = $script:TokenCache[$CacheKey]
                if ($CachedToken.ExpiresAt -gt (Get-Date).AddMinutes(5)) {
                    Write-Verbose "Using cached token (expires: $($CachedToken.ExpiresAt))"
                    return $CachedToken
                }
                Write-Verbose 'Cached token expired, removing'
                $script:TokenCache.Remove($CacheKey)
            }

            Write-Verbose "Retrieving $($Scope) access token for scope: $($ScopeUri)"

            if ($Interactive) {
                Write-Verbose 'Using Interactive authentication (delegated permissions)'

                # For interactive auth, we leverage the existing MgGraph connection
                # Return a token info object that signals interactive mode
                $MgContext = Get-MgContext -ErrorAction SilentlyContinue
                if (-not $MgContext) {
                    $errorRecord = [System.Management.Automation.ErrorRecord]::new(
                        [System.Exception]::new('Get-GraphToken failed: No active Microsoft Graph connection found. Use Connect-TntGraphSession -Interactive first.'),
                        'GetGraphTokenInteractiveNoConnectionError',
                        [System.Management.Automation.ErrorCategory]::ConnectionError,
                        $null
                    )
                    $PSCmdlet.ThrowTerminatingError($errorRecord)
                }

                # For interactive mode, return a special token info object
                # that indicates to use Invoke-MgGraphRequest instead of REST with bearer tokens
                $TokenInfo = [PSCustomObject]@{
                    SecureAccessToken = $null  # Not used for interactive
                    TokenType         = 'Interactive'
                    ExpiresIn         = 3600  # Nominal - MgGraph handles token refresh
                    ExpiresAt         = (Get-Date).AddHours(1)
                    Scope             = $ScopeUri
                    ServiceType       = $Scope
                    TenantId          = $MgContext.TenantId
                    ClientId          = $MgContext.ClientId
                    IsExpired         = $false
                    CreatedAt         = Get-Date
                    IsInteractive     = $true
                    GetSecureHeader   = $null  # Not used for interactive
                } | Add-Member -MemberType ScriptMethod -Name 'IsTokenExpired' -Value {
                    # For interactive, check if MgGraph context is still valid
                    $ctx = Get-MgContext -ErrorAction SilentlyContinue
                    return $null -eq $ctx
                } -PassThru | Add-Member -MemberType ScriptMethod -Name 'ClearToken' -Value {
                    # No-op for interactive - Disconnect-MgGraph handles cleanup
                } -PassThru | Add-Member -MemberType ScriptProperty -Name 'AccessToken' -Value {
                    # For interactive, return null - callers should use Invoke-MgGraphRequest
                    return $null
                } -PassThru | Add-Member -MemberType ScriptProperty -Name 'Header' -Value {
                    # For interactive, return null - callers should use Invoke-MgGraphRequest
                    return $null
                } -PassThru

                # Cache and return
                $script:TokenCache[$CacheKey] = $TokenInfo
                Write-Verbose "Interactive token info cached with key: $CacheKey"
                return $TokenInfo

            } elseif ($UseManagedIdentity) {
                Write-Verbose 'Using Managed Identity for authentication'

                # Use Azure Managed Identity to obtain token
                try {
                    # Get the resource URL from scope URI (remove /.default)
                    $ResourceUrl = $ScopeUri -replace '/\.default$', ''

                    Write-Verbose "Requesting Managed Identity token for resource: $ResourceUrl"

                    # Call Az.Accounts cmdlet for Managed Identity token
                    $AzToken = Get-AzAccessToken -ResourceUrl $ResourceUrl -ErrorAction Stop

                    # Build token request response object to match client credentials format
                    $TokenRequest = [PSCustomObject]@{
                        access_token = $AzToken.Token
                        token_type   = 'Bearer'
                        expires_in   = [int](($AzToken.ExpiresOn.UtcDateTime - (Get-Date).ToUniversalTime()).TotalSeconds)
                    }
                } catch {
                    $errorRecord = [System.Management.Automation.ErrorRecord]::new(
                        [System.Exception]::new("Get-GraphToken failed to obtain token using Managed Identity: $($_.Exception.Message)", $_.Exception),
                        'GetGraphTokenManagedIdentityError',
                        [System.Management.Automation.ErrorCategory]::AuthenticationError,
                        $null
                    )
                    $PSCmdlet.ThrowTerminatingError($errorRecord)
                }
            } else {
                Write-Verbose 'Using Client Credentials for authentication'

                # Convert SecureString to plain text for OAuth request
                $bstrPtr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($ClientSecret)
                try {
                    $PlainClientSecret = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstrPtr)
                } finally {
                    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstrPtr)
                }

                # Prepare authentication body for client credentials flow
                $AuthBody = @{
                    client_id     = $ClientId
                    client_secret = $PlainClientSecret
                    scope         = $ScopeUri
                    grant_type    = 'client_credentials'
                }

                # Use v2.0 endpoint for OAuth2
                $TokenUri = "https://login.microsoftonline.com/$($TenantId)/oauth2/v2.0/token"

                # Request the token
                try {
                    $TokenRequest = Invoke-RestMethod -Method Post -Uri $TokenUri -Body $AuthBody -ContentType 'application/x-www-form-urlencoded' -ErrorAction Stop
                } catch {
                    $errorRecord = [System.Management.Automation.ErrorRecord]::new(
                        [System.Exception]::new("Get-GraphToken failed to obtain token using Client Credentials: $($_.Exception.Message)", $_.Exception),
                        'GetGraphTokenClientCredentialsError',
                        [System.Management.Automation.ErrorCategory]::AuthenticationError,
                        $null
                    )
                    $PSCmdlet.ThrowTerminatingError($errorRecord)
                } finally {
                    # Clear plain text secret from memory
                    $PlainClientSecret = $null
                    if ($AuthBody) {
                        $AuthBody.Clear()
                    }
                }
            }

            # Convert to read-only SecureString to prevent modification after creation
            if ($TokenRequest.access_token) {
                $SecureAccessToken = ConvertTo-SecureString -String $TokenRequest.access_token -AsPlainText -Force
                $SecureAccessToken.MakeReadOnly()
            }

            # Store ONLY the secure token in script scope - never store plain text
            $script:AccessToken = $SecureAccessToken

            # Create secure authorization header function
            $script:GetSecureAuthHeader = {
                param([SecureString]$SecureToken)
                if ($null -eq $SecureToken) {
                    throw 'Access token is null or has been cleared'
                }

                # Decrypt token only when needed and clear immediately
                $bstrPtr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureToken)
                try {
                    $PlainToken = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstrPtr)
                    return @{
                        Authorization  = "Bearer $PlainToken"
                        'Content-Type' = 'application/json'
                    }
                } finally {
                    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstrPtr)
                    $PlainToken = $null
                }
            }

            Write-Verbose "Successfully retrieved access token. Expiration date: $((Get-Date).AddSeconds($TokenRequest.expires_in))"

            # Return secure token information
            $TokenInfo = [PSCustomObject]@{
                SecureAccessToken = $SecureAccessToken
                TokenType         = $TokenRequest.token_type
                ExpiresIn         = $TokenRequest.expires_in
                ExpiresAt         = (Get-Date).AddSeconds($TokenRequest.expires_in)
                Scope             = $ScopeUri
                ServiceType       = $Scope
                TenantId          = $TenantId
                ClientId          = $ClientId
                IsExpired         = $false
                CreatedAt         = Get-Date
                GetSecureHeader   = $script:GetSecureAuthHeader
            } | Add-Member -MemberType ScriptMethod -Name 'IsTokenExpired' -Value {
                # Method to check if token is expired
                return (Get-Date) -gt $this.ExpiresAt
            } -PassThru | Add-Member -MemberType ScriptMethod -Name 'ClearToken' -Value {
                # Method to securely clear the token
                $this.SecureAccessToken = $null
            } -PassThru | Add-Member -MemberType ScriptProperty -Name 'AccessToken' -Value {
                # Decrypt SecureAccessToken on demand (required by Connect-ExchangeOnline and Connect-IPPSSession)
                if ($null -eq $this.SecureAccessToken) {
                    return $null
                }
                $bstrPtr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($this.SecureAccessToken)
                try {
                    return [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstrPtr)
                } finally {
                    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstrPtr)
                }
            } -PassThru | Add-Member -MemberType ScriptProperty -Name 'Header' -Value {
                # Backward-compatible property: return auth header for API calls
                if ($null -eq $this.SecureAccessToken) {
                    return $null
                }
                $bstrPtr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($this.SecureAccessToken)
                try {
                    $token = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstrPtr)
                    return @{
                        Authorization  = "Bearer $token"
                        'Content-Type' = 'application/json'
                    }
                } finally {
                    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstrPtr)
                    $token = $null
                }
            } -PassThru

            # Store in script scope for backward compatibility
            $script:TokenInfo = $TokenInfo

            # Cache token for future requests
            $script:TokenCache[$CacheKey] = $TokenInfo
            Write-Verbose "Token cached with key: $CacheKey"

            return $script:TokenInfo
        } catch {
            $ErrorDetails = $_.Exception.Message

            # Enhanced error handling for common authentication issues
            if ($_.Exception.Response) {
                try {
                    $ErrorStream = $_.Exception.Response.GetResponseStream()
                    $Reader = New-Object System.IO.StreamReader($ErrorStream)
                    $ErrorBody = $Reader.ReadToEnd() | ConvertFrom-Json
                    $ErrorDetails = "$($ErrorBody.error): $($ErrorBody.error_description)"
                } catch {
                    $ErrorDetails = "HTTP $($_.Exception.Response.StatusCode.value__): $($_.Exception.Response.StatusDescription)"
                }
            }

            Write-Error "Failed to retrieve access token for tenant '$($TenantId)' and scope '$($ScopeUri)': $($ErrorDetails)"

            # Provide scope-specific troubleshooting guidance
            $TroubleshootingGuidance = @'
Common causes for authentication failures:
1. Incorrect Client ID or Client Secret
2. App registration not found in the specified tenant
3. Required permissions not granted or admin consent not provided
4. Client secret has expired
5. Tenant ID format is incorrect

SCOPE-SPECIFIC REQUIREMENTS:
'@

            if ($ScopeUri -eq 'https://management.azure.com/.default') {
                $TroubleshootingGuidance += @'

For Azure Resource Manager scope:
- App registration needs 'Azure Service Management' API permissions
- Service principal requires RBAC role assignments on target resources
- Use Azure PowerShell: Connect-AzAccount to verify access
- Check role assignments: Get-AzRoleAssignment -ServicePrincipalName <ClientId>
'@
            } elseif ($ScopeUri -eq 'https://graph.microsoft.com/.default') {
                $TroubleshootingGuidance += @'

For Microsoft Graph scope:
- App registration needs Microsoft Graph application permissions
- Admin consent must be granted for all permissions
- Check permissions in Azure Portal: App registrations > API permissions
'@
            }

            $TroubleshootingGuidance += @"

Verify your app registration at:
https://portal.azure.com/#blade/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/Overview/appId/$($ClientId)
"@

            Write-Warning $TroubleshootingGuidance

            $errorRecord = [System.Management.Automation.ErrorRecord]::new(
                [System.Exception]::new("Get-GraphToken failed to retrieve access token for tenant '$TenantId' and scope '$ScopeUri': $ErrorDetails", $_.Exception),
                'GetGraphTokenAuthenticationError',
                [System.Management.Automation.ErrorCategory]::AuthenticationError,
                $TenantId
            )
            $PSCmdlet.ThrowTerminatingError($errorRecord)
        }
    }
}
