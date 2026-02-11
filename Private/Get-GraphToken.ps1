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

    .PARAMETER CertificateThumbprint
        The thumbprint of a certificate installed in the local certificate store (Cert:\CurrentUser\My or
        Cert:\LocalMachine\My) for certificate-based authentication. The certificate must have a private key
        and use an RSA key pair. Used to build a JWT bearer assertion for the OAuth2 client credentials flow.

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
        $Token = Get-GraphToken -TenantId $TenantId -ClientId $ClientId -CertificateThumbprint $Thumbprint -Scope Graph
        Retrieves a Microsoft Graph access token using certificate authentication.

    .EXAMPLE
        $ArmToken = Get-GraphToken -TenantId $TenantId -ClientId $ClientId -CertificateThumbprint $Thumbprint -Scope Azure
        Retrieves an Azure Resource Manager access token using certificate authentication.

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
        [Parameter(Mandatory = $true, ParameterSetName = 'Certificate')]
        [Parameter(Mandatory = $false, ParameterSetName = 'ManagedIdentity')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Interactive')]
        [ValidateNotNullOrEmpty()]
        [string]$TenantId,

        [Parameter(Mandatory = $true, ParameterSetName = 'ClientCredentials')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Certificate')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Interactive')]
        [Alias('ApplicationId')]
        [ValidatePattern('^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$')]
        [string]$ClientId,

        [Parameter(Mandatory = $true, ParameterSetName = 'ClientCredentials')]
        [Alias('ApplicationSecret')]
        [ValidateNotNullOrEmpty()]
        [SecureString]$ClientSecret,

        [Parameter(Mandatory = $true, ParameterSetName = 'Certificate')]
        [ValidateNotNullOrEmpty()]
        [string]$CertificateThumbprint,

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
            } elseif ($CertificateThumbprint) {
                "$ScopeUri-$ClientId-$TenantId-$CertificateThumbprint"
            } else {
                "$ScopeUri-$ClientId-$TenantId"
            }

            # Refresh tokens 5 minutes before expiration to prevent mid-operation failures
            if ($script:TokenCache.ContainsKey($CacheKey)) {
                $CachedToken = $script:TokenCache[$CacheKey]
                if ($CachedToken.ExpiresAt -gt [datetime]::Now.AddMinutes(5)) {
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
                    SecureAccessToken = $null
                    TokenType         = 'Interactive'
                    ExpiresIn         = 3600
                    ExpiresAt         = [datetime]::Now.AddHours(1)
                    Scope             = $ScopeUri
                    ServiceType       = $Scope
                    TenantId          = $MgContext.TenantId
                    ClientId          = $MgContext.ClientId
                    IsExpired         = $false
                    CreatedAt         = [datetime]::Now
                    IsInteractive     = $true
                    GetSecureHeader   = $null
                } | Add-Member -MemberType ScriptMethod -Name 'IsTokenExpired' -Value {
                    # For interactive, check if MgGraph context is still valid
                    $ctx = Get-MgContext -ErrorAction SilentlyContinue
                    return $null -eq $ctx
                } -PassThru | Add-Member -MemberType ScriptMethod -Name 'ClearToken' -Value {
                    # No-op for interactive - Disconnect-MgGraph handles cleanup
                } -PassThru | Add-Member -MemberType ScriptProperty -Name 'AccessToken' -Value {
                    # Return null - callers should use Invoke-MgGraphRequest
                    return $null
                } -PassThru | Add-Member -MemberType ScriptProperty -Name 'Header' -Value {
                    # Return null - callers should use Invoke-MgGraphRequest
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
                        expires_in   = [int](($AzToken.ExpiresOn.UtcDateTime - [datetime]::UtcNow).TotalSeconds)
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
            } elseif ($CertificateThumbprint) {
                Write-Verbose 'Using Certificate authentication with JWT bearer assertion'

                # Normalize thumbprint: remove whitespace, uppercase
                $NormalizedThumbprint = ($CertificateThumbprint -replace '\s', '').ToUpperInvariant()

                # Find certificate in local stores
                $Certificate = $null
                foreach ($StoreLocation in @('CurrentUser', 'LocalMachine')) {
                    $CertPath = "Cert:\$StoreLocation\My\$NormalizedThumbprint"
                    $Certificate = Get-Item -Path $CertPath -ErrorAction SilentlyContinue
                    if ($Certificate) {
                        Write-Verbose "Found certificate in $StoreLocation store"
                        break
                    }
                }

                if (-not $Certificate) {
                    $errorRecord = [System.Management.Automation.ErrorRecord]::new(
                        [System.Exception]::new("Get-GraphToken failed: Certificate with thumbprint '$NormalizedThumbprint' not found in Cert:\CurrentUser\My or Cert:\LocalMachine\My."),
                        'GetGraphTokenCertificateNotFoundError',
                        [System.Management.Automation.ErrorCategory]::ObjectNotFound,
                        $NormalizedThumbprint
                    )
                    $PSCmdlet.ThrowTerminatingError($errorRecord)
                }

                # Validate certificate has a private key
                if (-not $Certificate.HasPrivateKey) {
                    $errorRecord = [System.Management.Automation.ErrorRecord]::new(
                        [System.Exception]::new("Get-GraphToken failed: Certificate '$NormalizedThumbprint' does not have a private key. Import the certificate with the private key (.pfx) to use certificate authentication."),
                        'GetGraphTokenCertificateNoPrivateKeyError',
                        [System.Management.Automation.ErrorCategory]::SecurityError,
                        $Certificate
                    )
                    $PSCmdlet.ThrowTerminatingError($errorRecord)
                }

                # Validate RSA key type
                $RsaPrivateKey = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Certificate)
                if (-not $RsaPrivateKey) {
                    $errorRecord = [System.Management.Automation.ErrorRecord]::new(
                        [System.Exception]::new("Get-GraphToken failed: Certificate '$NormalizedThumbprint' does not have an RSA private key. Only RSA certificates are supported for JWT bearer assertions."),
                        'GetGraphTokenCertificateNotRsaError',
                        [System.Management.Automation.ErrorCategory]::InvalidType,
                        $Certificate
                    )
                    $PSCmdlet.ThrowTerminatingError($errorRecord)
                }

                $JwtAssertion = $null
                try {
                    # Build JWT header
                    $CertHash = $Certificate.GetCertHash()
                    $X5t = [Convert]::ToBase64String($CertHash) -replace '\+', '-' -replace '/', '_' -replace '='

                    $JwtHeader = @{
                        alg = 'RS256'
                        typ = 'JWT'
                        x5t = $X5t
                    }

                    # Add x5t#S256 if SHA-256 hash is available
                    $CertHashSha256 = $Certificate.GetCertHash([System.Security.Cryptography.HashAlgorithmName]::SHA256)
                    if ($CertHashSha256) {
                        $X5tS256 = [Convert]::ToBase64String($CertHashSha256) -replace '\+', '-' -replace '/', '_' -replace '='
                        $JwtHeader['x5t#S256'] = $X5tS256
                    }

                    # Build JWT claims
                    $TokenEndpoint = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
                    $Now = [DateTimeOffset]::UtcNow
                    $JwtClaims = @{
                        aud = $TokenEndpoint
                        iss = $ClientId
                        sub = $ClientId
                        jti = [Guid]::NewGuid().ToString()
                        nbf = $Now.ToUnixTimeSeconds()
                        exp = $Now.AddMinutes(10).ToUnixTimeSeconds()
                    }

                    # Encode header and claims
                    $EncodedHeader = [Convert]::ToBase64String(
                        [System.Text.Encoding]::UTF8.GetBytes(($JwtHeader | ConvertTo-Json -Compress))
                    ) -replace '\+', '-' -replace '/', '_' -replace '='
                    $EncodedClaims = [Convert]::ToBase64String(
                        [System.Text.Encoding]::UTF8.GetBytes(($JwtClaims | ConvertTo-Json -Compress))
                    ) -replace '\+', '-' -replace '/', '_' -replace '='

                    # Sign JWT with RSA-SHA256
                    $DataToSign = [System.Text.Encoding]::UTF8.GetBytes("$EncodedHeader.$EncodedClaims")
                    $Signature = $RsaPrivateKey.SignData(
                        $DataToSign,
                        [System.Security.Cryptography.HashAlgorithmName]::SHA256,
                        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
                    )
                    $EncodedSignature = [Convert]::ToBase64String($Signature) -replace '\+', '-' -replace '/', '_' -replace '='

                    $JwtAssertion = "$EncodedHeader.$EncodedClaims.$EncodedSignature"

                    # POST to token endpoint with JWT bearer assertion
                    $AuthBody = @{
                        client_id             = $ClientId
                        scope                 = $ScopeUri
                        grant_type            = 'client_credentials'
                        client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
                        client_assertion      = $JwtAssertion
                    }

                    $TokenUri = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"

                    try {
                        $TokenRequest = Invoke-RestMethod -Method Post -Uri $TokenUri -Body $AuthBody -ContentType 'application/x-www-form-urlencoded' -ErrorAction Stop
                    } catch {
                        $errorRecord = [System.Management.Automation.ErrorRecord]::new(
                            [System.Exception]::new("Get-GraphToken failed to obtain token using Certificate authentication: $($_.Exception.Message)", $_.Exception),
                            'GetGraphTokenCertificateError',
                            [System.Management.Automation.ErrorCategory]::AuthenticationError,
                            $null
                        )
                        $PSCmdlet.ThrowTerminatingError($errorRecord)
                    }
                } finally {
                    # Clear JWT strings from memory
                    $JwtAssertion = $null
                    if ($AuthBody) {
                        $AuthBody.Clear()
                    }
                    $EncodedHeader = $null
                    $EncodedClaims = $null
                    $EncodedSignature = $null
                    $DataToSign = $null
                    if ($RsaPrivateKey -is [System.IDisposable]) {
                        $RsaPrivateKey.Dispose()
                    }
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

            Write-Verbose "Successfully retrieved access token. Expiration date: $([datetime]::Now.AddSeconds($TokenRequest.expires_in))"

            # Return secure token information
            $TokenInfo = [PSCustomObject]@{
                SecureAccessToken = $SecureAccessToken
                TokenType         = $TokenRequest.token_type
                ExpiresIn         = $TokenRequest.expires_in
                ExpiresAt         = [datetime]::Now.AddSeconds($TokenRequest.expires_in)
                Scope             = $ScopeUri
                ServiceType       = $Scope
                TenantId          = $TenantId
                ClientId          = $ClientId
                IsExpired         = $false
                CreatedAt         = [datetime]::Now
                GetSecureHeader   = $script:GetSecureAuthHeader
            } | Add-Member -MemberType ScriptMethod -Name 'IsTokenExpired' -Value {
                # Method to check if token is expired
                return [datetime]::Now -gt $this.ExpiresAt
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

            if ($CertificateThumbprint) {
                $TroubleshootingGuidance += @"

CERTIFICATE-SPECIFIC TROUBLESHOOTING:
- Verify the certificate is installed: Get-ChildItem Cert:\CurrentUser\My\$($CertificateThumbprint)
- Check LocalMachine store: Get-ChildItem Cert:\LocalMachine\My\$($CertificateThumbprint)
- Ensure the certificate has a private key (.pfx import)
- Verify the certificate is uploaded to the app registration in Azure Portal
- Check certificate expiration: (Get-Item Cert:\CurrentUser\My\$($CertificateThumbprint)).NotAfter
- Ensure the certificate uses RSA key pair (EC keys are not supported)
"@
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
