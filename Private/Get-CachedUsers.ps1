function Get-CachedUsers {
    <#
    .SYNOPSIS
        Retrieves and caches Microsoft Graph user data with tenant-aware isolation.

    .DESCRIPTION
        This function provides a caching layer for Microsoft Graph user data to eliminate redundant API calls.
        Supports two modes:
        - Batch mode (-FetchAll): Downloads all users at once for functions that iterate all users anyway
        - Incremental mode (-UserIds/-UserPrincipalNames): Fetches only specific users for targeted lookups

        The cache is tenant-aware using TenantId-ClientId as the cache key.

    .PARAMETER TenantId
        The Azure AD Tenant ID to fetch users from.

    .PARAMETER ClientId
        The Application (Client) ID of the app registration.

    .PARAMETER RequiredProperties
        Additional user properties to fetch beyond the default set.
        Default properties: Id, DisplayName, UserPrincipalName, AccountEnabled, Mail, UserType

    .PARAMETER UserIds
        Specific user IDs to fetch (incremental mode). Only fetches missing users.

    .PARAMETER UserPrincipalNames
        Specific UPNs to fetch (incremental mode). Only fetches missing users.

    .PARAMETER FetchAll
        Explicit flag to fetch all users (batch mode). Use for functions that iterate all users.

    .PARAMETER ForceBetaAPI
        Use the beta API endpoint (required for SignInActivity).

    .PARAMETER ForceRefresh
        Bypass TTL check and force a refresh of cached data.

    .PARAMETER TTLMinutes
        Time-to-live for cached data in minutes. Default is 15.

    .EXAMPLE
        # Batch mode - fetch all users for Intune device loop
        $Cache = Get-CachedUsers -TenantId $TenantId -ClientId $ClientId -FetchAll

    .EXAMPLE
        # Incremental mode - fetch only specific users by ID
        $Cache = Get-CachedUsers -TenantId $TenantId -ClientId $ClientId -UserIds @($Id1, $Id2)

    .OUTPUTS
        PSCustomObject with Users array and O(1) lookup hashtables.

    .NOTES
        Author: Tom de Leeuw
        Website: https://systom.dev
        Module: TenantReports

        This is an internal function for the TenantReports module.

    .LINK
        https://systom.dev
    #>

    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$TenantId,

        [Parameter(Mandatory = $false)]
        [ValidatePattern('^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$')]
        [string]$ClientId,

        [Parameter()]
        [string[]]$RequiredProperties,

        [Parameter()]
        [string[]]$UserIds,

        [Parameter()]
        [string[]]$UserPrincipalNames,

        [Parameter()]
        [switch]$FetchAll,

        [Parameter()]
        [switch]$ForceBetaAPI,

        [Parameter()]
        [switch]$ForceRefresh,

        [Parameter()]
        [ValidateRange(1, 1440)]
        [int]$TTLMinutes = 15
    )

    begin {
        if (-not $script:UserCache) {
            $script:UserCache = @{}
        }

        $DefaultProperties = @(
            'Id'
            'DisplayName'
            'UserPrincipalName'
            'AccountEnabled'
            'Mail'
            'UserType'
        )

        # Extended properties available via v1.0 API
        $ExtendedV1Properties = @(
            'Department'
            'JobTitle'
            'OfficeLocation'
            'CreatedDateTime'
            'LastPasswordChangeDateTime'
            'UsageLocation'
            'AssignedLicenses'
        )

        # Properties that require beta API
        $BetaOnlyProperties = @(
            'SignInActivity'
        )

        $SafeClientId = $ClientId ?? 'Interactive'
        $CacheKey = "$TenantId-$SafeClientId"
    }

    process {
        try {
            # Determine which properties to fetch
            $PropertiesToFetch = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
            foreach ($Property in $DefaultProperties) { [void]$PropertiesToFetch.Add($Property) }

            if ($RequiredProperties) {
                foreach ($Property in $RequiredProperties) { [void]$PropertiesToFetch.Add($Property) }
            }

            # Determine if beta API is needed
            $NeedsBetaAPI = $ForceBetaAPI
            if (-not $NeedsBetaAPI) {
                foreach ($Property in $PropertiesToFetch) {
                    if ($Property -in $BetaOnlyProperties) {
                        $NeedsBetaAPI = $true
                        break
                    }
                }
            }

            # Check existing cache
            $ExistingCache = $script:UserCache[$CacheKey]
            $CacheValid = $false
            $CacheHit = $false

            if ($ExistingCache -and -not $ForceRefresh) {
                # TTL check
                $ExpiresAt = $ExistingCache.FetchedAt.AddMinutes($ExistingCache.TTL)
                if ($ExpiresAt -gt (Get-Date)) {
                    # Check if existing cache has required properties
                    $HasAllProperties = $true
                    foreach ($Prop in $PropertiesToFetch) {
                        if ($Prop -notin $ExistingCache.Properties) {
                            $HasAllProperties = $false
                            break
                        }
                    }

                    if ($HasAllProperties) {
                        $CacheValid = $true
                    } else {
                        Write-Verbose "Cache missing required properties, will refetch"
                    }
                } else {
                    Write-Verbose "Cache expired (TTL: $($ExistingCache.TTL) minutes)"
                }
            }

            # Batch mode: -FetchAll specified
            if ($FetchAll) {
                if ($CacheValid -and $ExistingCache.IsBatchCache) {
                    Write-Verbose "Using cached batch user data (UserCount: $($ExistingCache.UserCount), CacheAge: $([int]((Get-Date) - $ExistingCache.FetchedAt).TotalMinutes) minutes)"
                    $CacheHit = $true
                    return [PSCustomObject]@{
                        Users           = $ExistingCache.Users
                        LookupByUPN     = $ExistingCache.LookupByUPN
                        LookupByMail    = $ExistingCache.LookupByMail
                        LookupByDisplay = $ExistingCache.LookupByDisplay
                        LookupById      = $ExistingCache.LookupById
                        Properties      = $ExistingCache.Properties
                        UsedBetaAPI     = $ExistingCache.UsedBetaAPI
                        CacheHit        = $true
                        UserCount       = $ExistingCache.UserCount
                        IsBatchCache    = $true
                    }
                }

                # Fetch all users
                Write-Verbose "Fetching all users (batch mode)..."
                $PropertySelect = $PropertiesToFetch -join ','
                $ApiVersion = if ($NeedsBetaAPI) { 'beta' } else { 'v1.0' }

                $AllUsers = Get-MgUser -All -Property $PropertySelect -ErrorAction Stop
                Write-Verbose "Fetched $($AllUsers.Count) users using $ApiVersion API"

                # Build lookup hashtables (PowerShell @{} is case-insensitive by default)
                $LookupByUPN = @{}
                $LookupByMail = @{}
                $LookupByDisplay = @{}
                $LookupById = @{}

                foreach ($User in $AllUsers) {
                    if ($User.Id) {
                        $LookupById[$User.Id] = $User
                    }
                    if ($User.UserPrincipalName) {
                        $LookupByUPN[$User.UserPrincipalName] = $User
                    }
                    if ($User.Mail) {
                        $LookupByMail[$User.Mail] = $User
                    }
                    if ($User.DisplayName) {
                        if (-not $LookupByDisplay.ContainsKey($User.DisplayName)) {
                            $LookupByDisplay[$User.DisplayName] = $User
                        } else {
                            Write-Verbose "DisplayName collision: '$($User.DisplayName)' (ID: $($User.Id)) conflicts with existing entry (ID: $($LookupByDisplay[$User.DisplayName].Id))"
                        }
                    }
                }

                # Store in cache
                $script:UserCache[$CacheKey] = @{
                    Users           = $AllUsers
                    LookupByUPN     = $LookupByUPN
                    LookupByMail    = $LookupByMail
                    LookupByDisplay = $LookupByDisplay
                    LookupById      = $LookupById
                    Properties      = [string[]]$PropertiesToFetch
                    UsedBetaAPI     = [bool]$NeedsBetaAPI
                    IsBatchCache    = $true
                    UserCount       = $AllUsers.Count
                    FetchedAt       = Get-Date
                    TTL             = $TTLMinutes
                }

                return [PSCustomObject]@{
                    Users           = $AllUsers
                    LookupByUPN     = $LookupByUPN
                    LookupByMail    = $LookupByMail
                    LookupByDisplay = $LookupByDisplay
                    LookupById      = $LookupById
                    Properties      = [string[]]$PropertiesToFetch
                    UsedBetaAPI     = [bool]$NeedsBetaAPI
                    CacheHit        = $false
                    UserCount       = $AllUsers.Count
                    IsBatchCache    = $true
                }
            }

            # Incremental mode: -UserIds or -UserPrincipalNames specified
            if ($UserIds -or $UserPrincipalNames) {
                # Initialize cache structure if needed
                if (-not $CacheValid -or -not $ExistingCache) {
                    # Create empty incremental cache structure
                    $script:UserCache[$CacheKey] = @{
                        Users           = [System.Collections.Generic.List[object]]::new()
                        LookupByUPN     = @{}
                        LookupByMail    = @{}
                        LookupByDisplay = @{}
                        LookupById      = @{}
                        Properties      = [string[]]$PropertiesToFetch
                        UsedBetaAPI     = [bool]$NeedsBetaAPI
                        IsBatchCache    = $false
                        UserCount       = 0
                        FetchedAt       = Get-Date
                        TTL             = $TTLMinutes
                    }
                    $ExistingCache = $script:UserCache[$CacheKey]
                }

                # If a batch cache exists and is valid, just use it for lookups
                if ($ExistingCache.IsBatchCache -and $CacheValid) {
                    Write-Verbose "Using existing batch cache for incremental lookups"
                    return [PSCustomObject]@{
                        Users           = $ExistingCache.Users
                        LookupByUPN     = $ExistingCache.LookupByUPN
                        LookupByMail    = $ExistingCache.LookupByMail
                        LookupByDisplay = $ExistingCache.LookupByDisplay
                        LookupById      = $ExistingCache.LookupById
                        Properties      = $ExistingCache.Properties
                        UsedBetaAPI     = $ExistingCache.UsedBetaAPI
                        CacheHit        = $true
                        UserCount       = $ExistingCache.UserCount
                        IsBatchCache    = $true
                    }
                }

                # Identify which users need to be fetched
                $MissingUserIds = [System.Collections.Generic.List[string]]::new()
                $MissingUPNs = [System.Collections.Generic.List[string]]::new()

                if ($UserIds) {
                    foreach ($Id in $UserIds) {
                        if ($Id -and -not $ExistingCache.LookupById.ContainsKey($Id)) {
                            $MissingUserIds.Add($Id)
                        }
                    }
                }

                if ($UserPrincipalNames) {
                    foreach ($UPN in $UserPrincipalNames) {
                        if ($UPN -and -not $ExistingCache.LookupByUPN.ContainsKey($UPN)) {
                            $MissingUPNs.Add($UPN)
                        }
                    }
                }

                $TotalMissing = $MissingUserIds.Count + $MissingUPNs.Count

                if ($TotalMissing -eq 0) {
                    Write-Verbose "All requested users found in cache (cache hit)"
                    $CacheHit = $true
                } else {
                    Write-Verbose "Fetching $TotalMissing users (incremental mode)..."

                    $PropertySelect = $PropertiesToFetch -join ','

                    # Fetch missing users by ID
                    foreach ($Id in $MissingUserIds) {
                        try {
                            $User = Get-MgUser -UserId $Id -Property $PropertySelect -ErrorAction SilentlyContinue
                            if ($User) {
                                # Add to cache collections
                                $ExistingCache.Users.Add($User)
                                if ($User.Id) {
                                    $ExistingCache.LookupById[$User.Id] = $User
                                }
                                if ($User.UserPrincipalName) {
                                    $ExistingCache.LookupByUPN[$User.UserPrincipalName] = $User
                                }
                                if ($User.Mail) {
                                    $ExistingCache.LookupByMail[$User.Mail] = $User
                                }
                                if ($User.DisplayName -and -not $ExistingCache.LookupByDisplay.ContainsKey($User.DisplayName)) {
                                    $ExistingCache.LookupByDisplay[$User.DisplayName] = $User
                                }
                            }
                        } catch {
                            Write-Verbose "Could not fetch user with ID: $Id - $($_.Exception.Message)"
                        }
                    }

                    # Fetch missing users by UPN
                    foreach ($UPN in $MissingUPNs) {
                        try {
                            $User = Get-MgUser -UserId $UPN -Property $PropertySelect -ErrorAction SilentlyContinue
                            if ($User) {
                                # Check if already added by ID lookup
                                if (-not $ExistingCache.LookupById.ContainsKey($User.Id)) {
                                    $ExistingCache.Users.Add($User)
                                    if ($User.Id) {
                                        $ExistingCache.LookupById[$User.Id] = $User
                                    }
                                    if ($User.UserPrincipalName) {
                                        $ExistingCache.LookupByUPN[$User.UserPrincipalName] = $User
                                    }
                                    if ($User.Mail) {
                                        $ExistingCache.LookupByMail[$User.Mail] = $User
                                    }
                                    if ($User.DisplayName -and -not $ExistingCache.LookupByDisplay.ContainsKey($User.DisplayName)) {
                                        $ExistingCache.LookupByDisplay[$User.DisplayName] = $User
                                    }
                                }
                            }
                        } catch {
                            Write-Verbose "Could not fetch user with UPN: $UPN - $($_.Exception.Message)"
                        }
                    }

                    # Update cache metadata
                    $ExistingCache.UserCount = $ExistingCache.Users.Count
                    $ExistingCache.FetchedAt = Get-Date

                    Write-Verbose "Incremental cache now contains $($ExistingCache.UserCount) users"
                }

                return [PSCustomObject]@{
                    Users           = $ExistingCache.Users
                    LookupByUPN     = $ExistingCache.LookupByUPN
                    LookupByMail    = $ExistingCache.LookupByMail
                    LookupByDisplay = $ExistingCache.LookupByDisplay
                    LookupById      = $ExistingCache.LookupById
                    Properties      = $ExistingCache.Properties
                    UsedBetaAPI     = $ExistingCache.UsedBetaAPI
                    CacheHit        = $CacheHit
                    UserCount       = $ExistingCache.UserCount
                    IsBatchCache    = $false
                }
            }

            # No mode specified - return empty result or existing cache
            if ($CacheValid) {
                Write-Verbose "Returning existing cache (no fetch mode specified)"
                return [PSCustomObject]@{
                    Users           = $ExistingCache.Users
                    LookupByUPN     = $ExistingCache.LookupByUPN
                    LookupByMail    = $ExistingCache.LookupByMail
                    LookupByDisplay = $ExistingCache.LookupByDisplay
                    LookupById      = $ExistingCache.LookupById
                    Properties      = $ExistingCache.Properties
                    UsedBetaAPI     = $ExistingCache.UsedBetaAPI
                    CacheHit        = $true
                    UserCount       = $ExistingCache.UserCount
                    IsBatchCache    = $ExistingCache.IsBatchCache
                }
            }

            Write-Warning "Get-CachedUsers called without -FetchAll, -UserIds, or -UserPrincipalNames. Specify a fetch mode."
            return [PSCustomObject]@{
                Users           = @()
                LookupByUPN     = @{}
                LookupByMail    = @{}
                LookupByDisplay = @{}
                LookupById      = @{}
                Properties      = [string[]]$PropertiesToFetch
                UsedBetaAPI     = [bool]$NeedsBetaAPI
                CacheHit        = $false
                UserCount       = 0
                IsBatchCache    = $false
            }
        }
        catch {
            Write-Error "Get-CachedUsers failed: $($_.Exception.Message)"
            # Return empty result on error rather than throwing
            return [PSCustomObject]@{
                Users           = @()
                LookupByUPN     = @{}
                LookupByMail    = @{}
                LookupByDisplay = @{}
                LookupById      = @{}
                Properties      = [string[]]$PropertiesToFetch
                UsedBetaAPI     = [bool]$NeedsBetaAPI
                CacheHit        = $false
                UserCount       = 0
                IsBatchCache    = $false
            }
        }
    }
}
