function Disconnect-TntGraphSession {
    <#
    .SYNOPSIS
        Helper function to safely disconnect from Microsoft cloud services based on connection state.

    .DESCRIPTION
        This helper function checks the connection state object returned by Connect-TntGraphSession
        and disconnects from Microsoft Graph only if the connection was established by the current operation.
        For REST API connections, no explicit disconnect is needed as tokens are stateless.

    .PARAMETER ConnectionState
        The connection state object returned by Connect-TntGraphSession.

    .EXAMPLE
        Disconnect-TntGraphSession -ConnectionState $ConnectionInfo

        Disconnects from Microsoft Graph if the connection should be cleaned up.

    .NOTES
        Author: Tom de Leeuw
        Website: https://systom.dev
        Module: TenantReports

        This is an internal helper function for the Security Reporting module.
        Only performs disconnect for Microsoft Graph SDK connections where ShouldDisconnect is true.
        REST API connections (token-based) do not require explicit disconnect.

    .LINK
        https://systom.dev
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [PSCustomObject]$ConnectionState
    )

    process {
        try {
            if (-not $ConnectionState.ShouldDisconnect) {
                Write-Verbose 'Disconnect skipped - connection managed by orchestrator'
                return
            }

            switch ($ConnectionState.ConnectionType) {
                'Graph' {
                    try {
                        $CurrentContext = Get-MgContext -ErrorAction SilentlyContinue
                        if ($CurrentContext) {
                            Disconnect-MgGraph -ErrorAction Stop | Out-Null
                            Write-Verbose "Disconnected from Microsoft Graph (Tenant: $($ConnectionState.TenantId))"
                        } else {
                            Write-Verbose 'No active Microsoft Graph connection found to disconnect'
                        }
                    } catch {
                        Write-Verbose "Error during Microsoft Graph disconnect (non-critical): $($_.Exception.Message)"
                    }
                }
                'RestApi' {
                    # REST API connections are stateless - but secure token cleanup is required
                    try {
                        # Clear secure tokens from memory
                        if ($ConnectionState.PSObject.Properties['TokenInfo'] -and
                            $ConnectionState.TokenInfo.PSObject.Methods['ClearToken']) {
                            $ConnectionState.TokenInfo.ClearToken()
                            $ConnectionState.TokenInfo = $null
                        }

                        # Clear any cached tokens or headers
                        if ($ConnectionState.PSObject.Properties['AccessToken']) {
                            $ConnectionState.AccessToken = $null
                        }
                        if ($ConnectionState.PSObject.Properties['Headers']) {
                            $ConnectionState.Headers = $null
                        }
                        if ($ConnectionState.PSObject.Properties['GetSecureHeaders']) {
                            $ConnectionState.GetSecureHeaders = $null
                        }

                        # Clear user cache for this tenant
                        if ($script:UserCache -and $ConnectionState.TenantId) {
                            $CacheKeysToRemove = @($script:UserCache.Keys.Where({ $_ -like "$($ConnectionState.TenantId)-*" }))
                            foreach ($Key in $CacheKeysToRemove) {
                                $script:UserCache.Remove($Key)
                            }
                        }
                    } catch {
                        Write-Verbose "Error during secure token cleanup: $($_.Exception.Message)"
                    }
                }
            }
        } catch {
            # Log any unexpected errors but don't throw - cleanup should be non-blocking
            Write-Verbose "Unexpected error during connection cleanup: $($_.Exception.Message)"
        }
    }
}
