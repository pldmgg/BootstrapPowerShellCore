<#
    .SYNOPSIS
        This function starts a PowerShell Universal Dashboard (Web-based GUI) instance on the specified port on the
        localhost. The Dashboard features a Network Monitor tool that pings the specified Remote Hosts in your Domain
        every 5 seconds and reports the results to the site.

    .DESCRIPTION
        See .SYNOPSIS

    .PARAMETER Port
        This parameter is OPTIONAL, however, it has a default value of 80.

        This parameter takes an integer between 1 and 32768 that represents the port on the localhost that the site
        will run on.

    .PARAMETER InstallNmap
        This parameter is OPTIONAL, however, it has a default value of $True.

        This parameter is a switch. If used, nmap will be installed in order to guess the Operating System of
        Remote Hosts on the network.

    .PARAMETER RemoveExistingPUD
        This parameter is OPTIONAL, however, it has a default value of $True.

        This parameter is a switch. If used, all running PowerShell Universal Dashboard instances will be removed
        prior to starting the Network Monitor Dashboard.

    .PARAMETER LDAPCreds
        This parameter is OPTIONAL, however, if PUDAdminCenter is being run on Linux, it is MANDATORY.

        This parameter takes a pscredential that represents credentials with (at least) Read Access to your Domain's
        LDAP / Active Directory database.

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> Get-PUDAdminCenter
        
#>
function Get-PUDAdminCenter {
    Param (
        [Parameter(Mandatory=$False)]
        [ValidateRange(1,32768)]
        [int]$Port = 80,

        [Parameter(Mandatory=$False)]
        [switch]$InstallNmap = $False,

        [Parameter(Mandatory=$False)]
        [switch]$RemoveExistingPUD = $True,

        [Parameter(Mandatory=$False)]
        [pscredential]$LDAPCreds
    )

    #region >> Prep

    if ($PSVersionTable.Platform -eq "Unix" -and !$LDAPCreds) {
        Write-Error "Running PUDAdminCenter on Linux requires that you supply LDAP/Active Directory Credentials using the -LDAPCreds parameter! Halting!"
        $global:FunctionResult = "1"
        return
    }

    # Remove all current running instances of PUD
    if ($RemoveExistingPUD) {
        Get-UDDashboard | Stop-UDDashboard
    }

    # Remove All Runspaces to Remote Hosts
    Get-PSSession | Remove-PSSession
    $RunspacesToDispose = @(
        Get-Runspace | Where-Object {$_.Type -eq "Remote"}
    )
    if ($RunspacesToDispose.Count -gt 0) {
        foreach ($RSpace in $RunspacesToDispose) {$_.Dispose()}
    }

    # Define all of this Module's functions (both Public and Private) as an array of strings so that we can easily load them in different contexts/scopes
    $ThisModuleFunctionsStringArray =  $(Get-Module PUDAdminCenter).Invoke({$FunctionsForSBUse})

    # Create the $Pages ArrayList that will be used with 'New-UDDashboard -Pages'
    [System.Collections.ArrayList]$Pages = @()

    # Current Scope variable (ArrayList) containing the names of all of **Dynamic** Pages -
    # i.e. Pages where the URL contains a variable/parameter that is referenced within the Page itself.
    # For example, in this PUDAdminCenter App, the Overview Page (and all other Dynamic Pages in this list) is
    # eventually created via...
    #     New-UDPage -Url "/Overview/:RemoteHost" -Endpoint {param($RemoteHost) ...}
    # ...meaning that if a user were to navigate to http://localhost/Overview/Server01, Overview Page Endpoint scriptblock
    # code that referenced the variable $RemoteHost would contain the string value 'Server01' (unless it is specifcally
    # overriden within the Overview Page Endpoint scriptblock, which is NOT recommended).
    $DynamicPages = @(
        "PSRemotingCreds"
        "ToolSelect"
        "Overview"
        "Certificates"
        "Devices"
        "Events"
        "Files"
        "Firewall"
        "Users And Groups"
        "Network"
        "Processes"
        "Registry"
        "Roles And Features"
        "Scheduled Tasks"
        "Services"
        "Storage"
        "Updates"
    )

    if ($PSVersionTable.Platform -eq "Unix") {
        $RequiredLinuxCommands =  $(Get-Module PUDAdminCenter).Invoke({$RequiredLinuxCommands})
        [System.Collections.ArrayList]$CommandsNotPresent = @()
        foreach ($CommandName in $RequiredLinuxCommands) {
            $CommandCheckResult = command -v $CommandName
            if (!$CommandCheckResult) {
                $null = $CommandsNotPresent.Add($CommandName)
            }
        }

        if ($CommandsNotPresent.Count -gt 0) {
            [System.Collections.ArrayList]$FailedInstalls = @()
            if ($CommandsNotPresent -contains "echo" -or $CommandsNotPresent -contains "whoami") {
                try {
                    $null = InstallLinuxPackage -PossiblePackageNames "coreutils" -CommandName "echo"
                }
                catch {
                    $null = $FailedInstalls.Add("coreutils")
                }
            }
            if ($CommandsNotPresent -contains "nslookup" -or $CommandsNotPresent -contains "host" -or
            $CommandsNotPresent -contains "hostname" -or $CommandsNotPresent -contains "domainanme") {
                try {
                    $null = InstallLinuxPackage -PossiblePackageNames @("dnsutils","bindutils","bind-tools") -CommandName "nslookup"
                }
                catch {
                    $null = $FailedInstalls.Add("dnsutils_bindutils_bind-tools")
                }
            }
            if ($CommandsNotPresent -contains "ldapsearch") {
                try {
                    $null = InstallLinuxPackage -PossiblePackageNames "openldap-clients" -CommandName "ldapsearch"
                }
                catch {
                    $null = $FailedInstalls.Add("openldap-clients")
                }
            }
            if ($CommandsNotPresent -contains "expect") {
                try {
                    $null = InstallLinuxPackage -PossiblePackageNames "expect" -CommandName "expect"
                }
                catch {
                    $null = $FailedInstalls.Add("expect")
                }
            }
    
            if ($FailedInstalls.Count -gt 0) {
                Write-Error "The following Linux packages are required, but were not able to be installed:`n$($FailedInstalls -join "`n")`nHalting!"
                $global:FunctionResult = "1"
                return
            }
        }

        [System.Collections.ArrayList]$CommandsNotPresent = @()
        foreach ($CommandName in $RequiredLinuxCommands) {
            $CommandCheckResult = command -v $CommandName
            if (!$CommandCheckResult) {
                $null = $CommandsNotPresent.Add($CommandName)
            }
        }
    
        if ($CommandsNotPresent.Count -gt 0) {
            Write-Error "The following Linux commands are required, but not present on $env:ComputerName:`n$($CommandsNotPresent -join "`n")`nHalting!"
            $global:FunctionResult = "1"
            return
        }
    }

    # Make sure we can resolve the $DomainName
    try {
        $DomainName = GetDomainName
        $ResolveDomainInfo = [System.Net.Dns]::Resolve($DomainName)
    }
    catch {
        Write-Error "Unable to resolve domain '$DomainName'! Halting!"
        $global:FunctionResult = "1"
        return
    }    

    # Create Synchronized Hashtable so that we can pass variables between Pages regardless of scope.
    # This provides benefits above and beyond Universal Dashboard's $Cache: scope for two main reasons:
    #     1) It can be referenced anywhere (not just within an -Endpoint, which is what $Cache: scope is limited to)
    #     2) It allows us to more easily communicate with our own custom Runspace(s) that handle Live (Realtime) Data. For
    #     examples of this, see uses of the 'New-Runspace' function within each of the Dynamic Pages (excluding the
    #     PSRemotingCreds and ToolSelect Pages)
    Remove-Variable -Name PUDRSSyncHT -Scope Global -Force -ErrorAction SilentlyContinue
    $global:PUDRSSyncHT = [hashtable]::Synchronized(@{})

    # Populate $PUDRSSyncHT with information that you will need for your PUD Application. This will vary depending on
    # how your application works, but at the very least, you should:
    #     1) Add a Key that will contain information that will be displayed on your HomePage (for the PUDAdminCenter App,
    #     this is the Value contained within the 'RemoteHostList' Key)
    #     2) If you are planning on using Live (Realtime) Data, ensure you add one or more keys that will contain
    #     Live Data. (For the PUDAdminCenter App, this is the LiveDataRSInfo Key that exists within a hashtable
    #     dedicated to each specific Remote Host)
    # For this PUDAdminCenter Application, the structure of the $PUDRSSyncHT will look like...
    <#
        @{
            RemoteHostList   = $null
            <RemoteHostInfo> = @{
                NetworkInfo                 = $null
                <DynamicPage>               = @{
                    <StaticInfoKey>     = $null
                    LiveDataRSInfo      = $null
                    LiveDataTracker     = @{
                        Current     = $null
                        Previous    = $null
                    }
                }
            }
        }
    #>
    # In other words. each Key within the $PUDRSSyncHT Synchronized Hashtable (with the exception of the 'RemoteHostList' key)
    # will represent a Remote Host that we intend to manage. Each RemoteHost key value will be a hashtable containing the key
    # 'NetworkInfo', as well as keys that rperesent relevant Dynamic Pages ('Overview','Certificates',etc). Each Dynamic Page
    # key value will be a hashtable containing one or more keys with value(s) representing static info that is queried at the time
    # the page loads as well as the keys 'LiveDataRSInfo', and 'LiveDataTracker'. Some key values are initially set to $null because
    # actions taken either prior to starting the UDDashboard or actions taken within the PUDAdminCenter WebApp itself on different
    # pages will set/reset their values as appropriate.

    # Let's populate $PUDRSSyncHT.RemoteHostList with information that will be needed immediately upon navigating to the $HomePage.
    # For this reason, we're gathering the info before we start the UDDashboard. (Note that the below 'GetComputerObjectInLDAP' Private
    # function gets all Computers in Active Directory without using the ActiveDirectory PowerShell Module)
    if ($PSVersionTable.Platform -eq "Unix") {
        [System.Collections.ArrayList]$InitialRemoteHostListPrep = GetComputerObjectsInLDAP -ObjectCount 20 -LDAPCreds $LDAPCreds
        $PUDRSSyncHT.Add("LDAPCreds",$LDAPCreds)
    }
    else {
        [System.Collections.ArrayList]$InitialRemoteHostListPrep = $(GetComputerObjectsInLDAP -ObjectCount 20).Name
    }
    # Let's just get 20 of them initially. We want *something* on the HomePage but we don't want hundreds/thousands of entries. We want
    # the user to specify individual/range of hosts/devices that they want to manage.
    #$InitialRemoteHostListPrep = $InitialRemoteHostListPrep[0..20]
    if ($PSVersionTable.PSEdition -eq "Core" -and $PSVersionTable.Platform -eq "Win32NT") {
        [System.Collections.ArrayList]$InitialRemoteHostListPrep = $InitialRemoteHostListPrep | foreach {$_ -replace "CN=",""}
    }
    if ($PSVersionTable.PSEdition -eq "Core" -and $PSVersionTable.Platform -eq "Unix") {
        [System.Collections.ArrayList]$InitialRemoteHostListPrep = $InitialRemoteHostListPrep | foreach {$($_ -replace "cn: ","").Trim()}
    }

    # Filter Out the Remote Hosts that we can't resolve
    [System.Collections.ArrayList]$InitialRemoteHostList = @()

    # NOTE: Not having the Platform Property necessarily means we're on Windows PowerShell
    if ($PSVersionTable.Platform -eq "Win32NT" -or !$PSVersionTable.Platform) {
        if ($PSVersionTable.PSEdition -eq "Core") {
            Invoke-WinCommand -ComputerName localhost -ScriptBlock {
                $null = Clear-DnsClientCache
            }
        }
        else {
            $null = Clear-DnsClientCache
        }
    }
    else {
        Write-Verbose "Flushing the DNS Client Cache is generally not needed on Linux since the default (for most distros) is not to cache anything."
    }
    
    foreach ($HName in $InitialRemoteHostListPrep) {
        try {
            $RemoteHostNetworkInfo = ResolveHost -HostNameOrIP $HName -ErrorAction Stop

            if ($RemoteHostNetworkInfo.HostName -eq "localhost") {
                $HostNameOutput = hostname
                $HostNameShort = if ($HostNameOutput -match "\.") {$($HostNameOutput -split "\.")[0]} else {$HostNameOutput}
                [System.Collections.ArrayList][array]$IPAddresses = Get-NetworkInfo -InterfaceStatus Up -AddressFamily IPv4 | foreach {$_.Address.IPAddressToString}

                $RemoteHostNetworkInfo.FQDN = $HostNameOutput
                $RemoteHostNetworkInfo.HostName = $HostNameShort
                $RemoteHostNetworkInfo.IPAddressList = $IPAddresses
                $RemoteHostNetworkInfo.Domain = GetDomainName
            }

            # ResolveHost will NOT throw an error even if it can't figure out HostName, Domain, or FQDN as long as $IPAddr IS pingable
            # So, we need to do the below to compensate for code downstream that relies on HostName, Domain, and FQDN
            if (!$RemoteHostNetworkInfo.HostName) {
                $IPAddr = $RemoteHostNetworkInfo.IPAddressList[0]
                $LastTwoOctets = $($IPAddr -split '\.')[2..3] -join 'Dot'
                $UpdatedHostName = NewUniqueString -PossibleNewUniqueString "Unknown$LastTwoOctets" -ArrayOfStrings $PUDRSSyncHT.RemoteHostList.HostName
                $RemoteHostNetworkInfo.HostName = $UpdatedHostName
                $RemoteHostNetworkInfo.FQDN = $UpdatedHostName + '.Unknown'
                $RemoteHostNetworkInfo.Domain = 'Unknown'
            }

            if ($InitialRemoteHostList.FQDN -notcontains $RemoteHostNetworkInfo.FQDN) {
                $null = $InitialRemoteHostList.Add($RemoteHostNetworkInfo)
            }
        }
        catch {
            continue
        }
    }

    $PUDRSSyncHT.Add("RemoteHostList",$InitialRemoteHostList)

    # Add Keys for each of the Remote Hosts in the $InitialRemoteHostList    
    foreach ($RHost in $InitialRemoteHostList) {
        $Key = $RHost.HostName + "Info"
        $Value = @{
            NetworkInfo                 = $RHost
            CredHT                      = $null
            ServerInventoryStatic       = $null
            RelevantNetworkInterfaces   = $null
            LiveDataRSInfo              = $null
            LiveDataTracker             = @{Current = $null; Previous = $null}
        }
        foreach ($DynPage in $($DynamicPages | Where-Object {$_ -notmatch "PSRemotingCreds|ToolSelect"})) {
            $DynPageHT = @{
                LiveDataRSInfo      = $null
                LiveDataTracker     = @{Current = $null; Previous = $null}
            }
            $Value.Add($($DynPage -replace "[\s]",""),$DynPageHT)
        }
        $PUDRSSyncHT.Add($Key,$Value)
    }

    if ($InstallNmap) {
        # Install nmap
        if ($(Get-Module -ListAvailable).Name -notcontains "ProgramManagement") {Install-Module ProgramManagement}
        if ($(Get-Module).Name -notcontains "ProgramManagement") {Import-Module ProgramManagement}
        if (!$(Get-Command nmap -ErrorAction SilentlyContinue)) {
            try {
                Write-Host "Installing 'nmap'. This could take up to 10 minutes..." -ForegroundColor Yellow
                $InstallnmapResult = Install-Program -ProgramName nmap -CommandName nmap
            }
            catch {
                Write-Error $_
                $global:FunctionResult = "1"
                return
            }
        }
        if (!$(Get-Command nmap -ErrorAction SilentlyContinue)) {
            Write-Error "Unable to find the command 'nmap'! Halting!"
            $global:FunctionResult = "1"
            return
        }
        $NmapParentDir = $(Get-Command nmap).Source | Split-Path -Parent
        [System.Collections.Arraylist][array]$CurrentEnvPathArray = $env:Path -split ';' | Where-Object {![System.String]::IsNullOrWhiteSpace($_)}
        if ($CurrentEnvPathArray -notcontains $NmapParentDir) {
            $CurrentEnvPathArray.Insert(0,$NmapParentDir)
            $env:Path = $CurrentEnvPathArray -join ';'
        }
        $SystemPathInRegistry = 'HKLM:\System\CurrentControlSet\Control\Session Manager\Environment'
        $CurrentSystemPath = $(Get-ItemProperty -Path $SystemPathInRegistry -Name PATH).Path
        [System.Collections.Arraylist][array]$CurrentSystemPathArray = $CurrentSystemPath -split ";" | Where-Object {![System.String]::IsNullOrWhiteSpace($_)}
        if ($CurrentSystemPathArray -notcontains $NmapParentDir) {
            $CurrentSystemPathArray.Insert(0,$NmapParentDir)
            $UpdatedSystemPath = $CurrentSystemPathArray -join ';'
            Set-ItemProperty -Path $SystemPathInRegistry -Name PATH -Value $UpdatedSystemPath
        }
    }

    #endregion >> Prep


    #region >> Dynamic Pages

'Add Dynamic Pages Here'

    #endregion >> Dynamic Pages


    #region >> Static Pages

'Add Static Pages Here'

    #endregion >> Static Pages
    
    # Finalize the Site
    $Theme = New-UDTheme -Name "DefaultEx" -Parent Default -Definition @{
        UDDashboard = @{
            BackgroundColor = "rgb(255,255,255)"
        }
    }
    $MyDashboard = New-UDDashboard -Title "PUD Admin Center" -Pages $Pages -Theme $Theme

    # Start the Site
    Start-UDDashboard -Dashboard $MyDashboard -Port $Port
}

# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUePizpsqRPBumpH/F5+8luojQ
# Ll2gggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
# 9w0BAQsFADAwMQwwCgYDVQQGEwNMQUIxDTALBgNVBAoTBFpFUk8xETAPBgNVBAMT
# CFplcm9EQzAxMB4XDTE3MDkyMDIxMDM1OFoXDTE5MDkyMDIxMTM1OFowPTETMBEG
# CgmSJomT8ixkARkWA0xBQjEUMBIGCgmSJomT8ixkARkWBFpFUk8xEDAOBgNVBAMT
# B1plcm9TQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDCwqv+ROc1
# bpJmKx+8rPUUfT3kPSUYeDxY8GXU2RrWcL5TSZ6AVJsvNpj+7d94OEmPZate7h4d
# gJnhCSyh2/3v0BHBdgPzLcveLpxPiSWpTnqSWlLUW2NMFRRojZRscdA+e+9QotOB
# aZmnLDrlePQe5W7S1CxbVu+W0H5/ukte5h6gsKa0ktNJ6X9nOPiGBMn1LcZV/Ksl
# lUyuTc7KKYydYjbSSv2rQ4qmZCQHqxyNWVub1IiEP7ClqCYqeCdsTtfw4Y3WKxDI
# JaPmWzlHNs0nkEjvnAJhsRdLFbvY5C2KJIenxR0gA79U8Xd6+cZanrBUNbUC8GCN
# wYkYp4A4Jx+9AgMBAAGjggEqMIIBJjASBgkrBgEEAYI3FQEEBQIDAQABMCMGCSsG
# AQQBgjcVAgQWBBQ/0jsn2LS8aZiDw0omqt9+KWpj3DAdBgNVHQ4EFgQUicLX4r2C
# Kn0Zf5NYut8n7bkyhf4wGQYJKwYBBAGCNxQCBAweCgBTAHUAYgBDAEEwDgYDVR0P
# AQH/BAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAUdpW6phL2RQNF
# 7AZBgQV4tgr7OE0wMQYDVR0fBCowKDAmoCSgIoYgaHR0cDovL3BraS9jZXJ0ZGF0
# YS9aZXJvREMwMS5jcmwwPAYIKwYBBQUHAQEEMDAuMCwGCCsGAQUFBzAChiBodHRw
# Oi8vcGtpL2NlcnRkYXRhL1plcm9EQzAxLmNydDANBgkqhkiG9w0BAQsFAAOCAQEA
# tyX7aHk8vUM2WTQKINtrHKJJi29HaxhPaHrNZ0c32H70YZoFFaryM0GMowEaDbj0
# a3ShBuQWfW7bD7Z4DmNc5Q6cp7JeDKSZHwe5JWFGrl7DlSFSab/+a0GQgtG05dXW
# YVQsrwgfTDRXkmpLQxvSxAbxKiGrnuS+kaYmzRVDYWSZHwHFNgxeZ/La9/8FdCir
# MXdJEAGzG+9TwO9JvJSyoGTzu7n93IQp6QteRlaYVemd5/fYqBhtskk1zDiv9edk
# mHHpRWf9Xo94ZPEy7BqmDuixm4LdmmzIcFWqGGMo51hvzz0EaE8K5HuNvNaUB/hq
# MTOIB5145K8bFOoKHO4LkTCCBc8wggS3oAMCAQICE1gAAAH5oOvjAv3166MAAQAA
# AfkwDQYJKoZIhvcNAQELBQAwPTETMBEGCgmSJomT8ixkARkWA0xBQjEUMBIGCgmS
# JomT8ixkARkWBFpFUk8xEDAOBgNVBAMTB1plcm9TQ0EwHhcNMTcwOTIwMjE0MTIy
# WhcNMTkwOTIwMjExMzU4WjBpMQswCQYDVQQGEwJVUzELMAkGA1UECBMCUEExFTAT
# BgNVBAcTDFBoaWxhZGVscGhpYTEVMBMGA1UEChMMRGlNYWdnaW8gSW5jMQswCQYD
# VQQLEwJJVDESMBAGA1UEAxMJWmVyb0NvZGUyMIIBIjANBgkqhkiG9w0BAQEFAAOC
# AQ8AMIIBCgKCAQEAxX0+4yas6xfiaNVVVZJB2aRK+gS3iEMLx8wMF3kLJYLJyR+l
# rcGF/x3gMxcvkKJQouLuChjh2+i7Ra1aO37ch3X3KDMZIoWrSzbbvqdBlwax7Gsm
# BdLH9HZimSMCVgux0IfkClvnOlrc7Wpv1jqgvseRku5YKnNm1JD+91JDp/hBWRxR
# 3Qg2OR667FJd1Q/5FWwAdrzoQbFUuvAyeVl7TNW0n1XUHRgq9+ZYawb+fxl1ruTj
# 3MoktaLVzFKWqeHPKvgUTTnXvEbLh9RzX1eApZfTJmnUjBcl1tCQbSzLYkfJlJO6
# eRUHZwojUK+TkidfklU2SpgvyJm2DhCtssFWiQIDAQABo4ICmjCCApYwDgYDVR0P
# AQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB0GA1UdDgQWBBS5d2bhatXq
# eUDFo9KltQWHthbPKzAfBgNVHSMEGDAWgBSJwtfivYIqfRl/k1i63yftuTKF/jCB
# 6QYDVR0fBIHhMIHeMIHboIHYoIHVhoGubGRhcDovLy9DTj1aZXJvU0NBKDEpLENO
# PVplcm9TQ0EsQ049Q0RQLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNl
# cnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9emVybyxEQz1sYWI/Y2VydGlmaWNh
# dGVSZXZvY2F0aW9uTGlzdD9iYXNlP29iamVjdENsYXNzPWNSTERpc3RyaWJ1dGlv
# blBvaW50hiJodHRwOi8vcGtpL2NlcnRkYXRhL1plcm9TQ0EoMSkuY3JsMIHmBggr
# BgEFBQcBAQSB2TCB1jCBowYIKwYBBQUHMAKGgZZsZGFwOi8vL0NOPVplcm9TQ0Es
# Q049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENO
# PUNvbmZpZ3VyYXRpb24sREM9emVybyxEQz1sYWI/Y0FDZXJ0aWZpY2F0ZT9iYXNl
# P29iamVjdENsYXNzPWNlcnRpZmljYXRpb25BdXRob3JpdHkwLgYIKwYBBQUHMAKG
# Imh0dHA6Ly9wa2kvY2VydGRhdGEvWmVyb1NDQSgxKS5jcnQwPQYJKwYBBAGCNxUH
# BDAwLgYmKwYBBAGCNxUIg7j0P4Sb8nmD8Y84g7C3MobRzXiBJ6HzzB+P2VUCAWQC
# AQUwGwYJKwYBBAGCNxUKBA4wDDAKBggrBgEFBQcDAzANBgkqhkiG9w0BAQsFAAOC
# AQEAszRRF+YTPhd9UbkJZy/pZQIqTjpXLpbhxWzs1ECTwtIbJPiI4dhAVAjrzkGj
# DyXYWmpnNsyk19qE82AX75G9FLESfHbtesUXnrhbnsov4/D/qmXk/1KD9CE0lQHF
# Lu2DvOsdf2mp2pjdeBgKMRuy4cZ0VCc/myO7uy7dq0CvVdXRsQC6Fqtr7yob9NbE
# OdUYDBAGrt5ZAkw5YeL8H9E3JLGXtE7ir3ksT6Ki1mont2epJfHkO5JkmOI6XVtg
# anuOGbo62885BOiXLu5+H2Fg+8ueTP40zFhfLh3e3Kj6Lm/NdovqqTBAsk04tFW9
# Hp4gWfVc0gTDwok3rHOrfIY35TGCAfUwggHxAgEBMFQwPTETMBEGCgmSJomT8ixk
# ARkWA0xBQjEUMBIGCgmSJomT8ixkARkWBFpFUk8xEDAOBgNVBAMTB1plcm9TQ0EC
# E1gAAAH5oOvjAv3166MAAQAAAfkwCQYFKw4DAhoFAKB4MBgGCisGAQQBgjcCAQwx
# CjAIoAKAAKECgAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGC
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFC1+UAqKRG3LcLQW
# X9cpGIUVBodXMA0GCSqGSIb3DQEBAQUABIIBAAJc5Y9S/vj80dmfe/RwYgaTRv8d
# 2hgctlzYuz87i2rFGFmbXlrAtMV1rNuHKQNGvosDQC42vBr5BtD7PeNi+L0wMRdV
# ZUn9Bl462EfxTzPUPzbNP3eNspQwU5MZO02xHZdxPi45ICoFmeK71lFmc2BjMZ8K
# gReJVmwetBpxAQF8WscGAwL3sB6Gp/xMyla6Exqu0wJFnKjrZUkjuv5B9sJvOji6
# wZ28R9KSrRGmjLWjnslmFBJQpK9hi6MmKRpxfcE9Eu8LwnxFnxV7ss3q309CGSIj
# IuWy5XIkdBOVGW7jFsWYW3poZDFlzaQRmlMYv0uPyMvbxOrCZjSec8oi3rw=
# SIG # End signature block
