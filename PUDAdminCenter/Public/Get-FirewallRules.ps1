<#
    
    .SYNOPSIS
        Get Firewall Rules.
    
    .DESCRIPTION
        Get Firewall Rules.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> Get-FirewallRules
    
#>
function Get-FirewallRules {
    Import-Module netsecurity
    
    $sidToPrincipalCache = @{};
    
    function getPrincipalForSid($sid) {
    
        if ($sidToPrincipalCache.ContainsKey($sid)) {
        return $sidToPrincipalCache[$sid]
        }
    
        $propertyBag = @{}
        $propertyBag.userName = ""
        $propertyBag.domain = ""
        $propertyBag.principal = ""
        $propertyBag.ssid = $sid
    
        try{
            $win32Sid = [WMI]"root\cimv2:win32_sid.sid='$sid'";
        $propertyBag.userName = $win32Sid.AccountName;
        $propertyBag.domain = $win32Sid.ReferencedDomainName
    
        try {
            $objSID = New-Object System.Security.Principal.SecurityIdentifier($sid)
            try{
            $objUser = $objSID.Translate( [System.Security.Principal.NTAccount])
            $propertyBag.principal = $objUser.Value;
            } catch [System.Management.Automation.MethodInvocationException]{
            # the sid couldn't be resolved
            }
    
        } catch [System.Management.Automation.MethodInvocationException]{
            # the sid is invalid
        }
    
        } catch [System.Management.Automation.RuntimeException] {
        # failed to get the user info, which is ok, maybe an old SID
        }
    
        $object = New-Object -TypeName PSObject -Prop $propertyBag
        $sidToPrincipalCache.Add($sid, $object)
    
        return $object
    }
    
    function fillUserPrincipalsFromSddl($sddl, $allowedPrincipals, $skippedPrincipals) {
        if ($sddl -eq $null -or $sddl.count -eq 0) {
        return;
        }
    
        $entries = $sddl.split(@("(", ")"));
        foreach ($entry in $entries) {
        $entryChunks = $entry.split(";");
        $sid = $entryChunks[$entryChunks.count - 1];
        if ($entryChunks[0] -eq "A") {
            $allowed = getPrincipalForSid($sid);
            $allowedPrincipals.Add($allowed) > $null;
        } elseif ($entryChunks[0] -eq "D") {
            $skipped = getPrincipalForSid($sid);
            $skippedPrincipals.Add($skipped) > $null;
        }
        }
    }
    
    $stores = @('PersistentStore','RSOP');
    $allRules = @()
    foreach ($store in $stores){
        $rules = (Get-NetFirewallRule -PolicyStore $store)
    
        $rulesHash = @{}
        $rules | foreach {
        $newRule = ($_ | Microsoft.PowerShell.Utility\Select-Object `
            instanceId, `
            name, `
            displayName, `
            description, `
            displayGroup, `
            group, `
            @{Name="enabled"; Expression={$_.Enabled -eq [Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.Enabled]::True}}, `
            profiles, `
            platform, `
            direction, `
            action, `
            edgeTraversalPolicy, `
            looseSourceMapping, `
            localOnlyMapping, `
            owner, `
            primaryStatus, `
            status, `
            enforcementStatus, `
            policyStoreSource, `
            policyStoreSourceType, `
            @{Name="policyStore"; Expression={$store}}, `
            @{Name="addressFilter"; Expression={""}}, `
            @{Name="applicationFilter"; Expression={""}}, `
            @{Name="interfaceFilter"; Expression={""}}, `
            @{Name="interfaceTypeFilter"; Expression={""}}, `
            @{Name="portFilter"; Expression={""}}, `
            @{Name="securityFilter"; Expression={""}}, `
            @{Name="serviceFilter"; Expression={""}})
    
            $rulesHash[$_.CreationClassName] = $newRule
            $allRules += $newRule  }
    
        $addressFilters = (Get-NetFirewallAddressFilter  -PolicyStore $store)
        $applicationFilters = (Get-NetFirewallApplicationFilter  -PolicyStore $store)
        $interfaceFilters = (Get-NetFirewallInterfaceFilter  -PolicyStore $store)
        $interfaceTypeFilters = (Get-NetFirewallInterfaceTypeFilter  -PolicyStore  $store)
        $portFilters = (Get-NetFirewallPortFilter  -PolicyStore $store)
        $securityFilters = (Get-NetFirewallSecurityFilter  -PolicyStore $store)
        $serviceFilters = (Get-NetFirewallServiceFilter  -PolicyStore $store)
    
        $addressFilters | ForEach-Object {
        $newAddressFilter = $_ | Microsoft.PowerShell.Utility\Select-Object localAddress, remoteAddress;
        $newAddressFilter.localAddress = @($newAddressFilter.localAddress)
        $newAddressFilter.remoteAddress = @($newAddressFilter.remoteAddress)
        $rule = $rulesHash[$_.CreationClassName];
        if ($rule){
            $rule.addressFilter = $newAddressFilter
        }
        }
    
        $applicationFilters | ForEach-Object {
        $newApplicationFilter = $_ | Microsoft.PowerShell.Utility\Select-Object program, package;
            $rule = $rulesHash[$_.CreationClassName];
        if ($rule){
            $rule.applicationFilter = $newApplicationFilter
        }
        }
    
        $interfaceFilters | ForEach-Object {
        $newInterfaceFilter = $_ | Microsoft.PowerShell.Utility\Select-Object @{Name="interfaceAlias"; Expression={}};
        $newInterfaceFilter.interfaceAlias = @($_.interfaceAlias);
            $rule = $rulesHash[$_.CreationClassName];
        if ($rule){
            $rule.interfaceFilter = $newInterfaceFilter
        }
        }
    
        $interfaceTypeFilters | foreach {
        $newInterfaceTypeFilter  = $_ | Microsoft.PowerShell.Utility\Select-Object @{Name="interfaceType"; Expression={}};
        $newInterfaceTypeFilter.interfaceType = $_.PSbase.CimInstanceProperties["InterfaceType"].Value;
        $rule = $rulesHash[$_.CreationClassName];
        if ($rule){
            $rule.interfaceTypeFilter = $newInterfaceTypeFilter
        }
        }
    
        $portFilters | foreach {
        $newPortFilter = $_ | Microsoft.PowerShell.Utility\Select-Object dynamicTransport, icmpType, localPort, remotePort, protocol;
        $newPortFilter.localPort = @($newPortFilter.localPort);
        $newPortFilter.remotePort = @($newPortFilter.remotePort);
        $newPortFilter.icmpType = @($newPortFilter.icmpType);
        $rule = $rulesHash[$_.CreationClassName];
        if ($rule){
            $rule.portFilter = $newPortFilter
        }
        }
    
        $securityFilters | ForEach-Object {
        $allowedLocalUsers = New-Object System.Collections.ArrayList;
        $skippedLocalUsers = New-Object System.Collections.ArrayList;
        fillUserPrincipalsFromSddl -sddl $_.localUser -allowedprincipals $allowedLocalUsers -skippedPrincipals $skippedLocalUsers;
    
        $allowedRemoteMachines = New-Object System.Collections.ArrayList;
        $skippedRemoteMachines = New-Object System.Collections.ArrayList;
        fillUserPrincipalsFromSddl -sddl $_.remoteMachine -allowedprincipals $allowedRemoteMachines -skippedPrincipals $skippedRemoteMachines;
    
        $allowedRemoteUsers = New-Object System.Collections.ArrayList;
        $skippedRemoteUsers = New-Object System.Collections.ArrayList;
        fillUserPrincipalsFromSddl -sddl $_.remoteUser -allowedprincipals $allowedRemoteUsers -skippedPrincipals $skippedRemoteUsers;
    
        $newSecurityFilter = $_ | Microsoft.PowerShell.Utility\Select-Object authentication, `
        encryption, `
        overrideBlockRules, `
        @{Name="allowedLocalUsers"; Expression={}}, `
        @{Name="skippedLocalUsers"; Expression={}}, `
        @{Name="allowedRemoteMachines"; Expression={}}, `
        @{Name="skippedRemoteMachines"; Expression={}}, `
        @{Name="allowedRemoteUsers"; Expression={}}, `
        @{Name="skippedRemoteUsers"; Expression={}};
    
        $newSecurityFilter.allowedLocalUsers = $allowedLocalUsers.ToArray()
        $newSecurityFilter.skippedLocalUsers = $skippedLocalUsers.ToArray()
        $newSecurityFilter.allowedRemoteMachines = $allowedRemoteMachines.ToArray()
        $newSecurityFilter.skippedRemoteMachines = $skippedRemoteMachines.ToArray()
        $newSecurityFilter.allowedRemoteUsers = $allowedRemoteUsers.ToArray()
        $newSecurityFilter.skippedRemoteUsers = $skippedRemoteUsers.ToArray()
    
        $rule = $rulesHash[$_.CreationClassName];
        if ($rule){
            $rule.securityFilter = $newSecurityFilter
        }
        }
    
        $serviceFilters | ForEach-Object {
        $newServiceFilter = $_ | Microsoft.PowerShell.Utility\Select-Object serviceName;
        $rule = $rulesHash[$_.CreationClassName];
        if ($rule){
            $rule.serviceFilter = $newServiceFilter
        }
        }
    }
    
    $allRules
    
}

# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUTwyKlW7P644DdZeOZkHAv8om
# QmOgggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFGAJvSPX2HZTS+2A
# W8psyNfdZfm2MA0GCSqGSIb3DQEBAQUABIIBAGE96+N8+Etq8j7pvqE4Sxf+e4rv
# iSSXDpSVu9J6osWeKi7Q/pl4Ndn4R3Qxtrh1y4J6o6ap3gNUt+FHtnS99YCm7YiQ
# E0JHWseVlUT0hqCDyEqoFX/NCW4LxESKxvNHnj2gEtO6q9wnEDobsZprXEecK4zJ
# XtEiI6IZOGe69tBafMJersmu6F28BHMETlHW3qCgefnMLO3bfftsnf8Jt87boAeK
# wZoDhwd39gQLc5hxNo4nYckwTq9eluOEfigUAWuJY9o8dFdkEJ1/tlEJ92MlXl0S
# wR7zfcX0fabVkC7UsVp/f7mA6R+6DjxFirI54LKm4K7YDoT8ge3mkcazFzU=
# SIG # End signature block
