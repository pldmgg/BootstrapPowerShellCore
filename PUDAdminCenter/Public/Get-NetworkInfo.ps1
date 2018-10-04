<#
    .SYNOPSIS
        Get all information about interfaces on your local machine

    .DESCRIPTION
        See .SYNOPSIS

    .PARAMETER InterfaceStatus
        This parameter is OPTIONAL.
        
        This parameter takes a string that has a value of either "Up" or "Down".

    .PARAMETER AddressFamily
        This parameter is OPTIONAL.

        This parameter takes a string that has a value of either "IPv4" or "IPv6"

    .EXAMPLE
        # On Windows
        PS C:\Users\testadmin> Get-NetworkInfo interfaceStatus "Up" -AddressFamily "IPv4"

    .EXAMPLE
        # On Linux
        PS /home/pdadmin/Downloads> Get-NetworkInfo interfaceStatus "Up" -AddressFamily "IPv4"
#>
function Get-NetworkInfo {
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$False)]
        [ValidateSet("Up","Down")]
        [string]$InterfaceStatus,

        [Parameter(Mandatory=$False)]
        [ValidateSet("IPv4","IPv6")]
        [string]$AddressFamily
    )

    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

    if ($AddressFamily) {
        if ($AddressFamily -eq "IPv4") {
            $AddrFam = "InterNetwork"
        }
        if ($AddressFamily -eq "IPv6") {
            $AddrFam = "InterNetworkV6"
        }
    }

    ##### END Variable/Parameter Transforms and PreRun Prep #####


    ##### BEGIN Main Body #####

    [System.Collections.Arraylist]$PSObjectCollection = @()
    $interfaces = [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()

    $InterfacesToExplore = $interfaces
    if ($InterfaceStatus) {
        $InterfacesToExplore = $InterfacesToExplore | Where-Object {$_.OperationalStatus -eq $InterfaceStatus}
    }
    if ($AddressFamily) {
        $InterfacesToExplore = $InterfacesToExplore | Where-Object {$($_.GetIPProperties().UnicastAddresses | foreach {$_.Address.AddressFamily}) -contains $AddrFam}
    }

    foreach ($adapter in $InterfacesToExplore) {
        $ipprops = $adapter.GetIPProperties()
        $ippropsPropertyNames = $($ipprops | Get-Member -MemberType Property).Name

        if ($AddressFamily) {
            $UnicastAddressesToExplore = $ipprops.UnicastAddresses | Where-Object {$_.Address.AddressFamily -eq $AddrFam}
        }
        else {
            $UnicastAddressesToExplore = $ipprops.UnicastAddresses
        }

        foreach ($ip in $UnicastAddressesToExplore) {
            $FinalPSObject = [pscustomobject]@{}
            
            $adapterPropertyNames = $($adapter | Get-Member -MemberType Property).Name
            foreach ($adapterPropName in $adapterPropertyNames) {
                $FinalPSObjectMemberCheck = $($FinalPSObject | Get-Member -MemberType NoteProperty).Name
                if ($FinalPSObjectMemberCheck -notcontains $adapterPropName) {
                    $FinalPSObject | Add-Member -MemberType NoteProperty -Name $adapterPropName -Value $($adapter.$adapterPropName)
                }
            }
            
            foreach ($ippropsPropName in $ippropsPropertyNames) {
                $FinalPSObjectMemberCheck = $($FinalPSObject | Get-Member -MemberType NoteProperty).Name
                if ($FinalPSObjectMemberCheck -notcontains $ippropsPropName -and
                $ippropsPropName -ne "UnicastAddresses" -and $ippropsPropName -ne "MulticastAddresses") {
                    $FinalPSObject | Add-Member -MemberType NoteProperty -Name $ippropsPropName -Value $($ipprops.$ippropsPropName)
                }
            }
                
            $ipUnicastPropertyNames = $($ip | Get-Member -MemberType Property).Name
            foreach ($UnicastPropName in $ipUnicastPropertyNames) {
                $FinalPSObjectMemberCheck = $($FinalPSObject | Get-Member -MemberType NoteProperty).Name
                if ($FinalPSObjectMemberCheck -notcontains $UnicastPropName) {
                    $FinalPSObject | Add-Member -MemberType NoteProperty -Name $UnicastPropName -Value $($ip.$UnicastPropName)
                }
            }
            
            $null = $PSObjectCollection.Add($FinalPSObject)
        }
    }

    $PSObjectCollection

    ##### END Main Body #####
        
}

# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUJuXgx86EBL0VceUIyvWZp/Y7
# hWugggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFAUoEm3/4AaJ857r
# FbyfA+dfqHdUMA0GCSqGSIb3DQEBAQUABIIBABQVbG4tIK7mt9VrceHCJqiTzs8+
# PA0jTna0St1BvUnzgLiVKWh+Sw3kgNhLhBHC42Ym5N7rpVEldps32OTMDlEgkz/v
# Xx3LOf3ZshjLWMWqyiH7lA9rEyqPzz8ju8UnkqyssERnAmMyRSz+X0YjRpIhxBtt
# 7pP9VLo83A1WPZMC/zLXHgPWkL2qiv8Fw6wA7ofF4i6ULt/ZIoucgm9f8GCI5nIv
# ME7D8iQmx6an5aH0t7Ya+UMHW3E8ri+YA+Tcqqjx+CXHcRxB/VC30jfV+V2nyjK9
# gJA+QvgphIv3fy5eEcuDtVDiK1+NjZ8CgKKA1sh/ifbomuU+qdqJexQW0SE=
# SIG # End signature block
