function GetWindowsScripts {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string]$Win64PackageUrl,
    
        [Parameter(Mandatory=$True)]
        [string]$Win64PackageName
    )
    
    [System.Collections.ArrayList]$WindowsPMInstallScriptPrep = @(
        'try {'
        "    if (`$(Get-Module -ListAvailable).Name -notcontains 'ProgramManagement') {`$null = Install-Module ProgramManagement -ErrorAction Stop}"
        "    if (`$(Get-Module).Name -notcontains 'ProgramManagement') {`$null = Import-Module ProgramManagement -ErrorAction Stop}"
        '    $null = Uninstall-Program -ProgramName powershell-core -ErrorAction SilentlyContinue'
        '    $InstallPwshResult = Install-Program -ProgramName powershell-core -CommandName pwsh.exe -ExpectedInstallLocation "$env:ProgramFiles\PowerShell"'
        '    if (!$InstallPwshResult.MainExecutable) {throw "Unable to find pwsh.exe after successful installation!"}'
        '    $RegistrySystemPath = "HKLM:\System\CurrentControlSet\Control\Session Manager\Environment"'
        '    $CurrentSystemPath = $(Get-ItemProperty -Path $RegistrySystemPath -Name PATH).Path'
        '    [System.Collections.Arraylist][array]$CurrentSystemPathArray = $CurrentSystemPath -split ";" | Where-Object {![System.String]::IsNullOrWhiteSpace($_)} | Sort-Object | Get-Unique'
        '    $PwshParentDir = $InstallPwshResult.MainExecutable | Split-Path -Parent'
        '    if ($CurrentSystemPathArray -notcontains $PwshParentDir) {'
        '        $CurrentSystemPathArray.Insert(0,$PwshParentDir)'
        '        $UpdatedSystemPath = $CurrentSystemPathArray -join ";"'
        '        Set-ItemProperty -Path $RegistrySystemPath -Name PATH -Value $UpdatedSystemPath'
        '    }'
        '} catch {'
        '    Write-Error $_'
        "    `$global:FunctionResult = '1'"
        '    return'
        '}'
        'echo powershellInstallComplete'
    )
    $InstallPwshBytes = [System.Text.Encoding]::Unicode.GetBytes($($WindowsPMInstallScriptPrep -join "`n"))
    $EncodedCommandInstallPwsh = [Convert]::ToBase64String($InstallPwshBytes)
    [System.Collections.ArrayList]$WindowsPMInstallScript = @("powershell -NoProfile -EncodedCommand $EncodedCommandInstallPwsh")

    [System.Collections.ArrayList]$WindowsManualInstallScriptPrep = @(
        "`$OutFilePath = Join-Path `$HOME 'Downloads\$Win64PackageName'"
        "Invoke-WebRequest -Uri $Win64PackageUrl -OutFile `$OutFilePath"
        '$DateStamp = Get-Date -Format yyyyMMddTHHmmss'
        '$MSIFullPath = $OutFilePath'
        '$MSIParentDir = $MSIFullPath | Split-Path -Parent'
        '$MSIFileName = $MSIFullPath | Split-Path -Leaf'
        "`$MSIFileNameOnly = `$MSIFileName -replace [regex]::Escape('.msi'),''"
        "`$logFile = Join-Path `$MSIParentDir (`$MSIFileNameOnly + `$DateStamp + '.log')"
        '$MSIArguments = @('
        "    '/i'"
        '    $MSIFullPath'
        "    '/qn'"
        "    '/norestart'"
        "    '/L*v'"
        '    $logFile'
        ')'
        'Start-Process msiexec.exe -ArgumentList $MSIArguments -Wait -NoNewWindow'
        'echo powershellInstallComplete'
    )
    $InstallPwshBytes = [System.Text.Encoding]::Unicode.GetBytes($($WindowsManualInstallScriptPrep -join "`n"))
    $EncodedCommandInstallPwsh = [Convert]::ToBase64String($InstallPwshBytes)
    [System.Collections.ArrayList]$WindowsManualInstallScript = @("powershell -NoProfile -EncodedCommand $EncodedCommandInstallPwsh")

    [System.Collections.ArrayList]$WindowsUninstallScript = @(
        'try {'
        '    if ($(Get-Module -ListAvailable).Name -notcontains "ProgramManagement") {$null = Install-Module ProgramManagement -ErrorAction Stop}'
        '    if ($(Get-Module).Name -notcontains "ProgramManagement") {$null = Import-Module ProgramManagement -ErrorAction Stop}'
        '    Install-Program -ProgramName powershell-core -CommandName pwsh.exe -ExpectedInstallLocation "$env:ProgramFiles\PowerShell" -ErrorAction Stop'
        '} catch {'
        '    Write-Error $_'
        '    $global:FunctionResult = "1"'
        '    return'
        '}'
        'try {'
        '    Uninstall-Program -ProgramName powershell-core -ErrorAction Stop'
        '} catch {'
        '    Write-Error $_'
        '    $global:FunctionResult = "1"'
        '    return'
        '}'
        'echo pwshConfigComplete'
    )
    $InstallPwshBytes = [System.Text.Encoding]::Unicode.GetBytes($($WindowsUninstallScript -join "`n"))
    $EncodedCommandInstallPwsh = [Convert]::ToBase64String($InstallPwshBytes)
    [System.Collections.ArrayList]$WindowsUninstallScript = @("powershell -NoProfile -EncodedCommand $EncodedCommandInstallPwsh")

    [System.Collections.ArrayList]$WindowsPwshRemotingScript = @(
        'try {'
        "    if (`$(Get-Module -ListAvailable).Name -notcontains 'WinSSH') {`$null = Install-Module WinSSH -ErrorAction Stop}"
        "    if (`$(Get-Module).Name -notcontains 'WinSSH') {`$null = Import-Module WinSSH -ErrorAction Stop}"
        '    Install-WinSSH -GiveWinSSHBinariesPathPriority -ConfigureSSHDOnLocalHost -DefaultShell pwsh'
        '} catch {'
        '    Write-Error $_'
        "    `$global:FunctionResult = '1'"
        '    return'
        '}'
    )
    $InstallPwshBytes = [System.Text.Encoding]::Unicode.GetBytes($($WindowsPwshRemotingScript -join "`n"))
    $EncodedCommandInstallPwsh = [Convert]::ToBase64String($InstallPwshBytes)
    [System.Collections.ArrayList]$WindowsPwshRemotingScript = @("powershell -NoProfile -EncodedCommand $EncodedCommandInstallPwsh")

    [pscustomobject]@{
        PackageManagerInstallScript = [System.Collections.ArrayList]$WindowsPMInstallScript
        ManualInstallScript         = [System.Collections.ArrayList]$WindowsManualInstallScript
        UninstallScript             = [System.Collections.ArrayList]$WindowsUninstallScript
        ConfigurePwshRemotingScript = [System.Collections.ArrayList]$WindowsPwshRemotingScript
    }
}

# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUiPuEtfJe55bukUk+36ZMRMvc
# x5igggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFLyC1aGRerAjUo4J
# vGScFYev9304MA0GCSqGSIb3DQEBAQUABIIBAJ0B2k8QSgFCQ1hRXZTXkVcd3X6x
# fF50FY2Y623vQTyrVDs44gua41nqBOteEVg5Po/r2H5qvHXkA0Wi3eMPzaCDCYIE
# 30Qz+d+ZIYeoA/6Quz4z8RlCgGN7LLlxxA+HTtGunjA7kYCW+OfOVCRUWbI/j1kw
# EHyR/5AXmhfE3wY8iSJXSmGHfuRMBYynZZsIlIkbs11wTCX0hrbckgMkrfPAuVIj
# ig445U2A9Ejz1mJ87UndmpByy6HNBPryUp6Sfv0BQx3N/TW4/L3127G+wP3/beGl
# pEZei+XBqM8YAz5EP87CUY+nSNy2eGHgpq+ML/2fWhZ9Ec0lzDeb5BVZVns=
# SIG # End signature block
