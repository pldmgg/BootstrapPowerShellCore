<#
    .SYNOPSIS
        This function does the following to a Remote Host:

        - Installs the latest version of PowerShell Core using the Remote Host's Package Management system
        - Configures sshd on the Remote Host to use pwsh by default
        - If the Remote Host is Linux, removes the default setting that causes a password prompt when a sudoer uses runs 'sudo pwsh'

    .DESCRIPTION
        See SYNOPSIS

    .PARAMETER RemoteOSGuess
        This parameter is OPTIONAL.
        
        This parameter takes a string (either "Windows" or "Linux") that represents the type of platform you anticipate the
        Remote Host is running. The default value for this parameter is "Windows".

        IMPORTANT NOTE: If you specify "Linux" and it turns out that the Remote Host is running Windows, this function will fail.
        So, if you're not sure, leave the default value "Windows".

    .PARAMETER RemoteHostNameOrIP
        This parameter is MANDATORY.

        This parameter takes a string that represents the DNS-resolvable HostName/FQDN or IPv4 Address of the target Remote Host

    .PARAMETER LocalUserName
        This parameter is MANDATORY for the Parameter Set 'Local'.

        This parameter takes a string that represents the Local User Account on the Remote Host that you are using to ssh into
        the Remote Host. This string must be in format: <RemoteHostName>\<UserName>

    .Parameter DomainUserName
        This parameter is MANDATORY for the Parameter Set 'Domain'.

        This parameter takes a string that represents the Domain User Account on the Remote Host that you are using to ssh into
        the Remote Host. This string must be in format: <DomainShortName>\<UserName>

    .Parameter LocalPasswordSS
        This parameter is OPTIONAL. (However, either -LocalPasswordSS or -KeyFilePath is mandatory for the 'Domain' Parameter Set)

        This parameter takes a securestring that represents the password for the -LocalUserName you are using to ssh into the
        Remote Host.

    .Parameter DomainPasswordSS
        This parameter is OPTIONAL. (However, either -DomainPasswordSS or -KeyFilePath is mandatory for the 'Domain' Parameter Set)

        This parameter takes a securestring that represents the password for the -DomainUserName you are using to ssh into the
        Remote Host.

    .PARAMETER KeyFilePath
        This parameter is OPTIONAL. (However, either -DomainPasswordSS, -LocalPasswordSS, or -KeyFilePath is required)

        This parameter takes a string that represents the full path to the Key File you are using to ssh into the Remote Host.
        Use this parameter instead of -LocalPasswordSS or -DomainPasswordSS.

    .PARAMETER UsePackageManagement
        This parameter is OPTIONAL, however, it has a default value of $True

        This parameter is a switch. If used (default behavior), the appropriate Package Management system on the Remote Host
        will be used to install PowerShell Core.

        If explicitly set to $False, the appropriate PowerShell Core installation package will be downloaded directly from GitHub
        and installed on the Remote Host.

    .PARAMETER DomainUserForNoSudoPwd
        This parameter is OPTIONAL.

        This parameter takes a string or array of strings that represent Domain Users that you would like to allow to use
        'sudo pwsh' without a password prompt. Each user must be in format: <DomainShortName>\<UserName>

        Only applies to Linux Remote Hosts.

    .PARAMETER LocalUserForNoSudoPwd
        This parameter is OPTIONAL.

        This parameter takes a string or array of strings that represent Local Users on the Remote Host that you would like to
        allow to use 'sudo pwsh' without a password prompt. Each user must be in format: <RemoteHostName>\<UserName>

        Only applies to Linux Remote Hosts.

    .PARAMETER DomainGroupForNoSudoPwd
        This parameter is OPTIONAL.

        This parameter takes a string or array of strings that represent Domain Groups that you would like to allow to use
        'sudo pwsh' without a password prompt.

        Only applies to Linux Remote Hosts.

    .EXAMPLE
        # Minimal parameters...

        $ConfigurePwshRemotingSplatParams = @{
            RemoteHostNameOrIP      = "192.168.2.61"
            LocalUserName           = "centos7x\vagrant"
            LocalPasswordSS         = $(Read-Host -Prompt "Enter password" -AsSecureString)
        }
        $ConfigurePwshRemotingResult = Configure-PwshRemoting @ConfigurePwshRemotingSplatParams
        
#>
function Configure-PwshRemoting {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [ValidateSet("Windows","Linux")]
        [string]$RemoteOSGuess = "Windows",

        [Parameter(Mandatory=$True)]
        [string]$RemoteHostNameOrIP,

        [Parameter(
            Mandatory=$True,
            ParameterSetName='Local'
        )]
        [ValidatePattern("\\")] # Must be in format <RemoteHostName>\<User>
        [string]$LocalUserName,

        [Parameter(
            Mandatory=$True,
            ParameterSetName='Domain'    
        )]
        [ValidatePattern("\\")] # Must be in format <DomainShortName>\<User>
        [string]$DomainUserName,

        [Parameter(
            Mandatory=$False,
            ParameterSetName='Local'
        )]
        [securestring]$LocalPasswordSS,

        [Parameter(
            Mandatory=$False,
            ParameterSetName='Domain'
        )]
        [securestring]$DomainPasswordSS,

        [Parameter(Mandatory=$False)]
        [string]$KeyFilePath,

        [Parameter(Mandatory=$False)]
        [ValidatePattern("\\")] # Must be in format <DomainShortName>\<User>
        [string[]]$DomainUserForNoSudoPwd,

        [Parameter(
            Mandatory=$False,
            ParameterSetName='Local'
        )]
        [ValidatePattern("\\")] # Must be in format <DomainShortName>\<User>
        [string[]]$LocalUserForNoSudoPwd,

        [Parameter(
            Mandatory=$False,
            ParameterSetName='Domain'
        )]
        [string[]]$DomainGroupForNoSudoPwd
    )

    #region >> Prep

    if (!$(Get-Command ssh -ErrorAction SilentlyContinue)) {
        Write-Error "Unable to find 'ssh'! Please make sure it is installed and part of your Environment/System Path! Halting!"
        $global:FunctionResult = "1"
        return
    }

    if ($KeyFilePath) {
        if (!$(Test-Path $KeyFilePath)) {
            Write-Error "Unable to find KeyFilePath '$KeyFilePath'! Halting!"
            $global:FunctionResult = "1"
            return
        }

        if (!$LocalUserName -and !$DomainUserName) {
            Write-Error "You must supply either -LocalUserName or -DomainUserName when using the -KeyFilePath parameter! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    try {
        $RemoteHostNetworkInfo = ResolveHost -HostNameOrIP $RemoteHostNameOrIP -ErrorAction Stop
    }
    catch {
        Write-Error $_
        Write-Error "Unable to resolve '$RemoteHostNameOrIP'! Halting!"
        $global:FunctionResult = "1"
        return
    }

    if ($LocalPasswordSS -or $DomainPasswordSS -and $KeyFilePath) {
        Write-Error "Please use EITHER -KeyFilePath OR -LocalPasswordSS/-DomainPasswordSS in order to ssh to $RemoteHostNameOrIP! Halting!"
        $global:FunctionResult = "1"
        return
    }

    if ($LocalUserName) {
        if ($($LocalUserName -split "\\")[0] -ne $RemoteHostNetworkInfo.HostName) {
            $ErrMsg = "The HostName indicated by -LocalUserName (i.e. $($($LocalUserName -split "\\")[0]) is not the same as " +
            "the HostName as determined by network resolution (i.e. $($RemoteHostNetworkInfo.HostName))! Halting!"
            Write-Error $ErrMsg
            $global:FunctionResult = "1"
            return
        }
    }
    if ($DomainUserName) {
        if ($($DomainUserName -split "\\")[0] -ne $($RemoteHostNetworkInfo.Domain -split "\.")[0]) {
            $ErrMsg = "The Domain indicated by -DomainUserName (i.e. '$($($DomainUserName -split "\\")[0])') is not the same as " +
            "the Domain as determined by network resolution (i.e. '$($($RemoteHostNetworkInfo.Domain -split "\.")[0])')! Halting!"
            Write-Error $ErrMsg
            $global:FunctionResult = "1"
            return
        }
    }

    # Probe the Remote Host to get OS and Shell Info
    try {
        Write-Host "Probing $RemoteHostNameOrIP to determine OS and available shell..."

        $GetSSHProbeSplatParams = @{
            RemoteHostNameOrIP  = $RemoteHostNameOrIP
        }
        if ($KeyFilePath) {
            $GetSSHProbeSplatParams.Add("KeyFilePath",$KeyFilePath)
        }
        if ($LocalUserName) {
            $GetSSHProbeSplatParams.Add("LocalUserName",$LocalUserName)
        }
        if ($DomainUserName) {
            $GetSSHProbeSplatParams.Add("DomainUserName",$DomainUserName)
        }
        if ($LocalPasswordSS -and !$KeyFilePath) {
            $GetSSHProbeSplatParams.Add("LocalPasswordSS",$LocalPasswordSS)
        }
        if ($DomainPasswordSS -and !$KeyFilePath) {
            $GetSSHProbeSplatParams.Add("DomainPasswordSS",$DomainPasswordSS)
        }
        if ($RemoteOSGuess) {
            $GetSSHProbeSplatParams.Add("RemoteOSGuess",$RemoteOSGuess)
        }
        
        $OSCheck = Get-SSHProbe @GetSSHProbeSplatParams -ErrorAction Stop
    }
    catch {
        Write-Verbose $_.Exception.Message
        $global:FunctionResult = "1"

        try {
            $null = Stop-AwaitSession
        }
        catch {
            Write-Verbose $_.Exception.Message
        }
    }

    if (!$OSCheck.OS -or !$OSCheck.Shell) {
        try {
            Write-Host "Probing $RemoteHostNameOrIP to determine OS and available shell..."

            $GetSSHProbeSplatParams = @{
                RemoteHostNameOrIP  = $RemoteHostNameOrIP
            }
            if ($KeyFilePath) {
                $GetSSHProbeSplatParams.Add("KeyFilePath",$KeyFilePath)
            }
            if ($LocalUserName) {
                $GetSSHProbeSplatParams.Add("LocalUserName",$LocalUserName)
            }
            if ($DomainUserName) {
                $GetSSHProbeSplatParams.Add("DomainUserName",$DomainUserName)
            }
            if ($LocalPasswordSS -and !$KeyFilePath) {
                $GetSSHProbeSplatParams.Add("LocalPasswordSS",$LocalPasswordSS)
            }
            if ($DomainPasswordSS -and !$KeyFilePath) {
                $GetSSHProbeSplatParams.Add("DomainPasswordSS",$DomainPasswordSS)
            }
            if ($RemoteOSGuess) {
                $GetSSHProbeSplatParams.Add("RemoteOSGuess",$RemoteOSGuess)
            }
            
            $OSCheck = Get-SSHProbe @GetSSHProbeSplatParams -ErrorAction Stop
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
    
            try {
                $null = Stop-AwaitSession
            }
            catch {
                Write-Verbose $_.Exception.Message
            }
    
            return
        }
    }

    if (!$OSCheck.OS -or !$OSCheck.Shell) {
        Write-Error "The Get-SSHProbe function was unable to identify $RemoteHostNameOrIP's platform or default shell! Please check your ssh connection/credentials. Halting!"
        $global:FunctionResult = "1"
        return
    }
    
    if ($OSCheck.OS -eq "Linux") {
        # Check to make sure the user has sudo privileges
        try {
            $GetSudoStatusSplatParams = @{
                RemoteHostNameOrIP  = $RemoteHostNameOrIP
            }
            if ($KeyFilePath) {
                $GetSudoStatusSplatParams.Add("KeyFilePath",$KeyFilePath)
            }
            if ($LocalPasswordSS) {
                $GetSudoStatusSplatParams.Add("LocalPasswordSS",$LocalPasswordSS)
            }
            if ($DomainPasswordSS) {
                $GetSudoStatusSplatParams.Add("DomainPasswordSS",$DomainPasswordSS)
            }
            if ($LocalUserName) {
                $GetSudoStatusSplatParams.Add("LocalUserName",$LocalUserName)
            }
            if ($DomainUserName) {
                $GetSudoStatusSplatParams.Add("DomainUserName",$DomainUserName)
            }
            
            $GetSudoStatusResult = Get-SudoStatus @GetSudoStatusSplatParams
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }
        
        if (!$GetSudoStatusResult.HasSudoPrivileges) {
            Write-Error "The user does not appear to have sudo privileges on $RemoteHostNameOrIP! Halting!"
            $global:FunctionResult = "1"
            return
        }

        # If the user has sudo privileges but there's a password prompt, but -LocalPasswordSS and -DomainPasswordSS
        # parameters were not used, we need to halt
        if ($GetSudoStatusResult.PasswordPrompt) {
            if (!$LocalPasswordSS -and !$DomainPasswordSS) {
                Write-Error "The user will be prompted for a sudo password, but neither the -LocalPasswordSS nor -DomainPasswordSS parameter was provided! Halting!"
                $global:FunctionResult = "1"
                return
            }
        }
    }

    #endregion >> Prep

    #region >> Main

    try {
        $BootstrapPwshSplatParams = @{
            RemoteHostNameOrIP      = $RemoteHostNameOrIP
            ConfigurePSRemoting     = $True
            ErrorAction             = "Stop"
        }
        if ($LocalUserName) {
            $BootstrapPwshSplatParams.Add('LocalUserName',$LocalUserName)
        }
        if ($DomainUserName) {
            $BootstrapPwshSplatParams.Add('DomainUserName',$DomainUserName)
        }

        if ($KeyFilePath) {
            $BootstrapPwshSplatParams.Add('KeyFilePath',$KeyFilePath)
        }
        if ($LocalPasswordSS) {
            $BootstrapPwshSplatParams.Add('LocalPasswordSS',$LocalPasswordSS)
        }
        if ($DomainPasswordSS) {
            $BootstrapPwshSplatParams.Add('DomainPasswordSS',$DomainPasswordSS)
        }
        $BootstrapPwshResult = Bootstrap-PowerShellCore @BootstrapPwshSplatParams
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        return
    }

    if ($OSCheck.OS -eq "Linux") {
        $RemoveSudoPwdSplatParams = @{
            RemoteHostNameOrIP      = $RemoteHostNameOrIP
            ErrorAction             = "Stop"
        }
        if ($LocalUserName) {
            $RemoveSudoPwdSplatParams.Add('LocalUserName',$LocalUserName)
        }
        if ($DomainUserName) {
            $RemoveSudoPwdSplatParams.Add('DomainUserName',$DomainUserName)
        }
        if ($KeyFilePath) {
            $RemoveSudoPwdSplatParams.Add('KeyFilePath',$KeyFilePath)
        }
        if ($LocalPasswordSS) {
            $RemoveSudoPwdSplatParams.Add('LocalPasswordSS',$LocalPasswordSS)
        }
        if ($DomainPasswordSS) {
            $RemoveSudoPwdSplatParams.Add('DomainPasswordSS',$DomainPasswordSS)
        }
        if ($DomainUserForNoSudoPwd) {
            $RemoveSudoPwdSplatParams.Add('DomainUserForNoSudoPwd',$DomainUserForNoSudoPwd)
        }
        elseif ($LocalUserForNoSudoPwd) {
            $RemoveSudoPwdSplatParams.Add('LocalUserForNoSudoPwd',$LocalUserForNoSudoPwd)
        }
        elseif ($DomainGroupForNoSudoPwd) {
            $RemoveSudoPwdSplatParams.Add('DomainGroupForNoSudoPwd',$DomainGroupForNoSudoPwd)
        }
        $RemoveSudoPwdResult = Remove-SudoPwd @RemoveSudoPwdSplatParams
    }

    # Test to make sure PwshRemoting is configured properly
    <#
    $NewPSSessionSplatParams = @{
        HostName    = $RemoteHostNetworkInfo.IPAddressList[0]
    }
    if ($LocalUserName) {
        $NewPSSessionSplatParams.Add('UserName',$LocalUserName)
    }
    if ($DomainUserName) {
        $NewPSSessionSplatParams.Add('UserName',$DomainUserName)
    }
    if ($KeyFilePath) {
        $NewPSSessionSplatParams.Add('KeyFilePath',$KeyFilePath)
    }

    $ToRemoteHost = New-PSSession @NewPSSessionSplatParams
    $SB = {
        $PSVersionTable | ConvertTo-Json
    }
    $Bytes = [System.Text.Encoding]::Unicode.GetBytes($SB.ToString())
    $EncodedCommandPSVerTable = [Convert]::ToBase64String($Bytes)
    Invoke-Command -Session $ToRemoteHost -ScriptBlock {sudo pwsh -EncodedCommand $using:EncodedCommandPSVerTable} | ConvertFrom-Json
    #>

    [pscustomobject]@{
        GetSudoStatusResult     = $GetSudoStatusResult
        BootstrapPwshResult     = $BootstrapPwshResult
        RemoveSudoPwdResult     = $RemoveSudoPwdResult
    }

    #endregion >> Main
}

# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUNP08BZ1LhYAnSmaORGQxXS4S
# Ltqgggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFKuh6K6+pLBI9Xfq
# I6a06R5fgPR1MA0GCSqGSIb3DQEBAQUABIIBAGFoMiXUi6ba+eWP+bySq9c+ZCJ5
# HJNyCEmP9CQbq93qtadnQeIJ4MwT1G3FQAcqWl/FcrS6vOzix1cNoL20g+yazAYF
# YUTRYo0RBx/axmmu+yu37YsqofyaDjgrUObnXs6tM+rdY9Sh+CfNZNkM2kFZBVdm
# nkt4A0CIZfg0XFPd0Dc+fL4fj6JlyEABH98UToJCJ1QsNQGmwL5FJ7gFA0VLvV9q
# X5hwshcUa41Bq+mbnhVVZ3gtXLgbaq2qXSRLqfFv+GQzz2iaiqTDyqnxKmpJIM58
# hEPR4JaN85AELcMPxx0Nse+XUzjgkcd3+GBwGWl31RoxvpuqnsNVZerXTmY=
# SIG # End signature block
