<#
    .SYNOPSIS
        Edits /etc/sudoers to allow the specified user to run 'sudo pwsh' without needing to enter a sudo password.

    .DESCRIPTION
        See SYNOPSIS

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
        This parameter is MANDATORY for the Parameter Set 'Local'.

        This parameter takes a securestring that represents the password for the -LocalUserName you are using to ssh into the
        Remote Host.

    .Parameter DomainPasswordSS
        This parameter is MANDATORY for the Parameter Set 'Domain'.

        This parameter takes a securestring that represents the password for the -DomainUserName you are using to ssh into the
        Remote Host.

    .PARAMETER KeyFilePath
        This parameter is OPTIONAL.

        This parameter takes a string that represents the full path to the Key File you are using to ssh into the Remote Host.
        Use this parameter instead of -LocalPasswordSS or -DomainPasswordSS.

    .PARAMETER DomainUserForNoSudoPwd
        This parameter is OPTIONAL.

        This parameter takes a string or array of strings that represent Domain Users that you would like to allow to use
        'sudo pwsh' without a password prompt. Each user must be in format: <DomainShortName>\<UserName>

    .PARAMETER LocalUserForNoSudoPwd
        This parameter is OPTIONAL.

        This parameter takes a string or array of strings that represent Local Users on the Remote Host that you would like to
        allow to use 'sudo pwsh' without a password prompt. Each user must be in format: <RemoteHostName>\<UserName>

    .PARAMETER DomainGroupForNoSudoPwd
        This parameter is OPTIONAL.

        This parameter takes a string or array of strings that represent Domain Groups that you would like to allow to use
        'sudo pwsh' without a password prompt.

    .EXAMPLE
        # Minimal parameters...

        $RemoveSudoPwdSplatParams = @{
            RemoteHostNameOrIP      = "zerowin16sshb"
            DomainUserNameSS        = "zero\zeroadmin"
            DomainPasswordSS        = $(Read-Host -Prompt "Enter password" -AsSecureString)
        }
        Remove-SudoPwd @RemoveSudoPwdSplatParams
    
    .EXAMPLE
        # Remove sudo prompt requirement for multiple Domain Users

        $RemoveSudoPwdSplatParams = @{
            RemoteHostNameOrIP      = "zerowin16sshb"
            DomainUserNameSS        = "zero\zeroadmin"
            DomainPasswordSS        = $(Read-Host -Prompt "Enter password" -AsSecureString)
            DomainUserForNoSudoPwd  = @('zero\zeroadmin','zero\zeroadminbackup')
        }
        Remove-SudoPwd @RemoveSudoPwdSplatParams

    .EXAMPLE
        # Remove sudo prompt requirement for a Domain Group

        $RemoveSudoPwdSplatParams = @{
            RemoteHostNameOrIP      = "zerowin16sshb"
            DomainUserNameSS        = "zero\zeroadmin"
            DomainPasswordSS        = $(Read-Host -Prompt "Enter password" -AsSecureString)
            DomainGroupForNoSudoPwd  = @('Domain Admins')
        }
        Remove-SudoPwd @RemoveSudoPwdSplatParams

    .EXAMPLE
        # Using a local account on the Remote Host...

        $RemoveSudoPwdSplatParams = @{
            RemoteHostNameOrIP      = "centos7nodomain"
            LocalUserNameSS         = "centos7nodomain\vagrant"
            LocalPasswordSS         = $(Read-Host -Prompt "Enter password" -AsSecureString)
        }
        Remove-SudoPwd @RemoveSudoPwdSplatParams

    .EXAMPLE
        # Using an ssh Key File instead of a password...

        $RemoveSudoPwdSplatParams = @{
            RemoteHostNameOrIP      = "centos7nodomain"
            LocalUserNameSS         = "centos7nodomain\vagrant"
            KeyFilePath             = $HOME/.ssh/my_ssh_key
        }
        Remove-SudoPwd @RemoveSudoPwdSplatParams
        
#>
function Remove-SudoPwd {
    [CmdletBinding()]
    Param(
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

    if (!$DomainUserForNoSudoPwd -and !$LocalUserForNoSudoPwd -and !$DomainGroupForNoSudoPwd) {
        if ($LocalUserName) {
            $LocalUserForNoSudoPwd = $LocalUserName
        }
        if ($DomainUserName) {
            $DomainUserForNoSudoPwd = $DomainUserName
        }
    }

    # Make sure the Remote Host is Linux
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
    
    if ($OSCheck.OS -ne "Linux") {
        Write-Error "$RemoteHostNameOrIP does not appear to be running Linux! Halting!"
        $global:FunctionResult = "1"
        return
    }

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

    if ($DomainUserForNoSudoPwd -or $LocalUserForNoSudoPwd -or $DomainGroupForNoSudoPwd) {
        if ($DomainUserForNoSudoPwd) {
            # Check to make sure the Domain User Exists
            try {
                $Domain = GetDomainName
                $LDAPCreds = [pscredential]::new($DomainUserName,$DomainPasswordSS)
                $UserLDAPObjectsPrep = GetUserObjectsInLDAP -Domain $Domain -LDAPCreds $LDAPCreds
            }
            catch {
                Write-Error $_
                $global:FunctionResult = "1"
                return
            }

            # If we're on windows, $UserLDAPObjectsPrep contains DirectoryServices Objects
            if (!$PSVersionTable.Platform -or $PSVersionTable.Platform -eq "Win32NT") {
                $DomainUserNames = $UserLDAPObjectsPrep | foreach {$_.name[0].ToString()}
            }
            else {
                # If we're on Linux, $UserLDAPObjectsPrep contains strings like - cn: zeroadmin
                $DomainUserNames = $UserLDAPObjectsPrep | foreach {$_ -replace [regex]::Escape('cn: '),''}
            }

            $UsersNotFound = [System.Collections.Generic.List[PSObject]]::new()
            foreach ($User in $DomainUserForNoSudoPwd) {
                if ($DomainUserNames -notcontains $($User -split '\\')[-1]) {
                    $UsersNotFound.Add($User)
                }
            }

            if ($UsersNotFound.Count -gt 0) {
                Write-Error "The following users were not found:`n$($UsersNotFound -join "`n")`nHalting!"
                $global:FunctionResult = "1"
                return
            }
        }

        if ($DomainGroupForNoSudoPwd) {
            # Check to make sure the Domain Group Exists
            try {
                $Domain = GetDomainName
                $LDAPCreds = [pscredential]::new($DomainUserName,$DomainPasswordSS)
                $GroupLDAPObjectsPrep = GetGroupObjectsInLDAP -Domain $Domain -LDAPCreds $LDAPCreds
            }
            catch {
                Write-Error $_
                $global:FunctionResult = "1"
                return
            }

            # If we're on windows, $GroupLDAPObjectsPrep contains DirectoryServices Objects
            if (!$PSVersionTable.Platform -or $PSVersionTable.Platform -eq "Win32NT") {
                $DomainGroupNames = $GroupLDAPObjectsPrep | foreach {$_.name[0].ToString()}
            }
            else {
                # If we're on Linux, $GroupLDAPObjectsPrep contains strings like - cn: zeroadmin
                $DomainGroupNames = $GroupLDAPObjectsPrep | foreach {$_ -replace [regex]::Escape('cn: '),''}
            }

            $GroupsNotFound = [System.Collections.Generic.List[PSObject]]::new()
            foreach ($Group in $DomainGroupForNoSudoPwd) {
                if ($DomainGroupNames -notcontains $Group) {
                    $GroupsNotFound.Add($Group)
                }
            }

            if ($GroupsNotFound.Count -gt 0) {
                Write-Error "The following Groups were not found:`n$($GroupsNotFound -join "`n")`nHalting!"
                $global:FunctionResult = "1"
                return
            }
        }
    }

    if (!$PSVersionTable.Platform -or $PSVersionTable.Platform -eq "Win32NT") {
        try {
            if ($(Get-Module -ListAvailable).Name -notcontains 'WinSSH') {$null = Install-Module WinSSH -ErrorAction Stop}
            if ($(Get-Module).Name -notcontains 'WinSSH') {$null = Import-Module WinSSH -ErrorAction Stop}
            Import-Module "$($(Get-Module WinSSH).ModuleBase)\Await\Await.psd1" -ErrorAction Stop
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }

        try {
            $null = Stop-AwaitSession
        }
        catch {
            Write-Verbose $_.Exception.Message
        }
    }

    if ($PSVersionTable.Platform -eq "Unix") {
        # Determine if we have the required Linux commands
        [System.Collections.ArrayList]$LinuxCommands = @(
            "echo"
            "expect"
        )
        [System.Collections.ArrayList]$CommandsNotPresent = @()
        foreach ($CommandName in $LinuxCommands) {
            $CommandCheckResult = command -v $CommandName
            if (!$CommandCheckResult) {
                $null = $CommandsNotPresent.Add($CommandName)
            }
        }

        if ($CommandsNotPresent.Count -gt 0) {
            [System.Collections.ArrayList]$FailedInstalls = @()
            if ($CommandsNotPresent -contains "echo") {
                try {
                    $null = InstallLinuxPackage -PossiblePackageNames "coreutils" -CommandName "echo"
                }
                catch {
                    $null = $FailedInstalls.Add("coreutils")
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
        foreach ($CommandName in $LinuxCommands) {
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

    if ($LocalPasswordSS) {
        $LocalPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($LocalPasswordSS))
    }
    If ($DomainPasswordSS) {
        $DomainPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($DomainPasswordSS))
    }

    $OnWindows = !$PSVersionTable.Platform -or $PSVersionTable.Platform -eq "Win32NT"

    #endregion >> Prep

    #region >> Main

    # cat /etc/sudoers | grep -Eic 'Cmnd_Alias SUDO_PWSH = /bin/pwsh' > /dev/null && echo present || echo absent
    [System.Collections.Generic.List[PSObject]]$UpdateSudoersScript = @(
        'pscorepath=$(command -v pwsh)'
        "cat /etc/sudoers | grep -Eic 'Cmnd_Alias SUDO_PWSH =' > /dev/null && echo present || echo 'Cmnd_Alias SUDO_PWSH = '`"`$pscorepath`" | sudo EDITOR='tee -a' visudo"
        "cat /etc/sudoers | grep -Eic 'Defaults!SUDO_PWSH !requiretty' > /dev/null && echo present || echo 'Defaults!SUDO_PWSH !requiretty' | sudo EDITOR='tee -a' visudo"
    )
    if ($DomainUserForNoSudoPwd) {
        foreach ($User in $DomainUserForNoSudoPwd) {
            $DomainNameShort = $($User -split "\\")[0]
            $FullUserName = $($User -split "\\")[-1]

            if (!$OnWindows) {
                $AddUserString = "cat /etc/sudoers | grep -Eic '\%$DomainNameShort..$FullUserName ALL=\(ALL\) NOPASSWD: SUDO_PWSH' > " +
                "/dev/null && echo present || echo '%$DomainNameShort\\\$FullUserName ALL=(ALL) NOPASSWD: SUDO_PWSH' | sudo EDITOR='tee -a' visudo"
            }
            else {
                $AddUserString = "cat /etc/sudoers | grep -Eic '\%$DomainNameShort..$FullUserName ALL=\(ALL\) NOPASSWD: SUDO_PWSH' > " +
                "/dev/null && echo present || echo '%$DomainNameShort\\$FullUserName ALL=(ALL) NOPASSWD: SUDO_PWSH' | sudo EDITOR='tee -a' visudo"
            }

            $UpdateSudoersScript.Add($AddUserString)
        }
    }
    if ($DomainGroupForNoSudoPwd) {
        $DomainNameShort = $($Domain -split '\.')[0]
        
        foreach ($Group in $DomainGroupForNoSudoPwd) {
            # Ultimately needs to look like:
            #     %zero\\Domain\ Admins    ALL=(ALL)    ALL
            $FinalGroup = $Group -replace "[\s]","\ "
            $FinalGroupRegex = $Group -replace "[\s]",". "
            $FinalGroupAddString = $Group -replace "[\s]","\\ "

            if (!$OnWindows) {
                $AddUserString = "cat /etc/sudoers | grep -Eic '\%$DomainNameShort..$FinalGroupRegex ALL=\(ALL\) NOPASSWD: SUDO_PWSH' > " +
                "/dev/null && echo present || echo '%$DomainNameShort\\\$FinalGroupAddString ALL=(ALL) NOPASSWD: SUDO_PWSH' | sudo EDITOR='tee -a' visudo"
            }
            else {
                $AddUserString = "cat /etc/sudoers | grep -Eic '\%$DomainNameShort..$FinalGroupRegex ALL=\(ALL\) NOPASSWD: SUDO_PWSH' > " +
                "/dev/null && echo present || echo '%$DomainNameShort\\$FinalGroup ALL=(ALL) NOPASSWD: SUDO_PWSH' | sudo EDITOR='tee -a' visudo"
            }

            $UpdateSudoersScript.Add($AddUserString)
        }
    }
    if ($LocalUserForNoSudoPwd) {
        foreach ($User in $LocalUserForNoSudoPwd) {
            $FullUserName = $($User -split "\\")[-1]

            $AddUserString = "cat /etc/sudoers | grep -Eic '$FullUserName ALL=\(ALL\) NOPASSWD: SUDO_PWSH' > " +
            "/dev/null && echo present || echo '$FullUserName ALL=(ALL) NOPASSWD: SUDO_PWSH' | sudo EDITOR='tee -a' visudo"

            $UpdateSudoersScript.Add($AddUserString)
        }
    }
    $null = $UpdateSudoersScript.Add('echo sudoersUpdated')

    $SSHScriptBuilderSplatParams = @{
        RemoteHostNameOrIP      = $RemoteHostNameOrIP
    }
    if ($LocalUserName) {
        $null = $SSHScriptBuilderSplatParams.Add('LocalUserName',$LocalUserName)
    }
    if ($DomainUserName) {
        $null = $SSHScriptBuilderSplatParams.Add('DomainUserName',$DomainUserName)
    }
    if ($LocalPassword) {
        $null = $SSHScriptBuilderSplatParams.Add('LocalPassword',$LocalPassword)
    }
    if ($DomainPassword) {
        $null = $SSHScriptBuilderSplatParams.Add('DomainPassword',$DomainPassword)
    }

    if ($OnWindows) {
        $null = $SSHScriptBuilderSplatParams.Add('WindowsWaitTimeMin',1)
    }
        
    $null = $SSHScriptBuilderSplatParams.Add('ElevatedSSHScriptArray',$UpdateSudoersScript)

    $FinalOutput = SSHScriptBuilder @SSHScriptBuilderSplatParams
    
    $FinalOutput

    #endregion >> Main
}

# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUSp2HPGz0uFO1MBlQZ5xEES2o
# 7ZWgggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFFWi/iedusmlWiH2
# unNh9mi/7a0eMA0GCSqGSIb3DQEBAQUABIIBALV1SBw/6vDDEvf7QU3SJbnezX5S
# CbBJ42g1TsuUl1q33Ml1kgvFvaFY3K6oMCUxH1/TASJj+6v1b+B6mUeYsU+9MV38
# NfrXdCsOuDwNM9X0nRLBzMbFDvX7udBX2JVCfyxyXQqRXMzYh6b9/on4fSoQPVPi
# c5BEKf0S4Xgq4samDYx7DkC1SIsNfTGEKn84sqO86aKbzlrWLUVkrluPV+ARlNbG
# mX2kchb9w2VIsh6u96ua6NURp/EUnUvWsHfmLJPveSVCyslBM7AJlJccQGRo2cRh
# QCHKG/njAsqeC+gJako5ev+P5NKAdhBx6kQbfUqi/EXF6q4tA0mialb5q9c=
# SIG # End signature block
