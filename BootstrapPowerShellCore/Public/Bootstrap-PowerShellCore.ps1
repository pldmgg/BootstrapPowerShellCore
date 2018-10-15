<#
    .SYNOPSIS
        Use PowerShell to Update PowerShell Core. If you're on Windows, this function can be used to do the initial
        install of PowerShell Core. On any other OS, a version of PowerShell Core (at least 6.0.0-beta) must already
        be installed and used to run this function.

    .DESCRIPTION
        See SYNOPSIS

    .PARAMETER RemoteOSGuess
        This parameter is OPTIONAL.
        
        This parameter takes a string (either "Windows" or "Linux") that represents the type of platform you anticipate the
        Remote Host has. The default value for this parameter is "Windows".

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

    .PARAMETER OS
        This parameter is OPTIONAL.

        By default, this function probes the Remote Host to determine the OS running on the Remote Host. If you know in advance
        the OS running on the Remote Host, or if the Get-SSHProbe function returns incorrect information, use this parameter
        to specify one of the following values:
            "Ubuntu1404","Ubuntu1604","Ubuntu1804","Ubuntu1810","Debian8","Debian9","CentOS7","RHEL7","OpenSUSE423","Fedora","Raspbian"

    .PARAMETER UsePackageManagement
        This parameter is OPTIONAL, however, it has a default value of $True

        This parameter is a switch. If used (default behavior), the appropriate Package Management system on the Remote Host
        will be used to install PowerShell Core.

        If explicitly set to $False, the appropriate PowerShell Core installation package will be downloaded directly from GitHub
        and installed on the Remote Host.

    .PARAMETER ConfigurePSRemoting
        This parameter is OPTIONAL.

        This parameter is a switch. If used, in addition to installing PowerShell Core, sshd_config will be modified in order to enable
        PSRemoting using PowerShell Core.

    .EXAMPLE
        # Minimal parameters...

        $BootstrapPwshSplatParams = @{
            RemoteHostNameOrIP      = "zerowin16sshb"
            DomainUserNameSS        = "zero\zeroadmin"
            DomainPasswordSS        = $(Read-Host -Prompt "Enter password" -AsSecureString)
        }
        Bootstrap-PowerShellCore @BootstrapPwshSplatParams

    .EXAMPLE
        # Install pwsh AND configure sshd_config for PSRemoting...

        $BootstrapPwshSplatParams = @{
            RemoteHostNameOrIP      = "centos7nodomain"
            LocalUserNameSS         = "centos7nodomain\vagrant"
            LocalPasswordSS         = $(Read-Host -Prompt "Enter password" -AsSecureString)
            ConfigurePSRemoting     = $True
        }
        Bootstrap-PowerShellCore @BootstrapPwshSplatParams

    .EXAMPLE
        # Instead of using the Remote Host's Package Management System (which is default behavior),
        # download and install the appropriate pwsh package directly from GitHub

        $BootstrapPwshSplatParams = @{
            RemoteHostNameOrIP      = "centos7nodomain"
            LocalUserNameSS         = "centos7nodomain\vagrant"
            LocalPasswordSS         = $(Read-Host -Prompt "Enter password" -AsSecureString)
            UsePackageManagement    = $False
        }
        Bootstrap-PowerShellCore @BootstrapPwshSplatParams
        
#>
function Bootstrap-PowerShellCore {
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
        [ValidateSet("Windows","MacOS","Ubuntu1404","Ubuntu1604","Ubuntu1804","Ubuntu1810","Debian8","Debian9","CentOS7","RHEL7","OpenSUSE423","Fedora","Arch","Raspbian")]
        [string]$OS,

        [Parameter(Mandatory=$False)]
        [switch]$UsePackageManagement = $True,

        [Parameter(Mandatory=$False)]
        [switch]$ConfigurePSRemoting
    )

    #region >> Prep

    if (!$(GetElevation)) {
        Write-Error "Please run PowerShell with elevated privileges and try again. Halting!"
        $global:FunctionResult = "1"
        return
    }

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

    if ($KeyFilePath  -and !$($LocalPasswordSS -or $DomainPasswordSS)) {
        $WrnMsg = "If $RemoteHostNameOrIP is running Linux, you will be prompted for a sudo password! If you would like to avoid this prompt, " +
        "please run this function again and include either the -LocalPasswordSS or -DomainPasswordSS parameter."
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

    # Create PSCustomObjects with all applicable installation info
    Write-Host "Determining latest PowerShell Core Packages..."
    $ReleaseInfo = Invoke-RestMethod https://api.github.com/repos/PowerShell/PowerShell/releases/latest
    $PSCorePackageUrls = $ReleaseInfo.assets.browser_download_url
    $PSCorePackageNames = $ReleaseInfo.assets.name
    Write-Host "Determined latest PowerShell Core Packages."
    <#
        https://github.com/PowerShell/PowerShell/releases/download/v6.1.0/powershell-6.1.0-1.rhel.7.x86_64.rpm
        https://github.com/PowerShell/PowerShell/releases/download/v6.1.0/powershell-6.1.0-linux-arm32.tar.gz
        https://github.com/PowerShell/PowerShell/releases/download/v6.1.0/powershell-6.1.0-linux-musl-x64.tar.gz
        https://github.com/PowerShell/PowerShell/releases/download/v6.1.0/powershell-6.1.0-linux-x64.tar.gz
        https://github.com/PowerShell/PowerShell/releases/download/v6.1.0/powershell-6.1.0-osx-x64.pkg
        https://github.com/PowerShell/PowerShell/releases/download/v6.1.0/powershell-6.1.0-osx-x64.tar.gz
        https://github.com/PowerShell/PowerShell/releases/download/v6.1.0/PowerShell-6.1.0-win-arm32.zip
        https://github.com/PowerShell/PowerShell/releases/download/v6.1.0/PowerShell-6.1.0-win-arm64.zip
        https://github.com/PowerShell/PowerShell/releases/download/v6.1.0/PowerShell-6.1.0-win-x64.msi
        https://github.com/PowerShell/PowerShell/releases/download/v6.1.0/PowerShell-6.1.0-win-x64.zip
        https://github.com/PowerShell/PowerShell/releases/download/v6.1.0/PowerShell-6.1.0-win-x86.msi
        https://github.com/PowerShell/PowerShell/releases/download/v6.1.0/PowerShell-6.1.0-win-x86.zip
        https://github.com/PowerShell/PowerShell/releases/download/v6.1.0/powershell_6.1.0-1.debian.8_amd64.deb
        https://github.com/PowerShell/PowerShell/releases/download/v6.1.0/powershell_6.1.0-1.debian.9_amd64.deb
        https://github.com/PowerShell/PowerShell/releases/download/v6.1.0/powershell_6.1.0-1.ubuntu.14.04_amd64.deb
        https://github.com/PowerShell/PowerShell/releases/download/v6.1.0/powershell_6.1.0-1.ubuntu.16.04_amd64.deb
        https://github.com/PowerShell/PowerShell/releases/download/v6.1.0/powershell_6.1.0-1.ubuntu.18.04_amd64.deb
    #>
    switch ($PSCorePackageUrls) {
        {$_ -match "ubuntu" -and $_ -match "14\.04" -and $_ -match "\.deb"} {
            $Ubuntu1404PackageUrl = $_
            $Ubuntu1404PackageName = $($_ -split '/')[-1]
        }
        {$_ -match "ubuntu" -and $_ -match "16\.04" -and $_ -match "\.deb"} {
            $Ubuntu1604PackageUrl = $ArchPackageUrl = $_
            $Ubuntu1604PackageName = $ArchPackageName = $($_ -split '/')[-1]
        }
        {$_ -match "ubuntu" -and $_ -match "18\.04" -and $_ -match "\.deb"} {
            $Ubuntu1804PackageUrl = $_
            $Ubuntu1804PackageName = $($_ -split '/')[-1]
        }
        {$_ -match "debian\.8" -and $_ -match "\.deb"} {
            $Debian8PackageUrl = $_
            $Debian8PackageName = $($_ -split '/')[-1]
        }
        {$_ -match "debian\.9" -and $_ -match "\.deb"} {
            $Debian9PackageUrl = $_
            $Debian9PackageName = $($_ -split '/')[-1]
        }
        {$_ -match "rhel\.7" -and $_ -match "\.rpm"} {
            $CentOS7PackageUrl = $RHEL7PackageUrl = $OpenSUSE423PackageUrl = $Fedora27PackageUrl = $Fedora28PackageUrl = $_
            $CentOS7PackageName = $RHEL7PackageName = $OpenSUSE423PackageName = $Fedora27PackageName = $Fedora28PackageName = $($_ -split '/')[-1]
        }
        {$_ -match "osx" -and $_ -match "\.pkg"} {
            $MacOSPackageUrl = $_
            $MacOSPackageName = $($_ -split '/')[-1]
        }
        {$_ -match "win" -and $_ -match "x64" -and $_ -match "\.msi"} {
            $Win64PackageUrl = $_
            $Win64PackageName = $($_ -split '/')[-1]
        }
        {$_ -match "win" -and $_ -match "x86" -and $_ -match "\.msi"} {
            $Win32PackageUrl = $_
            $Win32PackageName = $($_ -split '/')[-1]
        }
        {$_ -match "win" -and $_ -match "arm64" -and $_ -match "\.zip"} {
            $WinArm64PackageUrl = $_
            $WinArm64PackageName = $($_ -split '/')[-1]
        }
        {$_ -match "win" -and $_ -match "arm32" -and $_ -match "\.zip"} {
            $WinArm32PackageUrl = $_
            $WinArm32PackageName = $($_ -split '/')[-1]
        }
        {$_ -match "linux" -and $_ -match "x64" -and $_ -match "\.tar\.gz"} {
            $LinuxGenericPackageUrl = $_
            $LinuxGenericPackageName = $($_ -split '/')[-1]
        }
        {$_ -match "linux" -and $_ -match "arm32" -and $_ -match "\.tar\.gz"} {
            $LinuxGenericArmPackageUrl = $RaspbianArmPackageUrl = $_
            $LinuxGenericArmPackageName = $RaspbianArmPackageName = $($_ -split '/')[-1]
        }
    }

    # Windows Install Scripts
    # $Windows is a PSCustomObject containing properties: PackageManagerInstallScript, ManualInstallScript, UninstallScript, ConfigurePwshRemotingScript
    $Windows = GetWindowsScripts -Win64PackageUrl $Win64PackageUrl -Win64PackageName $Win64PackageName
    
    # Ubuntu 14.04 Install Info
    $Ubuntu1404 = GetUbuntu1404Scripts -Ubuntu1404PackageUrl $Ubuntu1404PackageUrl -Ubuntu1404PackageName $Ubuntu1404PackageName

    # Ubuntu 16.04 Install Info
    $Ubuntu1604 = GetUbuntu1604Scripts -Ubuntu1604PackageUrl $Ubuntu1604PackageUrl -Ubuntu1604PackageName $Ubuntu1604PackageName

    # Ubuntu 18.04 Install Info
    $Ubuntu1804 = GetUbuntu1804Scripts -Ubuntu1804PackageUrl $Ubuntu1804PackageUrl -Ubuntu1804PackageName $Ubuntu1804PackageName

    # Debian 8 Install Info
    $Debian8 = GetDebian8Scripts -Debian8PackageUrl $Debian8PackageUrl -Debian8PackageName $Debian8PackageName

    # Debian 9 Install Info
    $Debian9 = GetDebian9Scripts -Debian9PackageUrl $Debian9PackageUrl -Debian9PackageName $Debian9PackageName

    # CentOS 7 and RHEL 7 Install Info
    $CentOS7 = GetCentOS7Scripts -CentOS7PackageUrl $CentOS7PackageUrl -CentOS7PackageName $CentOS7PackageName

    # OpenSUSE 42.3 Install Info
    $OpenSUSE423 = GetOpenSUSE423Scripts -OpenSUSE423PackageUrl $OpenSUSE423PackageUrl -OpenSUSE423PackageName $OpenSUSE423PackageName

    # Fedora Install Info
    $Fedora = GetFedoraScripts -FedoraPackageUrl $Fedora28PackageUrl -FedoraPackageName $Fedora28PackageName

    # Raspbian Install Info
    $Raspbian = GetRaspbianScripts -LinuxGenericArmPackageUrl $LinuxGenericArmPackageUrl -LinuxGenericArmPackageName $LinuxGenericArmPackageName

    # The below Operating Systems (Arch and MacOS) are situations where some operations MUST NOT be performed
    # using sudo and others MUST be performed using sudo.

    # Arch Install Info
    $Arch = GetArchScripts

    # MacOS Install Info
    $MacOS = GetMacOSScripts

    #endregion >> Prep

    #region >> Main Body

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

    Write-Host "Get-SSHProbe identified OS: $($OSCheck.OS); Shell: $($OSCheck.Shell)"

    if (!$OS) {
        # It's possible that the OSVersionInfo property is an array of strings, but we don't want the below switch to loop through each one,
        # so we have to make sure we only give the switch one string object (i.e. $SanitizedOSVersionInfo)
        $SanitizedOSVersionInfo = $($OSCheck.OSVersionInfo | foreach {$_ -split "`n"}) -join "`n"
        switch ($SanitizedOSVersionInfo) {
            {$($_ -match 'Microsoft|Windows' -and ![bool]$($_ -match "Linux")) -or $OSCheck.OS -eq "Windows"} {
                $OS = "Windows"
                $WindowsVersion = $OSCheck.OSVersionInfo
            }

            {$_ -match 'Darwin'} {
                $OS = "MacOS"
                $MacOSVersion = $OSCheck.OSVersionInfo
            }

            {$_ -match "Ubuntu 18\.04|18\.04\.[0-9]+-Ubuntu" -or $_ -match "Ubuntu.*1804|Ubuntu.*18\.04|1804.*Ubuntu|18\.04.*Ubuntu"} {
                $OS = "Ubuntu1804"
                $UbuntuVersion = "18.04"
            }

            {$_ -match "Ubuntu 16.04|16.04.[0-9]+-Ubuntu" -or $_ -match "Ubuntu.*1604|Ubuntu.*16\.04|1604.*Ubuntu|16\.04.*Ubuntu"} {
                $OS = "Ubuntu1604"
                $UbuntuVersion = "16.04"
            }

            {$_ -match "Ubuntu 14.04|14.04.[0-9]+-Ubuntu" -or $_ -match "Ubuntu.*1404|Ubuntu.*14\.04|1404.*Ubuntu|14\.04.*Ubuntu"} {
                $OS = "Ubuntu1404"
                $UbuntuVersion = "14.04"
            }

            {$_ -match 'Debian GNU/Linux 8|\+deb8' -or $_ -match "jessie"} {
                $OS = "Debian8"
                $DebianVersion = "8"
            }

            {$_ -match 'Debian GNU/Linux 9|\+deb9' -or $_ -match "stretch"} {
                $OS = "Debian9"
                $DebianVersion = "9"
            }

            {$_ -match 'CentOS|\.el[0-9]\.'} {
                $OS = "CentOS7"
                $CentOSVersion = "7"
            }

            {$_ -match 'RedHat'} {
                $OS = "RHEL7"
                $RHELVersion = "7"
            }

            {$_ -match 'openSUSE|leap.*42\.3|Leap 42\.3|openSUSE Leap'} {
                $OS = "OpenSUSE423"
                $OpenSUSEVersion = "42.3"
            }

            {$_ -match 'Arch Linux|arch[0-9]|-ARCH'} {
                $OS = "Arch"
                $OSVersionInfoLines = $_ -split "`n"
                $KernelVersion = $($OSVersionInfoLines -match "Kernel: ") -split " " -split "-" -match "[0-9]+\.[0-9]+\.[0-9]+"
                $ArchReleaseInfo = Invoke-RestMethod -Uri "https://www.archlinux.org/releng/releases/json"
                $ArchVersionPrep = $($ArchReleaseInfo.releases | Where-Object {$_.kernel_version -eq $KernelVersion}).version
                if ($ArchVersionPrep) {
                    $ArchVersion = @($ArchVersionPrep)[0]
                }
                else {
                    $ArchVersion = @(
                        $ArchReleaseInfo.releases | Where-Object {
                            $_.kernel_version -match $('^' + $($($KernelVersion -split "\.")[0..1] -join '\.'))
                        }
                    )[0]
                }
            }

            {$_ -match 'Fedora 28|fedora:28'} {
                $OS = "Fedora"
                $FedoraVersion = "28"
            }

            {$_ -match 'Fedora 27|fedora:27'} {
                $OS = "Fedora"
                $FedoraVersion = "27"
            }

            {$_ -match 'armv.*GNU'} {
                $OS = "Raspbian"
                $RaspbianVersion = "stretch"
            }
        }
    }

    if (!$OS) {
        Write-Error "Unable to determine OS Version Information for $RemoteHostNameOrIP! Halting!"
        $global:FunctionResult = "1"
        return
    }

    Write-Host "`$OS is: $OS"

    if ($LocalPasswordSS) {
        $LocalPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($LocalPasswordSS))
    }
    If ($DomainPasswordSS) {
        $DomainPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($DomainPasswordSS))
    }

    $TargetOSScripts = Get-Variable -Name $OS -ValueOnly

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

    $OnWindows = !$PSVersionTable.Platform -or $PSVersionTable.Platform -eq "Win32NT"

    if ($OSCheck.OS -eq "Windows") {
        $null = $SSHScriptBuilderSplatParams.Add('WindowsTarget',$True)

        if ($UsePackageManagement) {
            if ($OnWindows) {
                $null = $SSHScriptBuilderSplatParams.Add('WindowsWaitTimeMin',3)
            }
            else {
                #$null = $TargetOSScripts.PackageManagerInstallScript.Add('echo powershellInstallComplete')
            }

            if ($ConfigurePSRemoting) {
                $SSHScriptArray = $TargetOSScripts.ConfigurePwshRemotingScript

                $null = $SSHScriptBuilderSplatParams.Add('SSHScriptArray',$SSHScriptArray)
                $null = $SSHScriptBuilderSplatParams.Add('ScriptCompleteFlag','powershellInstallComplete|pwshConfigComplete')
            }
            else {
                $SSHScriptArray = $TargetOSScripts.PackageManagerInstallScript

                $null = $SSHScriptBuilderSplatParams.Add('SSHScriptArray',$SSHScriptArray)
                $null = $SSHScriptBuilderSplatParams.Add('ScriptCompleteFlag','powershellInstallComplete')
            }
        }
        else {
            if ($OnWindows) {
                $null = $SSHScriptBuilderSplatParams.Add('WindowsWaitTimeMin',3)
            }
            else {
                #$null = $TargetOSScripts.ManualInstallScript.Add('echo powershellInstallComplete')
            }

            if ($ConfigurePSRemoting) {
                $SSHScriptArray = $TargetOSScripts.ConfigurePwshRemotingScript

                $null = $SSHScriptBuilderSplatParams.Add('SSHScriptArray',$SSHScriptArray)
                $null = $SSHScriptBuilderSplatParams.Add('ScriptCompleteFlag','powershellInstallComplete|pwshConfigComplete')
            }
            else {
                $SSHScriptArray = $TargetOSScripts.ManualInstallScript

                $null = $SSHScriptBuilderSplatParams.Add('SSHScriptArray',$SSHScriptArray)
                $null = $SSHScriptBuilderSplatParams.Add('ScriptCompleteFlag','powershellInstallComplete')
            }
        }
    }
    if ($OSCheck.OS -eq "Linux" -and $OS -ne "Arch" -and $OS -ne "MacOS") {
        if ($UsePackageManagement) {
            if ($OnWindows) {
                $null = $TargetOSScripts.PackageManagerInstallScript.Insert($($TargetOSScripts.PackageManagerInstallScript.Count-1),'echo powershellInstallComplete')
                $null = $SSHScriptBuilderSplatParams.Add('WindowsWaitTimeMin',1)
            }
            else {
                $null = $TargetOSScripts.PackageManagerInstallScript.Add('echo powershellInstallComplete')
            }

            if ($ConfigurePSRemoting) {
                $null = $TargetOSScripts.ConfigurePwshRemotingScript.Add('echo pwshConfigComplete')

                $SSHScriptArray = $TargetOSScripts.PackageManagerInstallScript + $TargetOSScripts.ConfigurePwshRemotingScript
                
                $null = $SSHScriptBuilderSplatParams.Add('ElevatedSSHScriptArray',$SSHScriptArray)
                $null = $SSHScriptBuilderSplatParams.Add('ScriptCompleteFlag','powershellInstallComplete|pwshConfigComplete')
            }
            else {
                $SSHScriptArray = $TargetOSScripts.PackageManagerInstallScript
                
                $null = $SSHScriptBuilderSplatParams.Add('ElevatedSSHScriptArray',$SSHScriptArray)
                $null = $SSHScriptBuilderSplatParams.Add('ScriptCompleteFlag','powershellInstallComplete')
            }
        }
        else {
            if ($OnWindows) {
                $null = $TargetOSScripts.ManualInstallScript.Insert($($TargetOSScripts.ManualInstallScript.Count-1),'echo powershellInstallComplete')
                $null = $SSHScriptBuilderSplatParams.Add('WindowsWaitTimeMin',1)
            }
            else {
                $null = $TargetOSScripts.ManualInstallScript.Add('echo powershellInstallComplete')
            }

            if ($ConfigurePSRemoting) {
                $null = $TargetOSScripts.ConfigurePwshRemotingScript.Add('echo pwshConfigComplete')

                $SSHScriptArray = $TargetOSScripts.ManualInstallScript + $TargetOSScripts.ConfigurePwshRemotingScript

                $null = $SSHScriptBuilderSplatParams.Add('ElevatedSSHScriptArray',$SSHScriptArray)
                $null = $SSHScriptBuilderSplatParams.Add('ScriptCompleteFlag','powershellInstallComplete|pwshConfigComplete')
            }
            else {
                $SSHScriptArray = $TargetOSScripts.ManualInstallScript

                $null = $SSHScriptBuilderSplatParams.Add('ElevatedSSHScriptArray',$SSHScriptArray)
                $null = $SSHScriptBuilderSplatParams.Add('ScriptCompleteFlag','powershellInstallComplete')
            }
        }
    }
    if ($OS -eq "Arch" -or $OS -eq "MacOS") {
        if ($UsePackageManagement) {
            if ($OnWindows) {
                $null = $TargetOSScripts.PackageManagerInstallScript.Insert($($TargetOSScripts.PackageManagerInstallScript.Count-1),'echo powershellInstallComplete')
                if ($OS -eq "MacOS") {
                    $null = $SSHScriptBuilderSplatParams.Add('WindowsWaitTimeMin',12)
                }
                else {
                    $null = $SSHScriptBuilderSplatParams.Add('WindowsWaitTimeMin',3)
                }
                if ($OS -eq "Arch") {
                    $null = $SSHScriptBuilderSplatParams.Add('PwdPromptDelaySeconds',180)
                }
            }
            else {
                $null = $TargetOSScripts.PackageManagerInstallScript.Add('echo powershellInstallComplete')
            }

            if ($ConfigurePSRemoting) {
                $null = $TargetOSScripts.ConfigurePwshRemotingScript.Add('echo pwshConfigComplete')
                
                $null = $SSHScriptBuilderSplatParams.Add('SSHScriptArray',$TargetOSScripts.PackageManagerInstallScript)
                $null = $SSHScriptBuilderSplatParams.Add('ElevatedSSHScriptArray',$TargetOSScripts.ConfigurePwshRemotingScript)
                $null = $SSHScriptBuilderSplatParams.Add('ScriptCompleteFlag','powershellInstallComplete|pwshConfigComplete')
            }
            else {
                $null = $SSHScriptBuilderSplatParams.Add('SSHScriptArray',$TargetOSScripts.PackageManagerInstallScript)
                $null = $SSHScriptBuilderSplatParams.Add('ScriptCompleteFlag','powershellInstallComplete')
            }
        }
        else {
            if ($OnWindows) {
                $null = $TargetOSScripts.ManualInstallScript.Insert($($TargetOSScripts.ManualInstallScript.Count-1),'echo powershellInstallComplete')
                if ($OS -eq "MacOS") {
                    $null = $SSHScriptBuilderSplatParams.Add('WindowsWaitTimeMin',12)
                }
                else {
                    $null = $SSHScriptBuilderSplatParams.Add('WindowsWaitTimeMin',3)
                }
                if ($OS -eq "Arch") {
                    $null = $SSHScriptBuilderSplatParams.Add('PwdPromptDelaySeconds',180)
                }
            }
            else {
                $null = $TargetOSScripts.ManualInstallScript.Add('echo powershellInstallComplete')
            }

            if ($ConfigurePSRemoting) {
                $null = $TargetOSScripts.ConfigurePwshRemotingScript.Add('echo pwshConfigComplete')

                $null = $SSHScriptBuilderSplatParams.Add('SSHScriptArray',$TargetOSScripts.ManualInstallScript)
                $null = $SSHScriptBuilderSplatParams.Add('ElevatedSSHScriptArray',$TargetOSScripts.ConfigurePwshRemotingScript)
                $null = $SSHScriptBuilderSplatParams.Add('ScriptCompleteFlag','powershellInstallComplete|pwshConfigComplete')
            }
            else {
                $null = $SSHScriptBuilderSplatParams.Add('SSHScriptArray',$TargetOSScripts.ManualInstallScript)
                $null = $SSHScriptBuilderSplatParams.Add('ScriptCompleteFlag','powershellInstallComplete')
            }
        }
    }

    $FinalOutput = SSHScriptBuilder @SSHScriptBuilderSplatParams

    $FinalOutput
    
    #endregion >> Main Body
}

# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUp7ScRlC2CrPexWmeYEkk0Gz/
# wlmgggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFD93AxoaTo1jjznU
# 020RfV8ecM/sMA0GCSqGSIb3DQEBAQUABIIBAF8unidAUB1f5Q7aR9nzBEQ+D+F8
# Zp2DKvSgNgeC0fLSD4iB8Va624kPNinoEE9YeGAZrYN1BQa6S/fFJ8nYZopPBoq0
# ijU7d76WXLeNnLKKfQIMB0TW9lvqiFt+2LuiIp0Uech6upiwCd/HA4GGOZiqdG2T
# u/jlYpsSuTWE0yD5ObDtYTs1xFbjF7Xm2pCjY+oTuJTI+Eh2M1vipC7ksBPqbvxV
# X6X1l4dmKI/ndU9bQXJ2wFFodoJaSdj1j9Dj8kkf2KONlMZGM02rMoUet/w5a7x1
# zkFJUDwC0dgp7CpP20glfn2GECqs9N91lAMa9MUnTyjTmzEYPBeuuoBv3wE=
# SIG # End signature block
