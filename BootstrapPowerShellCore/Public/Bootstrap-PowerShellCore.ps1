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
        [ValidateSet("Windows","MacOS","Ubuntu1404","Ubuntu1604","Ubuntu1804","Ubuntu1810","Debian8","Debian9","CentOS7","RHEL7","OpenSUSE423","Fedora","Raspbian")]
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
            $Ubuntu1604PackageUrl = $_
            $Ubuntu1604PackageName = $($_ -split '/')[-1]
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
        {$_ -match "linux" -and $_ -match "x64" -and $_ -match "\.tag\.gz"} {
            $LinuxGenericPackageUrl = $_
            $LinuxGenericPackageName = $($_ -split '/')[-1]
        }
        {$_ -match "linux" -and $_ -match "arm32" -and $_ -match "\.tag\.gz"} {
            $LinuxGenericArmPackageUrl = $RaspbianArmPackageUrl = $_
            $LinuxGenericArmPackageName = $RaspbianArmPackageName = $($_ -split '/')[-1]
        }
    }

    # Windows Install Info
    $WindowsPMInstallScriptPrep = @(
        'try {'
        "    if (`$(Get-Module -ListAvailable).Name -notcontains 'ProgramManagement') {`$null = Install-Module ProgramManagement -ErrorAction Stop}"
        "    if (`$(Get-Module).Name -notcontains 'ProgramManagement') {`$null = Import-Module ProgramManagement -ErrorAction Stop}"
        '    Install-Program -ProgramName powershell-core -CommandName pwsh.exe -ExpectedInstallLocation "$env:ProgramFiles\PowerShell"'
        '} catch {'
        '    Write-Error $_'
        "    `$global:FunctionResult = '1'"
        '    return'
        '}'
        'echo powershellInstallComplete'
    )
    $WindowsPMInstallScript = "powershell -NoProfile -Command \```"$($WindowsPMInstallScriptPrep -join '; ')\```""

    $InstallPwshBytes = [System.Text.Encoding]::Unicode.GetBytes($WindowsPMInstallScriptPrep)
    $EncodedCommandInstallPwsh = [Convert]::ToBase64String($InstallPwshBytes)
    $WindowsPMInstallScriptForExpect = "powershell -NoProfile -EncodedCommand $EncodedCommandInstallPwsh"

    $WindowsManualInstallScriptPrep = @(
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
    $WindowsManualInstallScript = "powershell -NoProfile -Command \```"$($WindowsManualInstallScriptPrep -join '; ')\```""

    $InstallPwshBytes = [System.Text.Encoding]::Unicode.GetBytes($WindowsManualInstallScriptPrep)
    $EncodedCommandInstallPwsh = [Convert]::ToBase64String($InstallPwshBytes)
    $WindowsManualInstallScriptForExpect = "powershell -NoProfile -EncodedCommand $EncodedCommandInstallPwsh"

    $WindowsUninstallScript = @(
        'try {'
        '    if ($(Get-Module -ListAvailable).Name -notcontains "ProgramManagement") {$null = Install-Module ProgramManagement -ErrorAction Stop}'
        '    if ($(Get-Module).Name -notcontains "ProgramManagement") {$null = Import-Module ProgramManagement -ErrorAction Stop}'
        '    Install-Program -ProgramName powershell-core -CommandName pwsh.exe'
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
    )

    $InstallPwshBytes = [System.Text.Encoding]::Unicode.GetBytes($WindowsUninstallScript)
    $EncodedCommandInstallPwsh = [Convert]::ToBase64String($InstallPwshBytes)
    $WindowsUninstallScriptForExpect = "powershell -NoProfile -EncodedCommand $EncodedCommandInstallPwsh"

    $WindowsPwshRemotingScript = @(
        'try {'
        "    if (`$(Get-Module -ListAvailable).Name -notcontains 'WinSSH') {`$null = Install-Module WinSSH -ErrorAction Stop}"
        "    if (`$(Get-Module).Name -notcontains 'WinSSH') {`$null = Import-Module WinSSH -ErrorAction Stop}"
        '    Install-WinSSH -GiveWinSSHBinariesPathPriority -ConfigureSSHDOnLocalHost -DefaultShell pwsh'
        '} catch {'
        '    Write-Error $_'
        "    `$global:FunctionResult = '1'"
        '    return'
        '}'
        'echo pwshConfigComplete'
    )

    $InstallPwshBytes = [System.Text.Encoding]::Unicode.GetBytes($WindowsPwshRemotingScript)
    $EncodedCommandInstallPwsh = [Convert]::ToBase64String($InstallPwshBytes)
    $WindowsPwshRemotingScriptForExpect = "powershell -NoProfile -EncodedCommand $EncodedCommandInstallPwsh"

    $Windows = [pscustomobject]@{
        PackageManagerInstallScript = $WindowsPMInstallScript
        ManualInstallScript         = $WindowsManualInstallScript
        UninstallScript             = $WindowsUninstallScript
        ConfigurePwshRemotingScript = $WindowsPwshRemotingScript
        ExpectScripts               = [pscustomobject]@{
            PackageManagerInstallScript = $WindowsPMInstallScriptForExpect
            ManualInstallScript         = $WindowsManualInstallScriptForExpect
            UninstallScript             = $WindowsUninstallScriptForExpect
            ConfigurePwshRemotingScript = $WindowsPwshRemotingScriptForExpect
        }
    }

    # Pwsh PSRemoting Scripts targeting every platform except MacOS
    $PwshRemotingScriptPrep = @(
        "if echo `$(cat /etc/ssh/sshd_config | grep -c '^Subsystem powershell') > /dev/null -gt 0; then sed -i '/^Subsystem powershell/d' /etc/ssh/sshd_config; fi"
        'pscorepath=$(command -v pwsh)'
        'if test -z $pscorepath; then echo pwshNotFound && exit 1; fi'
        'subsystemline=$(echo \"\"Subsystem powershell $pscorepath -sshs -NoLogo -NoProfile\"\")'
        'sed -i \"\"s|sftp-server|sftp-server\n$subsystemline|\"\" /etc/ssh/sshd_config'
        'systemctl restart sshd'
        'echo pwshConfigComplete'
    )
    $PwshRemotingScript = "sudo bash -c \```"$($PwshRemotingScriptPrep -join '; ')\```""
    $PwshRemotingScriptPrepWindowsToLinux = @(
        "if echo \```$(cat /etc/ssh/sshd_config | grep -c '^Subsystem powershell') > /dev/null -gt 0; then sed -i '/^Subsystem powershell/d' /etc/ssh/sshd_config; fi"
        'pscorepath=\`$(command -v pwsh)'
        'if test -z \`$pscorepath; then echo pwshNotFound && exit 1; fi'
        'subsystemline=\`$(echo \`"\`"Subsystem powershell \`$pscorepath -sshs -NoLogo -NoProfile\`"\`")'
        'sed -i \\\`"s|sftp-server|sftp-server\\n\`$subsystemline|\\\`" /etc/ssh/sshd_config'
        'systemctl restart sshd'
        'echo pwshConfigComplete'
    )
    $PwshRemotingScriptWindowsToLinux = "sudo bash -c \```"$($PwshRemotingScriptPrepWindowsToLinux -join '; ')\```""
    # IMPORTANT NOTE: For Expect, we need to triple (i.e. \\\) for $ and "
    # We need to double (i.e. \\) for \n
    # We need to single (i.e. \) for [, ]
    # No need to escape |, -, /
    $PwshRemotingScriptPrepForExpect = @(
        "if echo \\\`$(cat /etc/ssh/sshd_config | grep -c '^Subsystem powershell') > /dev/null -gt 0; then sed -i '/^Subsystem powershell/d' /etc/ssh/sshd_config; fi"
        'pscorepath=\\\$(command -v pwsh)'
        'if test -z \\\$pscorepath; then echo pwshNotFound && exit 1; fi'
        'subsystemline=\\\$(echo \\\"Subsystem powershell \\\$pscorepath -sshs -NoLogo -NoProfile\\\")'
        'sed -i \\\"s|sftp-server|sftp-server\\\n\\\$subsystemline|\\\" /etc/ssh/sshd_config'
        'systemctl restart sshd'
        'echo pwshConfigComplete'
    )

    # Pwsh PSRemoting Scripts for MacOS target
    # sed -i '' -e 's/sftp-server/\'$'\nSubsystem powershell \/usr\/local\/bin\/pwsh -sshs -NoLogo -NoProfile/g' /etc/ssh/sshd_config
    # sed -i '' -e 's/libexec\/$/libexec\/sftp-server/g' /etc/ssh/sshd_config
    $PwshRemotingScriptPrepForMac = @(
        "cat /etc/ssh/sshd_config | grep -Eic 'Subsystem.*powershell' > /dev/null && echo sed -i '' '/^Subsystem powershell/d' /etc/ssh/sshd_config || echo false"
        'command -v pwsh > /dev/null && echo true || echo pwshNotFound && exit 1'
        "sed -i '' -e 's/sftp-server/\'`$'\nSubsystem powershell \/usr\/local\/bin\/pwsh -sshs -NoLogo -NoProfile/g' /etc/ssh/sshd_config"
        "sed -i '' -e 's/libexec\/`$/libexec\/sftp-server/g' /etc/ssh/sshd_config"
        'launchctl stop com.openssh.sshd && launchctl start com.openssh.sshd'
        'echo pwshConfigComplete'
    )
    $PwshRemotingScriptForMac = "sudo bash -c \```"$($PwshRemotingScriptPrepForMac -join '; ')\```""
    $PwshRemotingScriptPrepForMacWindowsToMac = @(
        "cat /etc/ssh/sshd_config | grep -Eic 'Subsystem.*powershell' > /dev/null && echo sed -i '' '/^Subsystem powershell/d' /etc/ssh/sshd_config || echo false"
        'command -v pwsh > /dev/null && echo true || echo pwshNotFound && exit 1'
        "sed -i '' -e 's/sftp-server/\'\```$'\nSubsystem powershell \/usr\/local\/bin\/pwsh -sshs -NoLogo -NoProfile/g' /etc/ssh/sshd_config"
        "sed -i '' -e 's/libexec\/\```$/libexec\/sftp-server/g' /etc/ssh/sshd_config"
        'launchctl stop com.openssh.sshd && launchctl start com.openssh.sshd'
        'echo pwshConfigComplete'
    )
    $PwshRemotingScriptForMacWindowsToMac = "sudo bash -c \```"$($PwshRemotingScriptPrepForMacWindowsToMac -join '; ')\```""
    $PwshRemotingScriptPrepForMacForExpect = @(
        "cat /etc/ssh/sshd_config | grep -Eic 'Subsystem.*powershell' > /dev/null && echo sed -i '' '/^Subsystem powershell/d' /etc/ssh/sshd_config || echo false"
        'command -v pwsh > /dev/null && echo true || echo pwshNotFound && exit 1'
        "sed -i '' -e 's/sftp-server/\'\\\`$'\nSubsystem powershell \/usr\/local\/bin\/pwsh -sshs -NoLogo -NoProfile/g' /etc/ssh/sshd_config"
        "sed -i '' -e 's/libexec\/\\\`$/libexec\/sftp-server/g' /etc/ssh/sshd_config"
        'launchctl stop com.openssh.sshd && launchctl start com.openssh.sshd'
        'echo pwshConfigComplete'
    )
    
    # Ubuntu 14.04 Install Info
    $Ubuntu1404PMInstallScriptPrep = @(
        'apt-get remove -y powershell'
        'ls packages-microsoft-prod.deb && rm -f packages-microsoft-prod.deb'
        'dpkg --purge packages-microsoft-prod'
        'wget -q https://packages.microsoft.com/config/ubuntu/14.04/packages-microsoft-prod.deb'
        'dpkg -i packages-microsoft-prod.deb'
        'apt-get update'
        #'echo powershellInstallComplete'
        'apt-get install -y powershell && echo powershellInstallComplete'
    )
    $Ubuntu1404PMInstallScript = "sudo bash -c \```"$($Ubuntu1404PMInstallScriptPrep -join '; ')\```""

    $Ubuntu1404ManualInstallScriptPrep = @(
        "wget -q $Ubuntu1404PackageUrl"
        "dpkg -i $Ubuntu1404PackageName"
        #'echo powershellInstallComplete'
        'apt-get install -f && echo powershellInstallComplete'
    )
    $Ubuntu1404ManualInstallScript = "sudo bash -c \```"$($Ubuntu1404ManualInstallScriptPrep -join '; ')\```""

    $Ubuntu1404UninstallScript = 'sudo apt remove powershell'

    $Ubuntu1404 = [pscustomobject]@{
        PackageManagerInstallScript                 = $Ubuntu1404PMInstallScript
        ManualInstallScript                         = $Ubuntu1404ManualInstallScript
        UninstallScript                             = $Ubuntu1404UninstallScript
        ConfigurePwshRemotingScript                 = $PwshRemotingScript
        ConfigurePwshRemotingScriptWindowsToLinux   = $PwshRemotingScriptWindowsToLinux
        ExpectScripts               = [pscustomobject]@{
            PackageManagerInstallScript = $Ubuntu1404PMInstallScriptPrep
            ManualInstallScript         = $Ubuntu1404ManualInstallScriptPrep
            UninstallScript             = $Ubuntu1404UninstallScript
            ConfigurePwshRemotingScript = $PwshRemotingScriptPrepForExpect
        }
    }

    # Ubuntu 16.04 Install Info
    $Ubuntu1604PMInstallScriptPrep = @(
        'apt-get remove -y powershell'
        'ls packages-microsoft-prod.deb && rm -f packages-microsoft-prod.deb'
        'dpkg --purge packages-microsoft-prod'
        'wget -q https://packages.microsoft.com/config/ubuntu/16.04/packages-microsoft-prod.deb'
        'dpkg -i packages-microsoft-prod.deb'
        'apt-get update'
        #'echo powershellInstallComplete'
        'apt-get install -y powershell && echo powershellInstallComplete'
    )
    $Ubuntu1604PMInstallScript = "sudo bash -c \```"$($Ubuntu1604PMInstallScriptPrep -join '; ')\```""

    $Ubuntu1604ManualInstallScriptPrep = @(
        "wget -q $Ubuntu1604PackageUrl"
        "dpkg -i $Ubuntu1604PackageName"
        #'echo powershellInstallComplete'
        'apt-get install -f && echo powershellInstallComplete'
    )
    $Ubuntu1604ManualInstallScript = "sudo bash -c \```"$($Ubuntu1604ManualInstallScriptPrep -join '; ')\```""

    $Ubuntu1604UninstallScript = 'sudo apt remove powershell'

    $Ubuntu1604 = [pscustomobject]@{
        PackageManagerInstallScript                 = $Ubuntu1604PMInstallScript
        ManualInstallScript                         = $Ubuntu1604ManualInstallScript
        UninstallScript                             = $Ubuntu1604UninstallScript
        ConfigurePwshRemotingScript                 = $PwshRemotingScript
        ConfigurePwshRemotingScriptWindowsToLinux   = $PwshRemotingScriptWindowsToLinux
        ExpectScripts               = [pscustomobject]@{
            PackageManagerInstallScript = $Ubuntu1604PMInstallScriptPrep
            ManualInstallScript         = $Ubuntu1604ManualInstallScriptPrep
            UninstallScript             = $Ubuntu1604UninstallScript
            ConfigurePwshRemotingScript = $PwshRemotingScriptPrepForExpect
        }
    }

    # Ubuntu 18.04 Install Info
    $Ubuntu1804PMInstallScriptPrep = @(
        'apt-get remove -y powershell'
        'ls packages-microsoft-prod.deb && rm -f packages-microsoft-prod.deb'
        'dpkg --purge packages-microsoft-prod'
        'wget -q https://packages.microsoft.com/config/ubuntu/18.04/packages-microsoft-prod.deb'
        'dpkg -i packages-microsoft-prod.deb'
        'apt-get update'
        #'echo powershellInstallComplete'
        'apt-get install -y powershell && echo powershellInstallComplete'
    )
    $Ubuntu1804PMInstallScript = "sudo bash -c \```"$($Ubuntu1804PMInstallScriptPrep -join '; ')\```""

    $Ubuntu1804ManualInstallScriptPrep = @(
        "wget -q $Ubuntu1804PackageUrl"
        "dpkg -i $Ubuntu1804PackageName"
        #'echo powershellInstallComplete'
        'apt-get install -f && echo powershellInstallComplete'
    )
    $Ubuntu1804ManualInstallScript = "sudo bash -c \```"$($Ubuntu1804ManualInstallScriptPrep -join '; ')\```""

    $Ubuntu1804UninstallScript = 'sudo apt remove powershell'

    $Ubuntu1804 = [pscustomobject]@{
        PackageManagerInstallScript                 = $Ubuntu1804PMInstallScript
        ManualInstallScript                         = $Ubuntu1804ManualInstallScript
        UninstallScript                             = $Ubuntu1804UninstallScript
        ConfigurePwshRemotingScript                 = $PwshRemotingScript
        ConfigurePwshRemotingScriptWindowsToLinux   = $PwshRemotingScriptWindowsToLinux
        ExpectScripts               = [pscustomobject]@{
            PackageManagerInstallScript = $Ubuntu1804PMInstallScriptPrep
            ManualInstallScript         = $Ubuntu1804ManualInstallScriptPrep
            UninstallScript             = $Ubuntu1804UninstallScript
            ConfigurePwshRemotingScript = $PwshRemotingScriptPrepForExpect
        }
    }

    # Debian 8 Install Info
    $Debian8PMInstallScriptPrep = @(
        'apt-get remove -y powershell'
        'apt-get install -y curl apt-transport-https ca-certificates'
        'curl https://packages.microsoft.com/keys/microsoft.asc | sudo apt-key add -'
        "sh -c 'echo \`"\`"deb [arch=amd64] https://packages.microsoft.com/repos/microsoft-debian-jessie-prod jessie main\`"\`" > /etc/apt/sources.list.d/microsoft.list'"
        'apt-get update'
        #'echo powershellInstallComplete'
        'apt-get install -y powershell && echo powershellInstallComplete'
    )
    $Debian8PMInstallScript = "sudo bash -c \```"$($Debian8PMInstallScriptPrep -join '; ')\```""

    $Debian8PMInstallScriptPrepForExpect = @(
        'apt-get remove -y powershell'
        'apt install -y curl apt-transport-https ca-certificates'
        'curl https://packages.microsoft.com/keys/microsoft.asc | sudo apt-key add -'
        "sh -c 'echo \\\`"deb \[arch=amd64\] https://packages.microsoft.com/repos/microsoft-debian-jessie-prod jessie main\\\`" > /etc/apt/sources.list.d/microsoft.list'"
        'apt-get update'
        #'echo powershellInstallComplete'
        'apt-get install -y powershell && echo powershellInstallComplete'
    )

    $Debian8ManualInstallScriptPrep = @(
        "ls $Debian8PackageName && rm -f $Debian8PackageName"
        "wget -q $Debian8PackageUrl"
        "dpkg -i $Debian8PackageName"
        #'echo powershellInstallComplete'
        'apt install -f && echo powershellInstallComplete'
    )
    $Debian8ManualInstallScript = "sudo bash -c \```"$($Debian8ManualInstallScriptPrep -join '; ')\```""

    $Debian8UninstallScript = 'sudo apt remove powershell'

    $Debian8 = [pscustomobject]@{
        PackageManagerInstallScript = $Debian8PMInstallScript
        ManualInstallScript         = $Debian8ManualInstallScript
        UninstallScript             = $Debian8UninstallScript
        ConfigurePwshRemotingScript                 = $PwshRemotingScript
        ConfigurePwshRemotingScriptWindowsToLinux   = $PwshRemotingScriptWindowsToLinux
        ExpectScripts               = [pscustomobject]@{
            PackageManagerInstallScript = $Debian8PMInstallScriptPrepForExpect
            ManualInstallScript         = $Debian8ManualInstallScriptPrep
            UninstallScript             = $Debian8UninstallScript
            ConfigurePwshRemotingScript = $PwshRemotingScriptPrepForExpect
        }
    }

    # Debian 9 Install Info
    $Debian9PMInstallScriptPrep = @(
        'apt-get remove -y powershell'
        'apt-get install -y curl gnupg apt-transport-https ca-certificates'
        'curl https://packages.microsoft.com/keys/microsoft.asc | sudo apt-key add -'
        "sh -c 'echo \`"\`"deb [arch=amd64] https://packages.microsoft.com/repos/microsoft-debian-stretch-prod stretch main\`"\`" > /etc/apt/sources.list.d/microsoft.list'"
        'apt-get update'
        #'echo powershellInstallComplete'
        'apt-get install -y powershell && echo powershellInstallComplete'
    )
    $Debian9PMInstallScript = "sudo bash -c \```"$($Debian9PMInstallScriptPrep -join '; ')\```""

    $Debian9PMInstallScriptPrepForExpect = @(
        'apt-get remove -y powershell'
        'apt-get install -y curl gnupg apt-transport-https ca-certificates'
        'curl https://packages.microsoft.com/keys/microsoft.asc | sudo apt-key add -'
        "sh -c 'echo \\\`"deb \[arch=amd64\] https://packages.microsoft.com/repos/microsoft-debian-stretch-prod stretch main\\\`" > /etc/apt/sources.list.d/microsoft.list'"
        'apt-get update'
        #'echo powershellInstallComplete'
        'apt install -y powershell && echo powershellInstallComplete'
    )

    $Debian9ManualInstallScriptPrep = @(
        "ls $Debian9PackageName && rm -f $Debian9PackageName"
        "wget -q $Debian9PackageUrl"
        "dpkg -i $Debian9PackageName"
        #'echo powershellInstallComplete'
        'apt install -f && echo powershellInstallComplete'
    )
    $Debian9ManualInstallScript = "sudo bash -c \```"$($Debian9ManualInstallScriptPrep -join '; ')\```""

    $Debian9UninstallScript = 'sudo apt remove powershell'

    $Debian9 = [pscustomobject]@{
        PackageManagerInstallScript                 = $Debian9PMInstallScript
        ManualInstallScript                         = $Debian9ManualInstallScript
        UninstallScript                             = $Debian9UninstallScript
        ConfigurePwshRemotingScript                 = $PwshRemotingScript
        ConfigurePwshRemotingScriptWindowsToLinux   = $PwshRemotingScriptWindowsToLinux
        ExpectScripts               = [pscustomobject]@{
            PackageManagerInstallScript = $Debian9PMInstallScriptPrepForExpect
            ManualInstallScript         = $Debian9ManualInstallScriptPrep
            UninstallScript             = $Debian9UninstallScript
            ConfigurePwshRemotingScript = $PwshRemotingScriptPrepForExpect
        }
    }

    # CentOS 7 and RHEL 7 Install Info
    # 'curl -s https://packages.microsoft.com/config/rhel/7/prod.repo > /etc/yum.repos.d/microsoft.repo'
    $CentOS7PMInstallScriptPrep = $RHELPMInstallScriptPrep = @(
        'curl https://packages.microsoft.com/config/rhel/7/prod.repo | sudo tee /etc/yum.repos.d/microsoft.repo'
        #'echo powershellInstallComplete'
        'yum install -y powershell && echo powershellInstallComplete'
    )
    $CentOS7PMInstallScript = $RHEL7PMInstallScript = "sudo bash -c \```"$($CentOS7PMInstallScriptPrep -join '; ')\```""

    $CentOS7ManualInstallScriptPrep = $RHEL7ManualInstallScriptPrep = @(
        #'echo powershellInstallComplete'
        "yum install $CentOS7PackageUrl && echo powershellInstallComplete"
    )
    $CentOS7ManualInstallScript = $RHEL7ManualInstallScript = "sudo bash -c \```"$($CentOS7ManualInstallScriptPrep -join '; ')\```""

    $CentOS7UninstallScript = $RHEL7UninstallScript = 'sudo yum remove powershell'

    $CentOS7 = $RHEL7 = [pscustomobject]@{
        PackageManagerInstallScript                 = $CentOS7PMInstallScript
        ManualInstallScript                         = $CentOS7ManualInstallScript
        UninstallScript                             = $CentOS7UninstallScript
        ConfigurePwshRemotingScript                 = $PwshRemotingScript
        ConfigurePwshRemotingScriptWindowsToLinux   = $PwshRemotingScriptWindowsToLinux
        ExpectScripts               = [pscustomobject]@{
            PackageManagerInstallScript = $CentOS7PMInstallScriptPrep
            ManualInstallScript         = $CentOS7ManualInstallScriptPrep
            UninstallScript             = $CentOS7UninstallScript
            ConfigurePwshRemotingScript = $PwshRemotingScriptPrepForExpect
        }
    }

    # OpenSUSE 42.3 Install Info
    $OpenSUSE423PMInstallScriptPrep = @(
        'zypper -n remove powershell'
        'zypper --non-interactive rr microsoft'
        'rpm --import https://packages.microsoft.com/keys/microsoft.asc'
        'zypper --non-interactive ar --gpgcheck-allow-unsigned-repo https://packages.microsoft.com/rhel/7/prod/ microsoft'
        'zypper --non-interactive update'
        #'echo powershellInstallComplete'
        "rpm -ivh --nodeps $OpenSUSE423PackageUrl && echo powershellInstallComplete"
        #"zypper -n install --force powershell"
    )
    $OpenSUSE423PMInstallScript = "sudo bash -c \```"$($OpenSUSE423PMInstallScriptPrep -join '; ')\```""

    $OpenSUSE423ManualInstallScriptPrep = @(
        'zypper -n remove powershell'
        'zypper --non-interactive rr microsoft'
        'rpm --import https://packages.microsoft.com/keys/microsoft.asc'
        'zypper --non-interactive ar --gpgcheck-allow-unsigned-repo https://packages.microsoft.com/rhel/7/prod/ microsoft'
        #'echo powershellInstallComplete'
        "rpm -ivh --nodeps $OpenSUSE423PackageUrl && echo powershellInstallComplete"
        #"zypper -n install --force $OpenSUSE423PackageUrl"
    )
    $OpenSUSE423ManualInstallScript = "sudo bash -c \```"$($OpenSUSE423ManualInstallScriptPrep -join '; ')\```""

    $OpenSUSE423UninstallScript = 'sudo zypper remove powershell'

    $OpenSUSE423 = [pscustomobject]@{
        PackageManagerInstallScript                 = $OpenSUSE423PMInstallScript
        ManualInstallScript                         = $OpenSUSE423ManualInstallScript
        UninstallScript                             = $OpenSUSE423UninstallScript
        ConfigurePwshRemotingScript                 = $PwshRemotingScript
        ConfigurePwshRemotingScriptWindowsToLinux   = $PwshRemotingScriptWindowsToLinux
        ExpectScripts               = [pscustomobject]@{
            PackageManagerInstallScript = $OpenSUSE423PMInstallScriptPrep
            ManualInstallScript         = $OpenSUSE423ManualInstallScriptPrep
            UninstallScript             = $OpenSUSE423UninstallScript
            ConfigurePwshRemotingScript = $PwshRemotingScriptPrepForExpect
        }
    }

    # Fedora Install Info
    $FedoraPMInstallScriptPrep = @(
        'dnf remove powershell -y'
        'rpm --import https://packages.microsoft.com/keys/microsoft.asc'
        'curl https://packages.microsoft.com/config/rhel/7/prod.repo | sudo tee /etc/yum.repos.d/microsoft.repo'
        'dnf update -y'
        'dnf install -y compat-openssl10'
        #'echo powershellInstallComplete'
        'dnf install -y powershell && echo powershellInstallComplete'
    )
    $FedoraPMInstallScript = "sudo bash -c \```"$($FedoraPMInstallScriptPrep -join '; ')\```""

    $FedoraManualInstallScriptPrep = @(
        'dnf remove powershell -y'
        'dnf install -y compat-openssl10'
        #'echo powershellInstallComplete'
        "dnf install -y $FedoraPackageUrl && echo powershellInstallComplete"
    )
    $FedoraManualInstallScript = "sudo bash -c \```"$($FedoraManualInstallScriptPrep -join '; ')\```""

    $FedoraUninstallScript = 'sudo dnf remove powershell'

    $Fedora = [pscustomobject]@{
        PackageManagerInstallScript                 = $FedoraPMInstallScript
        ManualInstallScript                         = $FedoraManualInstallScript
        UninstallScript                             = $FedoraUninstallScript
        ConfigurePwshRemotingScript                 = $PwshRemotingScript
        ConfigurePwshRemotingScriptWindowsToLinux   = $PwshRemotingScriptWindowsToLinux
        ExpectScripts               = [pscustomobject]@{
            PackageManagerInstallScript = $FedoraPMInstallScriptPrep
            ManualInstallScript         = $FedoraManualInstallScriptPrep
            UninstallScript             = $FedoraUninstallScript
            ConfigurePwshRemotingScript = $PwshRemotingScriptPrepForExpect
        }
    }

    # Raspbian Install Info
    $RaspbianManualInstallScriptPrep = @(
        'apt install libunwind8'
        "wget -q $LinuxGenericArmPackageUrl"
        'mkdir ~/powershell'
        #'echo powershellInstallComplete'
        "tar -xvf ./$LinuxGenericArmPackageName -C ~/powershell && echo powershellInstallComplete"
    )
    $RaspbianManualInstallScript = "sudo bash -c \```"$($RaspbianManualInstallScriptPrep -join '; ')\```""

    $RaspbianUninstallScript = 'rm -rf ~/powershell'

    $Raspbian = [pscustomobject]@{
        PackageManagerInstallScript                 = $null
        ManualInstallScript                         = $RaspbianManualInstallScript
        UninstallScript                             = $RaspbianUninstallScript
        ConfigurePwshRemotingScript                 = $PwshRemotingScript
        ConfigurePwshRemotingScriptWindowsToLinux   = $PwshRemotingScriptWindowsToLinux
        ExpectScripts               = [pscustomobject]@{
            PackageManagerInstallScript = $RaspbianPMInstallScriptPrep
            ManualInstallScript         = $RaspbianManualInstallScriptPrep
            UninstallScript             = $RaspbianUninstallScript
            ConfigurePwshRemotingScript = $PwshRemotingScriptPrepForExpect
        }
    }

    # MacOS Install Info
    <#
    $MacBrewInstall = @'
        usrlocaldir=$(echo "$HOME/usr/local")
        if [ ! -d "$usrlocaldir" ]; then mkdir -p "$usrlocaldir"; fi
        brewscript=$(echo "$(curl -fsSL https://gist.githubusercontent.com/skyl/36563a5be809e54dc139/raw/ad509acb9a3accc6408e184ec5e577657bdae7b3/install.rb)" | sed "s,YOUR_HOME = '',YOUR_HOME = '$HOME',g")
        yes '' | /usr/bin/ruby -e "$brewscript"
        export HOMEBREW_PREFIX=$usrlocaldir
        PATH=$PATH:$HOMEBREW_PREFIX/bin
        chown -R $USER $HOME/usr/local
        brew update
        brew tap caskroom/cask
        brew install openssl
        brew cask reinstall powershell
    '@
    #>
    # Line that worked:
    #    ssh pdadmin@192.168.2.59 "bash -c \`"usrlocaldir=\`$(echo \`"\`"\`$HOME/usr/local\`"\`"); if [ ! -d \`"\`"\`$usrlocaldir/Cellar\`"\`" ]; then mkdir -p \`"\`"\`$usrlocaldir/Cellar\`"\`"; fi; chown -R \`$USER \`$usrlocaldir; curl -fsSL https://raw.githubusercontent.com/pldmgg/BootstrapPowerShellCore/master/BootstrapPowerShellCore/Private/brewinstall.rb > ./brewinstall.rb; chmod +x ./brewinstall.rb; yes '' | ./brewinstall.rb \`$HOME\`""
    #    "bash -c \`"checkInPath=\`$(echo \`"\`"echo \\\`$PATH \| tr ':' '\\n' \| grep -xc \`"\`"); echo \`$checkInPath\`""
    #$BrewInstallNoSudoUrl = 'https://gist.githubusercontent.com/skyl/36563a5be809e54dc139/raw/ad509acb9a3accc6408e184ec5e577657bdae7b3/install.rb'
    $BrewInstallNoSudoUrl = 'https://raw.githubusercontent.com/pldmgg/BootstrapPowerShellCore/master/BootstrapPowerShellCore/Private/brewinstall.rb'
    $MacOSPMInstallScriptPrep = @(
        'usrlocaldir=$(echo \"\"$HOME/usr/local\"\")'
        'if [ ! -d \"\"$usrlocaldir/Cellar\"\" ]; then mkdir -p \"\"$usrlocaldir/Cellar\"\"; fi'
        'chown -R $USER $usrlocaldir'
        'checkbrew=$(command -v brew)'
        $('if test -z $checkbrew; then echo $PATH | tr {0} | grep -xc /usr/local/bin > /dev/null && echo true || PATH=$PATH:/usr/local/bin; fi' -f "':' '\n'")
        'checkbrew=$(command -v brew)'
        $('if test -z $checkbrew; then echo $PATH | tr {0} | grep -xc $usrlocaldir/bin > /dev/null && echo true || PATH=$PATH:$usrlocaldir/bin; fi' -f "':' '\n'")
        'checkbrew=$(command -v brew)'
        'if test -z $checkbrew; then brew cask uninstall powershell; fi'
        $('if test -z $checkbrew; then curl -fsSL {0} > ./brewinstall.rb && chmod +x ./brewinstall.rb; fi' -f $BrewInstallNoSudoUrl)
        "if test -z `$checkbrew; then yes '' | ./brewinstall.rb `$HOME && export HOMEBREW_PREFIX=`$usrlocaldir; fi"
        'brew update'
        'brew tap caskroom/cask'
        'brew install openssl'
        #'echo powershellInstallComplete'
        'brew cask reinstall powershell && echo powershellInstallComplete' # IMPORTANT NOTE: This will prompt for a password!
    )
    $MacOSPMInstallScript = "bash -c \```"$($MacOSPMInstallScriptPrep)\```""

    $MacOSPMInstallScriptPrepWindowsToLinux = @(
        'usrlocaldir=\`$(echo \`"\`"\`$HOME/usr/local\`"\`")'
        'if [ ! -d \`"\`"\`$usrlocaldir/Cellar\`"\`" ]; then mkdir -p \`"\`"\`$usrlocaldir/Cellar\`"\`"; fi'
        'chown -R \`$USER \`$usrlocaldir'
        'checkbrew=\`$(command -v brew)'
        $('if test -z \`$checkbrew; then echo \`$PATH | tr {0} | grep -xc /usr/local/bin > /dev/null && echo true || PATH=\`$PATH:/usr/local/bin; fi' -f "':' '\\n'")
        'checkbrew=\`$(command -v brew)'
        $('if test -z \`$checkbrew; then echo \`$PATH | tr {0} | grep -xc \`$usrlocaldir/bin > /dev/null && echo true || PATH=\`$PATH:\`$usrlocaldir/bin; fi' -f "':' '\\n'")
        'checkbrew=\`$(command -v brew)'
        'if test -z \`$checkbrew; then brew cask uninstall powershell; fi'
        $('if test -z \`$checkbrew; then curl -fsSL {0} > ./brewinstall.rb && chmod +x ./brewinstall.rb; fi' -f $BrewInstallNoSudoUrl)
        "if test -z \```$checkbrew; then yes '' | ./brewinstall.rb \```$HOME && export HOMEBREW_PREFIX=\```$usrlocaldir; fi"
        'brew update'
        'brew tap caskroom/cask'
        'brew install openssl'
        #'echo powershellInstallComplete'
        'brew cask reinstall powershell && echo powershellInstallComplete' # IMPORTANT NOTE: This will prompt for a password!
    )
    $MacOSPMInstallScriptWindowsToLinux = "bash -c \```"$($MacOSPMInstallScriptPrepWindowsToLinux -join '; ')\```""

    $MacOSScriptPrepForExpect = @(
        'usrlocaldir=\\\$(echo \\\"\\\$HOME/usr/local\\\")'
        'if \[ ! -d \\\"\\\$usrlocaldir/Cellar\\\" \]; then mkdir -p \\\"$usrlocaldir/Cellar\\\"; fi'
        'chown -R \\\$USER \\\$usrlocaldir'
        'checkbrew=\\\$(command -v brew)'
        $('if test -z \\\$checkbrew; then echo \\\$PATH | tr {0} | grep -xc /usr/local/bin > /dev/null && echo true || PATH=\\\$PATH:/usr/local/bin; fi' -f "':' '\\\n'")
        'checkbrew=\\\$(command -v brew)'
        $('if test -z \\\$checkbrew; then echo \\\$PATH | tr {0} | grep -xc \\\$usrlocaldir/bin > /dev/null && echo true || PATH=\\\$PATH:\\\$usrlocaldir/bin; fi' -f "':' '\\\n'")
        'checkbrew=\\\$(command -v brew)'
        'if test -z \\\$checkbrew; then brew cask uninstall powershell; fi'
        $('if test -z \\\$checkbrew; then curl -fsSL {0} > ./brewinstall.rb && chmod +x ./brewinstall.rb; fi' -f $BrewInstallNoSudoUrl)
        'if test -z \\\$checkbrew; then yes \\\"\\\" | ./brewinstall.rb \\\$HOME && export HOMEBREW_PREFIX=\\\$usrlocaldir; fi'
        'brew update'
        'brew tap caskroom/cask'
        'brew install openssl'
        #'echo powershellInstallComplete'
        'brew cask reinstall powershell && echo powershellInstallComplete' # IMPORTANT NOTE: This will prompt for a password!
    )

    $MacOSUninstallScript = 'brew cask uninstall powershell'

    $MacOS = [pscustomobject]@{
        PackageManagerInstallScript                 = $MacOSPMInstallScript
        ManualInstallScript                         = $MacOSPMInstallScript
        PackageManagerInstallScriptWindowsToLinux   = $MacOSPMInstallScriptWindowsToLinux
        ManualInstallScriptWindowsToLinux           = $MacOSPMInstallScriptWindowsToLinux
        UninstallScript                             = $MacOSUninstallScript
        ConfigurePwshRemotingScript                 = $PwshRemotingScriptPrepForMac
        ConfigurePwshRemotingScriptWindowsToLinux   = $PwshRemotingScriptForMacWindowsToMac
        ExpectScripts               = [pscustomobject]@{
            PackageManagerInstallScript = $MacOSScriptPrepForExpect
            ManualInstallScript         = $MacOSScriptPrepForExpect
            UninstallScript             = $MacOSUninstallScript
            ConfigurePwshRemotingScript = $PwshRemotingScriptPrepForMacForExpect
        }
    }

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
        switch ($OSCheck.OSVersionInfo) {
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

    if ($LocalUserName) {
        $FullUserName = $($LocalUserName -split "\\")[-1]
    }
    if ($DomainUserName) {
        $DomainNameShort = $($DomainUserName -split "\\")[0]
        $FullUserName = $($DomainUserName -split "\\")[-1]
    }

    $HostNameValue = $RHostIP = @(
        $RemoteHostNetworkInfo.IPAddressList | Where-Object {$_ -notmatch "^169"}
    )[0]

    # This is what we're going for:
    #     ssh pdadmin@192.168.2.10 "$SSHCmdString"
    [System.Collections.ArrayList]$SSHCmdStringArray = @(
        'ssh'
        '-t'
    )
    if ($KeyFilePath) {
        $null = $SSHCmdStringArray.Add("-i")
        $null = $SSHCmdStringArray.Add("'" + $KeyFilePath + "'")
    }
    if ($LocalUserName) {
        $null = $SSHCmdStringArray.Add("$FullUserName@$HostNameValue")
    }
    if ($DomainUserName) {
        $null = $SSHCmdStringArray.Add("$FullUserName@$DomainNameShort@$HostNameValue")
    }

    if ($OSCheck.OS -eq "Windows") {
        if (!$PSVersionTable.Platform -or $PSVersionTable.Platform -eq "Win32NT") {
            $ExpectScripts = $(Get-Variable -Name $OS -ValueOnly).ExpectScripts

            if ($UsePackageManagement) {
                if ($ConfigurePSRemoting) {
                    $SSHScript = $($SSHCmdStringArray -join " ") + ' ' + '"' + $ExpectScripts.ConfigurePwshRemotingScript + '"'
                }
                else {
                    $SSHScript = $($SSHCmdStringArray -join " ") + ' ' + '"' + $ExpectScripts.PackageManagerInstallScript + '"'
                }
            }
            else {
                if ($ConfigurePSRemoting) {
                    $SSHScript = $($SSHCmdStringArray -join " ") + ' ' + '"' + $ExpectScripts.ConfigurePwshRemotingScript + '"'
                }
                else {
                    $SSHScript = $($SSHCmdStringArray -join " ") + ' ' + '"' + $ExpectScripts.ManualInstallScript + '"'
                }
            }

            #Write-Host "`$SSHScript is:`n    $SSHScript"

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

            $PSAwaitProcess = $null
            $null = Start-AwaitSession
            Start-Sleep -Seconds 1
            $null = Send-AwaitCommand '$host.ui.RawUI.WindowTitle = "PSAwaitSession"'
            $PSAwaitProcess = $($(Get-Process | Where-Object {$_.Name -eq "powershell"}) | Sort-Object -Property StartTime -Descending)[0]
            Start-Sleep -Seconds 1
            $null = Send-AwaitCommand "`$env:Path = '$env:Path'"
            Start-Sleep -Seconds 1
            $null = Send-AwaitCommand -Command $([scriptblock]::Create($SSHScript))
            Start-Sleep -Seconds 5

            # This will either not prompt at all, prompt to accept the RemoteHost's RSA Host Key, or prompt for a password
            $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse

            [System.Collections.ArrayList]$CheckForExpectedResponses = @()
            $null = $CheckForExpectedResponses.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
            $Counter = 0
            $CompleteIndicatorRegex = if ($ConfigurePSRemoting) {"^pwshConfigComplete|^powershellInstallComplete"} else {"^powershellInstallComplete"}
            while (![bool]$($($CheckForExpectedResponses -split "`n") -match [regex]::Escape("Are you sure you want to continue connecting (yes/no)?")) -and
            ![bool]$($($CheckForExpectedResponses -split "`n") -match "password.*:") -and 
            ![bool]$($($CheckForExpectedResponses -split "`n") -match $CompleteIndicatorRegex) -and $Counter -le 60
            ) {
                $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse
                $null = $CheckForExpectedResponses.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                if ($CheckResponsesOutput -match "must be greater than zero" -or @($CheckResponsesOutput)[-1] -notmatch "[a-zA-Z]") {
                    break
                }
                Start-Sleep -Seconds 1
                $Counter++
            }
            if ($Counter -eq 61) {
                Write-Verbose "SSH via '$($SSHCmdStringArray -join " ")' timed out!"

                if ($PSAwaitProcess.Id) {
                    try {
                        $null = Stop-AwaitSession
                    }
                    catch {
                        if ($PSAwaitProcess.Id -eq $PID) {
                            Write-Error "The PSAwaitSession never spawned! Halting!"
                            $global:FunctionResult = "1"
                            return
                        }
                        else {
                            if ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue)) {
                                Stop-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue
                            }
                            $Counter = 0
                            while ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue) -and $Counter -le 15) {
                                Write-Verbose "Waiting for Await Module Process Id $($PSAwaitProcess.Id) to end..."
                                Start-Sleep -Seconds 1
                                $Counter++
                            }
                        }
                    }
                }
            }
            #endregion >> Await Attempt 1 of 2

            $CheckResponsesOutput = $CheckForExpectedResponses | foreach {$_ -split "`n"}
            
            #region >> Await Attempt 2 of 2
            
            # If $CheckResponsesOutput contains the string "must be greater than zero", then something broke with the Await Module.
            # Most of the time, just trying again resolves any issues
            if ($CheckResponsesOutput -match "must be greater than zero" -or @($CheckResponsesOutput)[-1] -notmatch "[a-zA-Z]" -and
            ![bool]$($CheckResponsesOutput -match "background process reported an error")) {
                if ($PSAwaitProcess.Id) {
                    try {
                        $null = Stop-AwaitSession
                    }
                    catch {
                        if ($PSAwaitProcess.Id -eq $PID) {
                            Write-Error "The PSAwaitSession never spawned! Halting!"
                            $global:FunctionResult = "1"
                            return
                        }
                        else {
                            if ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue)) {
                                Stop-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue
                            }
                            $Counter = 0
                            while ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue) -and $Counter -le 15) {
                                Write-Verbose "Waiting for Await Module Process Id $($PSAwaitProcess.Id) to end..."
                                Start-Sleep -Seconds 1
                                $Counter++
                            }
                        }
                    }
                }

                $PSAwaitProcess = $null
                $null = Start-AwaitSession
                Start-Sleep -Seconds 1
                $null = Send-AwaitCommand '$host.ui.RawUI.WindowTitle = "PSAwaitSession"'
                $PSAwaitProcess = $($(Get-Process | Where-Object {$_.Name -eq "powershell"}) | Sort-Object -Property StartTime -Descending)[0]
                Start-Sleep -Seconds 1
                $null = Send-AwaitCommand "`$env:Path = '$env:Path'"
                Start-Sleep -Seconds 1
                $null = Send-AwaitCommand -Command $([scriptblock]::Create($SSHScript))
                Start-Sleep -Seconds 5

                # This will either not prompt at all, prompt to accept the RemoteHost's RSA Host Key, or prompt for a password
                $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse

                [System.Collections.ArrayList]$CheckForExpectedResponses = @()
                $null = $CheckForExpectedResponses.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                $Counter = 0
                $CompleteIndicatorRegex = if ($ConfigurePSRemoting) {"^pwshConfigComplete|^powershellInstallComplete"} else {"^powershellInstallComplete"}
                while (![bool]$($SuccessOrAcceptHostKeyOrPwdPrompt -match [regex]::Escape("Are you sure you want to continue connecting (yes/no)?")) -and
                ![bool]$($SuccessOrAcceptHostKeyOrPwdPrompt -match "password.*:") -and 
                ![bool]$($SuccessOrAcceptHostKeyOrPwdPrompt -match $CompleteIndicatorRegex) -and $Counter -le 60
                ) {
                    $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse
                    $null = $CheckForExpectedResponses.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                    Start-Sleep -Seconds 1
                    $Counter++
                }
                if ($Counter -eq 61) {
                    Write-Error "SSH via '$($SSHCmdStringArray -join " ")' timed out!"
                    $global:FunctionResult = "1"

                    #$CheckForExpectedResponses

                    if ($PSAwaitProcess.Id) {
                        try {
                            $null = Stop-AwaitSession
                        }
                        catch {
                            if ($PSAwaitProcess.Id -eq $PID) {
                                Write-Error "The PSAwaitSession never spawned! Halting!"
                                $global:FunctionResult = "1"
                                return
                            }
                            else {
                                if ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue)) {
                                    Stop-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue
                                }
                                $Counter = 0
                                while ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue) -and $Counter -le 15) {
                                    Write-Verbose "Waiting for Await Module Process Id $($PSAwaitProcess.Id) to end..."
                                    Start-Sleep -Seconds 1
                                    $Counter++
                                }
                            }
                        }
                    }

                    return
                }
            }

            #endregion >> Await Attempt 2 of 2

            $CheckResponsesOutput = $CheckForExpectedResponses | foreach {$_ -split "`n"}

            # At this point, if we don't have the expected output, we need to fail
            if ($CheckResponsesOutput -match "must be greater than zero" -or @($CheckResponsesOutput)[-1] -notmatch "[a-zA-Z]" -and
            ![bool]$($CheckResponsesOutput -match "background process reported an error")) {
                Write-Error "Something went wrong with the PowerShell Await Module! Halting!"
                $global:FunctionResult = "1"

                if ($PSAwaitProcess.Id) {
                    try {
                        $null = Stop-AwaitSession
                    }
                    catch {
                        if ($PSAwaitProcess.Id -eq $PID) {
                            Write-Error "The PSAwaitSession never spawned! Halting!"
                            $global:FunctionResult = "1"
                            return
                        }
                        else {
                            if ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue)) {
                                Stop-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue
                            }
                            $Counter = 0
                            while ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue) -and $Counter -le 15) {
                                Write-Verbose "Waiting for Await Module Process Id $($PSAwaitProcess.Id) to end..."
                                Start-Sleep -Seconds 1
                                $Counter++
                            }
                        }
                    }
                }

                return
            }

            # Now we should either have a prompt to accept the host key, a prompt for a password, or it already worked...

            if ($CheckResponsesOutput -match [regex]::Escape("Are you sure you want to continue connecting (yes/no)?")) {
                $null = Send-AwaitCommand "yes"
                Start-Sleep -Seconds 3
                
                # This will either not prompt at all or prompt for a password
                $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse

                [System.Collections.ArrayList]$CheckExpectedSendYesOutput = @()
                $null = $CheckExpectedSendYesOutput.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                $Counter = 0
                $CompleteIndicatorRegex = if ($ConfigurePSRemoting) {"^pwshConfigComplete|^powershellInstallComplete"} else {"^powershellInstallComplete"}
                while (![bool]$($($CheckExpectedSendYesOutput -split "`n") -match "password.*:") -and 
                ![bool]$($($CheckExpectedSendYesOutput -split "`n") -match $CompleteIndicatorRegex) -and $Counter -le 60
                ) {
                    $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse
                    $null = $CheckExpectedSendYesOutput.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                    Start-Sleep -Seconds 1
                    $Counter++
                }
                if ($Counter -eq 61) {
                    Write-Error "Sending 'yes' to accept the ssh host key timed out!"
                    $global:FunctionResult = "1"
                    
                    if ($PSAwaitProcess.Id) {
                        try {
                            $null = Stop-AwaitSession
                        }
                        catch {
                            if ($PSAwaitProcess.Id -eq $PID) {
                                Write-Error "The PSAwaitSession never spawned! Halting!"
                                $global:FunctionResult = "1"
                                return
                            }
                            else {
                                if ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue)) {
                                    Stop-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue
                                }
                                $Counter = 0
                                while ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue) -and $Counter -le 15) {
                                    Write-Verbose "Waiting for Await Module Process Id $($PSAwaitProcess.Id) to end..."
                                    Start-Sleep -Seconds 1
                                    $Counter++
                                }
                            }
                        }
                    }

                    return
                }

                $CheckSendYesOutput = $CheckExpectedSendYesOutput | foreach {$_ -split "`n"}
                
                if ($CheckSendYesOutput -match "password.*:") {
                    if ($LocalPassword) {
                        $null = Send-AwaitCommand $LocalPassword
                    }
                    if ($DomainPassword) {
                        $null = Send-AwaitCommand $DomainPassword
                    }
                    Start-Sleep -Seconds 3

                    $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse

                    [System.Collections.ArrayList]$script:SSHOutputPrep = @()
                    $null = $SSHOutputPrep.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                    $Counter = 0
                    $CompleteIndicatorRegex = if ($ConfigurePSRemoting) {"^pwshConfigComplete|^powershellInstallComplete"} else {"^powershellInstallComplete"}
                    while (![bool]$($($SSHOutputPrep -split "`n") -match $CompleteIndicatorRegex) -and $Counter -le 6) {
                        $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse
                        if (![System.String]::IsNullOrWhiteSpace($SuccessOrAcceptHostKeyOrPwdPrompt)) {
                            $null = $SSHOutputPrep.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                        }
                        Start-Sleep -Seconds 10
                        $Counter++
                    }
                    if ($Counter -eq 7) {
                        Write-Error "Sending the user's password timed out!"
                        $global:FunctionResult = "1"

                        $SSHOutputPrep

                        if ($PSAwaitProcess.Id) {
                            try {
                                $null = Stop-AwaitSession
                            }
                            catch {
                                if ($PSAwaitProcess.Id -eq $PID) {
                                    Write-Error "The PSAwaitSession never spawned! Halting!"
                                    $global:FunctionResult = "1"
                                    return
                                }
                                else {
                                    if ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue)) {
                                        Stop-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue
                                    }
                                    $Counter = 0
                                    while ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue) -and $Counter -le 15) {
                                        Write-Verbose "Waiting for Await Module Process Id $($PSAwaitProcess.Id) to end..."
                                        Start-Sleep -Seconds 1
                                        $Counter++
                                    }
                                }
                            }
                        }

                        return
                    }
                }
            }
            elseif ($CheckResponsesOutput -match "password.*:") {
                if ($LocalPassword) {
                    $null = Send-AwaitCommand $LocalPassword
                }
                if ($DomainPassword) {
                    $null = Send-AwaitCommand $DomainPassword
                }
                Start-Sleep -Seconds 3

                $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse

                [System.Collections.ArrayList]$script:SSHOutputPrep = @()
                $null = $SSHOutputPrep.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                $Counter = 0
                $CompleteIndicatorRegex = if ($ConfigurePSRemoting) {"^pwshConfigComplete|^powershellInstallComplete"} else {"^powershellInstallComplete"}
                while (![bool]$($($SSHOutputPrep -split "`n") -match $CompleteIndicatorRegex) -and $Counter -le 6) {
                    $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse
                    if (![System.String]::IsNullOrWhiteSpace($SuccessOrAcceptHostKeyOrPwdPrompt)) {
                        $null = $SSHOutputPrep.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                    }
                    Start-Sleep -Seconds 10
                    $Counter++
                }
                if ($Counter -eq 7) {
                    Write-Error "Sending the user's password timed out!"
                    $global:FunctionResult = "1"

                    $SSHOutputPrep

                    if ($PSAwaitProcess.Id) {
                        try {
                            $null = Stop-AwaitSession
                        }
                        catch {
                            if ($PSAwaitProcess.Id -eq $PID) {
                                Write-Error "The PSAwaitSession never spawned! Halting!"
                                $global:FunctionResult = "1"
                                return
                            }
                            else {
                                if ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue)) {
                                    Stop-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue
                                }
                                $Counter = 0
                                while ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue) -and $Counter -le 15) {
                                    Write-Verbose "Waiting for Await Module Process Id $($PSAwaitProcess.Id) to end..."
                                    Start-Sleep -Seconds 1
                                    $Counter++
                                }
                            }
                        }
                    }

                    return
                }
            }
            else {
                $SSHOutputPrep = $($CheckResponsesOutput | Out-String) -split "`n"
            }

            # Give Await session a little more time to finish just in case
            Start-Sleep -Seconds 15

            if ($PSAwaitProcess.Id) {
                try {
                    $null = Stop-AwaitSession
                }
                catch {
                    if ($PSAwaitProcess.Id -eq $PID) {
                        Write-Error "The PSAwaitSession never spawned! Halting!"
                        $global:FunctionResult = "1"
                        return
                    }
                    else {
                        if ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue)) {
                            Stop-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue
                        }
                        $Counter = 0
                        while ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue) -and $Counter -le 15) {
                            Write-Verbose "Waiting for Await Module Process Id $($PSAwaitProcess.Id) to end..."
                            Start-Sleep -Seconds 1
                            $Counter++
                        }
                    }
                }
            }

            # We need to give the Remote Host a little more time to finish installation and configuration...
            if ($SSHOutputPrep) {
                Write-Host "Waiting 5 minutes for install/config to finish..."
                Start-Sleep -Seconds 300
            }

            if (!$SSHOutputPrep) {
                $TentativeResult = "ManualVerificationRequired"
            }
            elseif (![bool]$($SSHOutputPrep -match "powershell")) {
                $TentativeResult = "ReviewAllOutput"
            }
            else {
                $TentativeResult = "Success"
            }

            $FinalOutput = [pscustomobject]@{
                TentativeResult         = $TentativeResult
                AllOutput               = $SSHOutputPrep
                SSHProbeInfo            = $OSCheck
            }
        }

        if ($PSVersionTable.Platform -eq "Unix") {
            $FinalPassword = if ($DomainPassword) {$DomainPassword} else {$LocalPassword}
            #$FinalPassword = $FinalPassword -replace [regex]::Escape('$'),'\\\$' -replace [regex]::Escape('"'),'\\\"'
            $ExpectScripts = $(Get-Variable -Name $OS -ValueOnly).ExpectScripts

            if ($UsePackageManagement) {
                if ($ConfigurePSRemoting) {
                    $SSHScript = $ExpectScripts.ConfigurePwshRemotingScript
                }
                else {
                    $SSHScript = $ExpectScripts.PackageManagerInstallScript
                }
            }
            else {
                if ($ConfigurePSRemoting) {
                    $SSHScript = $ExpectScripts.ConfigurePwshRemotingScript
                }
                else {
                    $SSHScript = $ExpectScripts.ManualInstallScript
                }
            }

            #Write-Host "`$SSHScript is:`n$SSHScript"

            # NOTE: To diagnose expect, add the following at the top of the expect script (right below EOF): exp_internal 1

            $SSHScript = $SSHScript | foreach {
                if ($_ -match "powershellInstallComplete") {
                    'send -- \"' + $_ + '\r\"' + "`n" + 'expect \"*powershellInstallComplete*\"'
                }
                elseif ($_ -match "pwshConfigComplete") {
                    'send -- \"' + $_ + '\r\"' + "`n" + 'expect \"*pwshConfigComplete*\"'
                }
                else {
                    'send -- \"' + $_ + '\r\"' + "`n" + 'expect -re \"$prompt\"'
                }
            }

            $ExpectScriptPrep = @(
                'expect - << EOF'
                'set timeout 120'
                "set password $FinalPassword"
                'set prompt \"(>|:|#|\\\\\\$)\\\\s+\\$\"'
                "spawn $($SSHCmdStringArray -join " ")"
                'match_max 100000'
                'expect {'
                '    \"*(yes/no)?*\" {'
                '        send -- \"yes\r\"'
                '        exp_continue'
                '    }'
                '    -re \".*assword.*:\" {'
                '        send -- \"\$password\r\"'
                '        exp_continue'
                '    }'
                '    -re \"\$prompt\" {'
                '        send -- \"echo LoggedIn\r\"'
                '        expect \"*\"'
                '    }'
                '}'
                $SSHScript
                'send -- \"exit\r\"'
                'expect eof'
                'EOF'
            )
            $ExpectScript = $ExpectScriptPrep -join "`n"

            #Write-Host "`$ExpectScript is:`n$ExpectScript"
            #$ExpectScript | Export-CliXml "$HOME/ExpectScript1.xml"
            
            # The below $ExpectOutput is an array of strings
            $ExpectOutput = bash -c "$ExpectScript"

            # NOTE: The below -replace regex string removes garbage escape sequences like: [116;1H
            $SSHOutputPrep = $ExpectOutput -replace "\e\[(\d+;)*(\d+)?[ABCDHJKfmsu]",""

            # We need to give the Remote Host a little more time to finish installation and configuration...
            if ($SSHOutputPrep -match "powershell -NoProfile -EncodedCommand") {
                Write-Host "Waiting 5 mintutes for install/config to finish..."
                Start-Sleep -Seconds 300
            }

            if (!$SSHOutputPrep) {
                $TentativeResult = "ManualVerificationRequired"
            }
            elseif (![bool]$($SSHOutputPrep -match "powershell")) {
                $TentativeResult = "ReviewAllOutput"
            }
            else {
                $TentativeResult = "Success"
            }

            $FinalOutput = [pscustomobject]@{
                TentativeResult         = $TentativeResult
                AllOutput               = $SSHOutputPrep
                SSHProbeInfo            = $OSCheck
            }
        }
    }
    if ($OSCheck.OS -eq "Linux" -or $OSCheck.OS -eq "MacOS") {
        if (!$PSVersionTable.Platform -or $PSVersionTable.Platform -eq "Win32NT") {
            $BootstrapSB = {
                if ($OS -ne "MacOS") {
                    if ($UsePackageManagement) {
                        if ($ConfigurePSRemoting) {
                            $SSHCmdString = $($SSHCmdStringArray -join " ") + ' "' +
                            $($args[0].PackageManagerInstallScript.Substring(0,$($args[0].PackageManagerInstallScript.Length-3)) -replace [regex]::Escape('\"'),'\`"' -replace [regex]::Escape('$'),'\`$') + '; ' +
                            $($args[0].ConfigurePwshRemotingScriptWindowsToLinux -replace [regex]::Escape('sudo bash -c \`"'),'') + '"'
                        }
                        else {
                            $SSHCmdString = $($SSHCmdStringArray -join " ") + ' "' + $($args[0].PackageManagerInstallScript -replace [regex]::Escape('\"'),'\`"' -replace [regex]::Escape('$'),'\`$') + '"'
                        }
                    }
                    else {
                        if ($ConfigurePSRemoting) {
                            $SSHCmdString = $($SSHCmdStringArray -join " ") + ' "' +
                            $($args[0].ManualInstallScript.Substring(0,$($args[0].ManualInstallScript.Length-3)) -replace [regex]::Escape('\"'),'\`"' -replace [regex]::Escape('$'),'\`$') + '; ' +
                            $($args[0].ConfigurePwshRemotingScriptWindowsToLinux -replace [regex]::Escape('sudo bash -c \`"'),'') + '"'
                        }
                        else {
                            $SSHCmdString = $($SSHCmdStringArray -join " ") + ' "' + $($args[0].ManualInstallScript -replace [regex]::Escape('\"'),'\`"' -replace [regex]::Escape('$'),'\`$') + '"'
                        }
                    }
                }
                else {
                    if ($UsePackageManagement) {
                        if ($ConfigurePSRemoting) {
                            $SSHCmdString = $($SSHCmdStringArray -join " ") + ' "' +
                            $args[0].PackageManagerInstallScriptWindowsToLinux + '; ' +
                            $args[0].ConfigurePwshRemotingScriptWindowsToLinux + '"'
                        }
                        else {
                            $SSHCmdString = $($SSHCmdStringArray -join " ") + ' "' + $args[0].PackageManagerInstallScriptWindowsToLinux + '"'
                        }
                    }
                    else {
                        if ($ConfigurePSRemoting) {
                            $SSHCmdString = $($SSHCmdStringArray -join " ") + ' "' +
                            $args[0].ManualInstallScriptWindowsToLinux + '; ' +
                            $args[0].ConfigurePwshRemotingScriptWindowsToLinux + '"'
                        }
                        else {
                            $SSHCmdString = $($SSHCmdStringArray -join " ") + ' "' + $args[0].ManualInstallScriptWindowsToLinux + '"'
                        }
                    }
                }
            
                $SSHCmdString
            }
            
            $SSHCmdString = Invoke-Command -ScriptBlock $BootstrapSB -ArgumentList $(Get-Variable -Name $OS -ValueOnly)
            
            #Write-Host "`$SSHCmdString is:`n    $SSHCmdString"

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

            $PSAwaitProcess = $null
            $null = Start-AwaitSession
            Start-Sleep -Seconds 1
            $null = Send-AwaitCommand '$host.ui.RawUI.WindowTitle = "PSAwaitSession"'
            $PSAwaitProcess = $($(Get-Process | Where-Object {$_.Name -eq "powershell"}) | Sort-Object -Property StartTime -Descending)[0]
            Start-Sleep -Seconds 1
            $null = Send-AwaitCommand "`$env:Path = '$env:Path'"
            Start-Sleep -Seconds 1
            $null = Send-AwaitCommand -Command $([scriptblock]::Create($SSHCmdString))
            Start-Sleep -Seconds 5

            # This will either not prompt at all, prompt to accept the RemoteHost's RSA Host Key, or prompt for a password
            $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse

            [System.Collections.ArrayList]$CheckForExpectedResponses = @()
            $null = $CheckForExpectedResponses.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
            $Counter = 0
            $CompleteIndicatorRegex = if ($ConfigurePSRemoting) {"^pwshConfigComplete|^powershellInstallComplete"} else {"^powershellInstallComplete"}
            while (![bool]$($($CheckForExpectedResponses -split "`n") -match [regex]::Escape("Are you sure you want to continue connecting (yes/no)?")) -and
            ![bool]$($($CheckForExpectedResponses -split "`n") -match "password.*:") -and 
            ![bool]$($($CheckForExpectedResponses -split "`n") -match $CompleteIndicatorRegex) -and $Counter -le 60
            ) {
                $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse
                $null = $CheckForExpectedResponses.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                if ($CheckResponsesOutput -match "must be greater than zero" -or @($CheckResponsesOutput)[-1] -notmatch "[a-zA-Z]") {
                    break
                }
                Start-Sleep -Seconds 1
                $Counter++
            }
            if ($Counter -eq 61) {
                Write-Verbose "SSH via '$($SSHCmdStringArray -join " ")' timed out!"

                if ($PSAwaitProcess.Id) {
                    try {
                        $null = Stop-AwaitSession
                    }
                    catch {
                        if ($PSAwaitProcess.Id -eq $PID) {
                            Write-Error "The PSAwaitSession never spawned! Halting!"
                            $global:FunctionResult = "1"
                            return
                        }
                        else {
                            if ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue)) {
                                Stop-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue
                            }
                            $Counter = 0
                            while ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue) -and $Counter -le 15) {
                                Write-Verbose "Waiting for Await Module Process Id $($PSAwaitProcess.Id) to end..."
                                Start-Sleep -Seconds 1
                                $Counter++
                            }
                        }
                    }
                }
            }
            #endregion >> Await Attempt 1 of 2

            $CheckResponsesOutput = $CheckForExpectedResponses | foreach {$_ -split "`n"}
            
            #region >> Await Attempt 2 of 2
            
            # If $CheckResponsesOutput contains the string "must be greater than zero", then something broke with the Await Module.
            # Most of the time, just trying again resolves any issues
            if ($CheckResponsesOutput -match "must be greater than zero" -or @($CheckResponsesOutput)[-1] -notmatch "[a-zA-Z]" -and
            ![bool]$($CheckResponsesOutput -match "background process reported an error")) {
                if ($PSAwaitProcess.Id) {
                    try {
                        $null = Stop-AwaitSession
                    }
                    catch {
                        if ($PSAwaitProcess.Id -eq $PID) {
                            Write-Error "The PSAwaitSession never spawned! Halting!"
                            $global:FunctionResult = "1"
                            return
                        }
                        else {
                            if ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue)) {
                                Stop-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue
                            }
                            $Counter = 0
                            while ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue) -and $Counter -le 15) {
                                Write-Verbose "Waiting for Await Module Process Id $($PSAwaitProcess.Id) to end..."
                                Start-Sleep -Seconds 1
                                $Counter++
                            }
                        }
                    }
                }

                $PSAwaitProcess = $null
                $null = Start-AwaitSession
                Start-Sleep -Seconds 1
                $null = Send-AwaitCommand '$host.ui.RawUI.WindowTitle = "PSAwaitSession"'
                $PSAwaitProcess = $($(Get-Process | Where-Object {$_.Name -eq "powershell"}) | Sort-Object -Property StartTime -Descending)[0]
                Start-Sleep -Seconds 1
                $null = Send-AwaitCommand "`$env:Path = '$env:Path'"
                Start-Sleep -Seconds 1
                $null = Send-AwaitCommand -Command $([scriptblock]::Create($SSHCmdString))
                Start-Sleep -Seconds 5

                # This will either not prompt at all, prompt to accept the RemoteHost's RSA Host Key, or prompt for a password
                $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse

                [System.Collections.ArrayList]$CheckForExpectedResponses = @()
                $null = $CheckForExpectedResponses.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                $Counter = 0
                $CompleteIndicatorRegex = if ($ConfigurePSRemoting) {"^pwshConfigComplete|^powershellInstallComplete"} else {"^powershellInstallComplete"}
                while (![bool]$($SuccessOrAcceptHostKeyOrPwdPrompt -match [regex]::Escape("Are you sure you want to continue connecting (yes/no)?")) -and
                ![bool]$($SuccessOrAcceptHostKeyOrPwdPrompt -match "password.*:") -and 
                ![bool]$($SuccessOrAcceptHostKeyOrPwdPrompt -match $CompleteIndicatorRegex) -and $Counter -le 60
                ) {
                    $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse
                    $null = $CheckForExpectedResponses.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                    Start-Sleep -Seconds 1
                    $Counter++
                }
                if ($Counter -eq 61) {
                    Write-Error "SSH via '$($SSHCmdStringArray -join " ")' timed out!"
                    $global:FunctionResult = "1"

                    #$CheckForExpectedResponses

                    if ($PSAwaitProcess.Id) {
                        try {
                            $null = Stop-AwaitSession
                        }
                        catch {
                            if ($PSAwaitProcess.Id -eq $PID) {
                                Write-Error "The PSAwaitSession never spawned! Halting!"
                                $global:FunctionResult = "1"
                                return
                            }
                            else {
                                if ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue)) {
                                    Stop-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue
                                }
                                $Counter = 0
                                while ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue) -and $Counter -le 15) {
                                    Write-Verbose "Waiting for Await Module Process Id $($PSAwaitProcess.Id) to end..."
                                    Start-Sleep -Seconds 1
                                    $Counter++
                                }
                            }
                        }
                    }

                    return
                }
            }

            #endregion >> Await Attempt 2 of 2

            $CheckResponsesOutput = $CheckForExpectedResponses | foreach {$_ -split "`n"}

            # At this point, if we don't have the expected output, we need to fail
            if ($CheckResponsesOutput -match "must be greater than zero" -or @($CheckResponsesOutput)[-1] -notmatch "[a-zA-Z]" -and
            ![bool]$($CheckResponsesOutput -match "background process reported an error")) {
                Write-Error "Something went wrong with the PowerShell Await Module! Halting!"
                $global:FunctionResult = "1"

                if ($PSAwaitProcess.Id) {
                    try {
                        $null = Stop-AwaitSession
                    }
                    catch {
                        if ($PSAwaitProcess.Id -eq $PID) {
                            Write-Error "The PSAwaitSession never spawned! Halting!"
                            $global:FunctionResult = "1"
                            return
                        }
                        else {
                            if ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue)) {
                                Stop-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue
                            }
                            $Counter = 0
                            while ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue) -and $Counter -le 15) {
                                Write-Verbose "Waiting for Await Module Process Id $($PSAwaitProcess.Id) to end..."
                                Start-Sleep -Seconds 1
                                $Counter++
                            }
                        }
                    }
                }

                return
            }

            # Now we should either have a prompt to accept the host key, a prompt for a password, or it already worked...

            if ($CheckResponsesOutput -match [regex]::Escape("Are you sure you want to continue connecting (yes/no)?")) {
                $null = Send-AwaitCommand "yes"
                Start-Sleep -Seconds 3
                
                # This will either not prompt at all or prompt for a password
                $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse

                [System.Collections.ArrayList]$CheckExpectedSendYesOutput = @()
                $null = $CheckExpectedSendYesOutput.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                $Counter = 0
                $CompleteIndicatorRegex = if ($ConfigurePSRemoting) {"^pwshConfigComplete|^powershellInstallComplete"} else {"^powershellInstallComplete"}
                while (![bool]$($($CheckExpectedSendYesOutput -split "`n") -match "password.*:") -and 
                ![bool]$($($CheckExpectedSendYesOutput -split "`n") -match $CompleteIndicatorRegex) -and $Counter -le 60
                ) {
                    $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse
                    $null = $CheckExpectedSendYesOutput.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                    Start-Sleep -Seconds 1
                    $Counter++
                }
                if ($Counter -eq 61) {
                    Write-Error "Sending 'yes' to accept the ssh host key timed out!"
                    $global:FunctionResult = "1"
                    
                    if ($PSAwaitProcess.Id) {
                        try {
                            $null = Stop-AwaitSession
                        }
                        catch {
                            if ($PSAwaitProcess.Id -eq $PID) {
                                Write-Error "The PSAwaitSession never spawned! Halting!"
                                $global:FunctionResult = "1"
                                return
                            }
                            else {
                                if ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue)) {
                                    Stop-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue
                                }
                                $Counter = 0
                                while ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue) -and $Counter -le 15) {
                                    Write-Verbose "Waiting for Await Module Process Id $($PSAwaitProcess.Id) to end..."
                                    Start-Sleep -Seconds 1
                                    $Counter++
                                }
                            }
                        }
                    }

                    return
                }

                $CheckSendYesOutput = $CheckExpectedSendYesOutput | foreach {$_ -split "`n"}
                
                if ($CheckSendYesOutput -match "password.*:") {
                    if ($LocalPassword) {
                        $null = Send-AwaitCommand $LocalPassword
                    }
                    if ($DomainPassword) {
                        $null = Send-AwaitCommand $DomainPassword
                    }
                    Start-Sleep -Seconds 3

                    $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse

                    # Now we may or may not receive a password prompt for sudo...
                    if ($SuccessOrAcceptHostKeyOrPwdPrompt -match "password.*:") {
                        if ($LocalPassword) {
                            $null = Send-AwaitCommand $LocalPassword
                        }
                        if ($DomainPassword) {
                            $null = Send-AwaitCommand $DomainPassword
                        }
                        Start-Sleep -Seconds 3

                        $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse
                    }

                    # If $OS is MacOS, we need to wait for another password prompt because 'brew cask reinstall powershell' WILL prompt for 'Password:'
                    # Sometimes, the preceding step of installing openssl (dependency) can take up to 10 minutes, so we need to sit here for awhile
                    if ($OS -eq "MacOS") {
                        Write-Warning "Attempting install on MacOS! This could take up to 15 minutes! Please be patient..."
                        [System.Collections.ArrayList]$script:SSHOutputPrep = @()
                        $null = $SSHOutputPrep.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                        $Counter = 0
                        while (![bool]$($($SSHOutputPrep -split "`n") -match "password.*:") -and $Counter -le 90) {
                            $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse
                            if (![System.String]::IsNullOrWhiteSpace($SuccessOrAcceptHostKeyOrPwdPrompt)) {
                                $null = $SSHOutputPrep.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                            }
                            Start-Sleep -Seconds 10
                            $Counter++
                        }
                        if ($Counter -eq 91) {
                            Write-Error "Sending the user's password (MacOS) timed out!"
                            $global:FunctionResult = "1"
    
                            $SSHOutputPrep
    
                            if ($PSAwaitProcess.Id) {
                                try {
                                    $null = Stop-AwaitSession
                                }
                                catch {
                                    if ($PSAwaitProcess.Id -eq $PID) {
                                        Write-Error "The PSAwaitSession never spawned! Halting!"
                                        $global:FunctionResult = "1"
                                        return
                                    }
                                    else {
                                        if ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue)) {
                                            Stop-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue
                                        }
                                        $Counter = 0
                                        while ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue) -and $Counter -le 15) {
                                            Write-Verbose "Waiting for Await Module Process Id $($PSAwaitProcess.Id) to end..."
                                            Start-Sleep -Seconds 1
                                            $Counter++
                                        }
                                    }
                                }
                            }
    
                            return
                        }
    
                        if ($LocalPassword) {
                            $null = Send-AwaitCommand $LocalPassword
                        }
                        if ($DomainPassword) {
                            $null = Send-AwaitCommand $DomainPassword
                        }
                        Start-Sleep -Seconds 3
    
                        $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse
    
                        # If we're also configuring /etc/ssh/sshd_config on MacOS, we can expect another Password prompt for 'sudo', but we may not
                        # actually receive a prompt if the user doesn't require a sudo password, so we shouldn't outright fail here
                        if ($ConfigurePSRemoting) {
                            $Counter = 0
                            while (![bool]$($($SSHOutputPrep -split "`n") -match "password.*:") -and $Counter -le 15) {
                                $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse
                                if (![System.String]::IsNullOrWhiteSpace($SuccessOrAcceptHostKeyOrPwdPrompt)) {
                                    $null = $SSHOutputPrep.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                                }
                                Start-Sleep -Seconds 2
                                $Counter++
                            }
                            if ($Counter -eq 16) {
                                Write-Warning "Sending the user's password (MacOS PSRemoting) timed out!"
                                $DontSendPassword = $True
    
                                if ($PSAwaitProcess.Id) {
                                    try {
                                        $null = Stop-AwaitSession
                                    }
                                    catch {
                                        if ($PSAwaitProcess.Id -eq $PID) {
                                            Write-Error "The PSAwaitSession never spawned! Halting!"
                                            $global:FunctionResult = "1"
                                            return
                                        }
                                        else {
                                            if ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue)) {
                                                Stop-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue
                                            }
                                            $Counter = 0
                                            while ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue) -and $Counter -le 15) {
                                                Write-Verbose "Waiting for Await Module Process Id $($PSAwaitProcess.Id) to end..."
                                                Start-Sleep -Seconds 1
                                                $Counter++
                                            }
                                        }
                                    }
                                }
                            }
    
                            if (!$DontSendPassword) {
                                if ($LocalPassword) {
                                    $null = Send-AwaitCommand $LocalPassword
                                }
                                if ($DomainPassword) {
                                    $null = Send-AwaitCommand $DomainPassword
                                }
                                Start-Sleep -Seconds 3
            
                                $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse
                                $null = $SSHOutputPrep.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                            }
                        }
                    }

                    if (!$SSHOutputPrep) {
                        [System.Collections.ArrayList]$script:SSHOutputPrep = @()
                        $null = $SSHOutputPrep.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                    }
                    $Counter = 0
                    $CompleteIndicatorRegex = if ($ConfigurePSRemoting) {"^pwshConfigComplete|^powershellInstallComplete"} else {"^powershellInstallComplete"}
                    while (![bool]$($($SSHOutputPrep -split "`n") -match $CompleteIndicatorRegex) -and $Counter -le 6) {
                        $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse
                        if (![System.String]::IsNullOrWhiteSpace($SuccessOrAcceptHostKeyOrPwdPrompt)) {
                            $null = $SSHOutputPrep.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                        }
                        Start-Sleep -Seconds 10
                        $Counter++
                    }
                    if ($Counter -eq 7) {
                        Write-Error "Sending the user's password timed out!"
                        $global:FunctionResult = "1"

                        $SSHOutputPrep

                        if ($PSAwaitProcess.Id) {
                            try {
                                $null = Stop-AwaitSession
                            }
                            catch {
                                if ($PSAwaitProcess.Id -eq $PID) {
                                    Write-Error "The PSAwaitSession never spawned! Halting!"
                                    $global:FunctionResult = "1"
                                    return
                                }
                                else {
                                    if ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue)) {
                                        Stop-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue
                                    }
                                    $Counter = 0
                                    while ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue) -and $Counter -le 15) {
                                        Write-Verbose "Waiting for Await Module Process Id $($PSAwaitProcess.Id) to end..."
                                        Start-Sleep -Seconds 1
                                        $Counter++
                                    }
                                }
                            }
                        }

                        return
                    }
                }
            }
            elseif ($CheckResponsesOutput -match "password.*:") {
                if ($LocalPassword) {
                    $null = Send-AwaitCommand $LocalPassword
                }
                if ($DomainPassword) {
                    $null = Send-AwaitCommand $DomainPassword
                }
                Start-Sleep -Seconds 3

                $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse

                # Now we may or may not receive a password prompt for sudo...
                if ($SuccessOrAcceptHostKeyOrPwdPrompt -match "password.*:") {
                    if ($LocalPassword) {
                        $null = Send-AwaitCommand $LocalPassword
                    }
                    if ($DomainPassword) {
                        $null = Send-AwaitCommand $DomainPassword
                    }
                    Start-Sleep -Seconds 3

                    $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse
                }

                # If $OS is MacOS, we need to wait for another password prompt because 'brew cask reinstall powershell' WILL prompt for 'Password:'
                # Sometimes, the preceding step of installing openssl (dependency) can take up to 10 minutes, so we need to sit here for awhile
                if ($OS -eq "MacOS") {
                    Write-Warning "Attempting install on MacOS! This could take up to 15 minutes! Please be patient..."
                    [System.Collections.ArrayList]$script:SSHOutputPrep = @()
                    $null = $SSHOutputPrep.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                    $Counter = 0
                    while (![bool]$($($SSHOutputPrep -split "`n") -match "password.*:") -and $Counter -le 90) {
                        $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse
                        if (![System.String]::IsNullOrWhiteSpace($SuccessOrAcceptHostKeyOrPwdPrompt)) {
                            $null = $SSHOutputPrep.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                        }
                        Start-Sleep -Seconds 10
                        $Counter++
                    }
                    if ($Counter -eq 91) {
                        Write-Error "Sending the user's password (MacOS) timed out!"
                        $global:FunctionResult = "1"

                        $SSHOutputPrep

                        if ($PSAwaitProcess.Id) {
                            try {
                                $null = Stop-AwaitSession
                            }
                            catch {
                                if ($PSAwaitProcess.Id -eq $PID) {
                                    Write-Error "The PSAwaitSession never spawned! Halting!"
                                    $global:FunctionResult = "1"
                                    return
                                }
                                else {
                                    if ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue)) {
                                        Stop-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue
                                    }
                                    $Counter = 0
                                    while ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue) -and $Counter -le 15) {
                                        Write-Verbose "Waiting for Await Module Process Id $($PSAwaitProcess.Id) to end..."
                                        Start-Sleep -Seconds 1
                                        $Counter++
                                    }
                                }
                            }
                        }

                        return
                    }

                    if ($LocalPassword) {
                        $null = Send-AwaitCommand $LocalPassword
                    }
                    if ($DomainPassword) {
                        $null = Send-AwaitCommand $DomainPassword
                    }
                    Start-Sleep -Seconds 3

                    $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse

                    # If we're also configuring /etc/ssh/sshd_config on MacOS, we can expect another Password prompt for 'sudo', but we may not
                    # actually receive a prompt if the user doesn't require a sudo password, so we shouldn't outright fail here
                    if ($ConfigurePSRemoting) {
                        $Counter = 0
                        while (![bool]$($($SSHOutputPrep -split "`n") -match "password.*:") -and $Counter -le 15) {
                            $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse
                            if (![System.String]::IsNullOrWhiteSpace($SuccessOrAcceptHostKeyOrPwdPrompt)) {
                                $null = $SSHOutputPrep.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                            }
                            Start-Sleep -Seconds 2
                            $Counter++
                        }
                        if ($Counter -eq 16) {
                            Write-Warning "Sending the user's password (MacOS PSRemoting) timed out!"
                            $DontSendPassword = $True

                            if ($PSAwaitProcess.Id) {
                                try {
                                    $null = Stop-AwaitSession
                                }
                                catch {
                                    if ($PSAwaitProcess.Id -eq $PID) {
                                        Write-Error "The PSAwaitSession never spawned! Halting!"
                                        $global:FunctionResult = "1"
                                        return
                                    }
                                    else {
                                        if ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue)) {
                                            Stop-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue
                                        }
                                        $Counter = 0
                                        while ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue) -and $Counter -le 15) {
                                            Write-Verbose "Waiting for Await Module Process Id $($PSAwaitProcess.Id) to end..."
                                            Start-Sleep -Seconds 1
                                            $Counter++
                                        }
                                    }
                                }
                            }
                        }

                        if (!$DontSendPassword) {
                            if ($LocalPassword) {
                                $null = Send-AwaitCommand $LocalPassword
                            }
                            if ($DomainPassword) {
                                $null = Send-AwaitCommand $DomainPassword
                            }
                            Start-Sleep -Seconds 3
        
                            $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse
                            $null = $SSHOutputPrep.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                        }
                    }
                }

                if (!$SSHOutputPrep) {
                    [System.Collections.ArrayList]$script:SSHOutputPrep = @()
                    $null = $SSHOutputPrep.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                }
                $Counter = 0
                $CompleteIndicatorRegex = if ($ConfigurePSRemoting) {"^pwshConfigComplete|^powershellInstallComplete"} else {"^powershellInstallComplete"}
                while (![bool]$($($SSHOutputPrep -split "`n") -match $CompleteIndicatorRegex) -and $Counter -le 6) {
                    $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse
                    if (![System.String]::IsNullOrWhiteSpace($SuccessOrAcceptHostKeyOrPwdPrompt)) {
                        $null = $SSHOutputPrep.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                    }
                    Start-Sleep -Seconds 10
                    $Counter++
                }
                if ($Counter -eq 7) {
                    Write-Error "Sending the user's password timed out!"
                    $global:FunctionResult = "1"

                    $SSHOutputPrep

                    if ($PSAwaitProcess.Id) {
                        try {
                            $null = Stop-AwaitSession
                        }
                        catch {
                            if ($PSAwaitProcess.Id -eq $PID) {
                                Write-Error "The PSAwaitSession never spawned! Halting!"
                                $global:FunctionResult = "1"
                                return
                            }
                            else {
                                if ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue)) {
                                    Stop-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue
                                }
                                $Counter = 0
                                while ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue) -and $Counter -le 15) {
                                    Write-Verbose "Waiting for Await Module Process Id $($PSAwaitProcess.Id) to end..."
                                    Start-Sleep -Seconds 1
                                    $Counter++
                                }
                            }
                        }
                    }

                    return
                }
            }
            else {
                $SSHOutputPrep = $($CheckResponsesOutput | Out-String) -split "`n"
            }

            # Give Await session a little more time to finish just in case
            Start-Sleep -Seconds 15

            if ($PSAwaitProcess.Id) {
                try {
                    $null = Stop-AwaitSession
                }
                catch {
                    if ($PSAwaitProcess.Id -eq $PID) {
                        Write-Error "The PSAwaitSession never spawned! Halting!"
                        $global:FunctionResult = "1"
                        return
                    }
                    else {
                        if ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue)) {
                            Stop-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue
                        }
                        $Counter = 0
                        while ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue) -and $Counter -le 15) {
                            Write-Verbose "Waiting for Await Module Process Id $($PSAwaitProcess.Id) to end..."
                            Start-Sleep -Seconds 1
                            $Counter++
                        }
                    }
                }
            }

            if (!$SSHOutputPrep) {
                $TentativeResult = "ManualVerificationRequired"
            }
            elseif (![bool]$($SSHOutputPrep -match "powershell")) {
                $TentativeResult = "ReviewAllOutput"
            }
            else {
                $TentativeResult = "Success"
            }

            $FinalOutput = [pscustomobject]@{
                TentativeResult         = $TentativeResult
                AllOutput               = $SSHOutputPrep
                SSHProbeInfo            = $OSCheck
            }
        }

        if ($PSVersionTable.Platform -eq "Unix") {
            $FinalPassword = if ($DomainPassword) {$DomainPassword} else {$LocalPassword}
            #$FinalPassword = $FinalPassword -replace [regex]::Escape('$'),'\\\$' -replace [regex]::Escape('"'),'\\\"'
            $ExpectScripts = $(Get-Variable -Name $OS -ValueOnly).ExpectScripts

            if ($UsePackageManagement) {
                if ($ConfigurePSRemoting) {
                    $SSHScript = $ExpectScripts.PackageManagerInstallScript + $ExpectScripts.ConfigurePwshRemotingScript
                }
                else {
                    $SSHScript = $ExpectScripts.PackageManagerInstallScript
                }
            }
            else {
                if ($ConfigurePSRemoting) {
                    $SSHScript = $ExpectScripts.ManualInstallScript + $ExpectScripts.ConfigurePwshRemotingScript
                }
                else {
                    $SSHScript = $ExpectScripts.ManualInstallScript
                }
            }

            $SSHScript = $SSHScript | foreach {
                if ($_ -match "powershellInstallComplete") {
                    'send -- \"' + $_ + '\r\"' + "`n" + 'expect \"*powershellInstallComplete*\"'
                }
                elseif ($_ -match "pwshConfigComplete") {
                    'send -- \"' + $_ + '\r\"' + "`n" + 'expect \"*pwshConfigComplete*\"'
                }
                else {
                    'send -- \"' + $_ + '\r\"' + "`n" + 'expect -re \"$prompt\"'
                }
            }

            #Write-Host "`$SSHScript is:`n$SSHScript"

            $ExpectScriptPrep = @(
                'expect - << EOF'
                'set timeout 120'
                "set password $FinalPassword"
                'set prompt \"(>|:|#|\\\\\\$)\\\\s+\\$\"'
                "spawn $($SSHCmdStringArray -join " ")"
                'match_max 100000'
                'expect {'
                '    \"*(yes/no)?*\" {'
                '        send -- \"yes\r\"'
                '        exp_continue'
                '    }'
                '    -re \".*assword.*:\" {'
                '        send -- \"\$password\r\"'
                '        exp_continue'
                '    }'
                '    -re \"\$prompt\" {'
                '        send -- \"echo LoggedIn\r\"'
                '        expect \"*\"'
                '    }'
                '}'
                'send -- \"sudo su\r\"'
                'expect {'
                '    -re \".*assword.*:\" {'
                '        send -- \"\$password\r\"'
                '        exp_continue'
                '    }'
                '    -re \"\$prompt\" {'
                '        send -- \"echo StartInstall\r\"'
                '        expect \"StartInstall\"'
                '    }'
                '}'
                $SSHScript
                'send -- \"exit\r\"'
                'expect -re \"\$prompt\"'
                'send -- \"exit\r\"'
                'expect eof'
                'EOF'
            )
            $ExpectScript = $ExpectScriptPrep -join "`n"

            #Write-Host "`$ExpectScript is:`n$ExpectScript"
            #$ExpectScript | Export-CliXml "$HOME/ExpectScript2.xml"
            
            # The below $ExpectOutput is an array of strings
            $ExpectOutput = bash -c "$ExpectScript"

            # NOTE: The below -replace regex string removes garbage escape sequences like: [116;1H
            $SSHOutputPrep = $ExpectOutput -replace "\e\[(\d+;)*(\d+)?[ABCDHJKfmsu]",""

            if (!$SSHOutputPrep) {
                $TentativeResult = "ManualVerificationRequired"
            }
            elseif (![bool]$($SSHOutputPrep -match "powershell")) {
                $TentativeResult = "ReviewAllOutput"
            }
            else {
                $TentativeResult = "Success"
            }

            $FinalOutput = [pscustomobject]@{
                TentativeResult         = $TentativeResult
                AllOutput               = $SSHOutputPrep
                SSHProbeInfo            = $OSCheck
            }
        }
    }

    $FinalOutput
    
    #endregion >> Main Body
}

# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUdYNGFGyJee5gmORThOInHyTY
# Pdagggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFKK/48QwjERMUjAS
# +fcsvN2ImLn3MA0GCSqGSIb3DQEBAQUABIIBABKqsENu0NwJhSXaDIp0Z7h6i4a2
# XQQg0qk0xODxV2SdAiYcF/XZISTgMpQCK8EhVXqipHsZ2Xg+fOcdXVGFXYD75nUQ
# PLHNGONg49gKr17ax0/RpzboiEf0ggt9TWpb3xk+e3mNVgAmFOVU9gVGVn6BDrj1
# SKeRBcSIESoj8i4dYmqVwBcq/QytHR1INBESaQp6pdkvZbFYwYRjiPqHevoDPoRH
# RwpvjDqw8/Fk9DDFTIheLyxKQr4DwSmFDKb6yZ/k022vHcWpLfgpgRMjlSESPsek
# cIRtKvktzfNkIWM3odMgChngUHaMw2GNs9veNuZ9UUG7PMkoYWR3nr5VAL8=
# SIG # End signature block
