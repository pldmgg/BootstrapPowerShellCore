[Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"

# Get public and private function definition files.
[array]$Public  = Get-ChildItem -Path "$PSScriptRoot\Public\*.ps1" -ErrorAction SilentlyContinue
[array]$Private = Get-ChildItem -Path "$PSScriptRoot\Private\*.ps1" -ErrorAction SilentlyContinue
$ThisModule = $(Get-Item $PSCommandPath).BaseName

# Dot source the Private functions
foreach ($import in $Private) {
    try {
        . $import.FullName
    }
    catch {
        Write-Error -Message "Failed to import function $($import.FullName): $_"
    }
}

[System.Collections.Arraylist]$ModulesToInstallAndImport = @()
if (Test-Path "$PSScriptRoot\module.requirements.psd1") {
    $ModuleManifestData = Import-PowerShellDataFile "$PSScriptRoot\module.requirements.psd1"
    #$ModuleManifestData.Keys | Where-Object {$_ -ne "PSDependOptions"} | foreach {$null = $ModulesToinstallAndImport.Add($_)}
    $($ModuleManifestData.GetEnumerator()) | foreach {
        if ($_.Key -ne "PSDependOptions") {
            $PSObj = [pscustomobject]@{
                Name    = $_.Key
                Version = $_.Value.Version
            }
            $null = $ModulesToinstallAndImport.Add($PSObj)
        }
    }
}

if ($ModulesToInstallAndImport.Count -gt 0) {
    foreach ($ModuleItem in $ModulesToInstallAndImport) {
        if (!$(Get-Module -ListAvailable $ModuleItem.Name -ErrorAction SilentlyContinue)) {Install-Module $ModuleItem.Name}
        if (!$(Get-Module $ModuleItem.Name -ErrorAction SilentlyContinue)) {Import-Module $ModuleItem.Name}
    }
}

<#
[System.Collections.Arraylist]$ModulesToInstallAndImport = @()
if (Test-Path "$PSScriptRoot\module.requirements.psd1") {
    $ModuleManifestData = Import-PowerShellDataFile "$PSScriptRoot\module.requirements.psd1"
    #$ModuleManifestData.Keys | Where-Object {$_ -ne "PSDependOptions"} | foreach {$null = $ModulesToinstallAndImport.Add($_)}
    $($ModuleManifestData.GetEnumerator()) | foreach {
        $PSObj = [pscustomobject]@{
            Name    = $_.Key
            Version = $_.Value.Version
        }
        $null = $ModulesToinstallAndImport.Add($PSObj)
    }
}

if ($ModulesToInstallAndImport.Count -gt 0) {
    # NOTE: If you're not sure if the Required Module is Locally Available or Externally Available,
    # add it the the -RequiredModules string array just to be certain
    $InvModDepSplatParams = @{
        RequiredModules                     = $ModulesToInstallAndImport
        InstallModulesNotAvailableLocally   = $True
        ErrorAction                         = "SilentlyContinue"
        WarningAction                       = "SilentlyContinue"
    }
    $ModuleDependenciesMap = InvokeModuleDependencies @InvModDepSplatParams
}
#>

# Public Functions


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
            "Ubuntu1404","Ubuntu1604","Ubuntu1804","Ubuntu1810","Debian8","Debain9","CentOS7","RHEL7","OpenSUSE423","Fedora","Raspbian"

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
            Mandatory=$True,
            ParameterSetName='Local'    
        )]
        [securestring]$LocalPasswordSS,

        [Parameter(
            Mandatory=$True,
            ParameterSetName='Domain'
        )]
        [securestring]$DomainPasswordSS,

        [Parameter(Mandatory=$False)]
        [string]$KeyFilePath,

        [Parameter(Mandatory=$False)]
        [ValidateSet("Windows","Ubuntu1404","Ubuntu1604","Ubuntu1804","Ubuntu1810","Debian8","Debain9","CentOS7","RHEL7","OpenSUSE423","Fedora","Raspbian")]
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
    $ReleaseInfo = Invoke-RestMethod https://api.github.com/repos/PowerShell/PowerShell/releases/latest
    $PSCorePackageUrls = $ReleaseInfo.assets.browser_download_url
    $PSCorePackageNames = $ReleaseInfo.assets.name
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
        '    Install-Program -ProgramName powershell-core -CommandName pwsh.exe'
        '}'
        'catch {'
        '    Write-Error $_'
        "    `$global:FunctionResult = '1'"
        '    return'
        '}'
    )
    $WindowsPMInstallScript = "powershell -NoProfile -Command \`"$($WindowsPMInstallScriptPrep -join '; ')\`""

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
    )
    $WindowsManualInstallScript = "powershell -NoProfile -Command \`"$($WindowsManualInstallScriptPrep -join '; ')\`""

    $WindowsUninstallScript = @(
        'try {'
        '    if ($(Get-Module -ListAvailable).Name -notcontains "ProgramManagement") {$null = Install-Module ProgramManagement -ErrorAction Stop}'
        '    if ($(Get-Module).Name -notcontains "ProgramManagement") {$null = Import-Module ProgramManagement -ErrorAction Stop}'
        '    Install-Program -ProgramName powershell-core -CommandName pwsh.exe'
        '}'
        'catch {'
        '    Write-Error $_'
        '    $global:FunctionResult = "1"'
        '    return'
        '}'
        'try {'
        '    Uninstall-Program -ProgramName powershell-core -ErrorAction Stop'
        '}'
        'catch {'
        '    Write-Error $_'
        '    $global:FunctionResult = "1"'
        '    return'
        '}'
    )

    $WindowsPwshRemotingScript = @(
        'try {'
        "    if (`$(Get-Module -ListAvailable).Name -notcontains 'WinSSH') {`$null = Install-Module WinSSH -ErrorAction Stop}"
        "    if (`$(Get-Module).Name -notcontains 'WinSSH') {`$null = Import-Module WinSSH -ErrorAction Stop}"
        '    Install-WinSSH -GiveWinSSHBinariesPathPriority -ConfigureSSHDOnLocalHost -DefaultShell pwsh'
        '}'
        'catch {'
        '    Write-Error $_'
        "    `$global:FunctionResult = '1'"
        '    return'
        '}'
    )

    $Windows = [pscustomobject]@{
        PackageManagerInstallScript = $WindowsPMInstallScript
        ManualInstallScript         = $WindowsManualInstallScript
        UninstallScript             = $WindowsUninstallScript
        ConfigurePwshRemotingScript = $WindowsPwshRemotingScript
    }
    
    # Ubuntu 14.04 Install Info
    $Ubuntu1404PMInstallScriptPrep = @(
        'wget -q https://packages.microsoft.com/config/ubuntu/14.04/packages-microsoft-prod.deb'
        'dpkg -i packages-microsoft-prod.deb'
        'apt update'
        'apt install -y powershell && echo powershellInstallComplete'
    )
    $Ubuntu1404PMInstallScript = "sudo bash -c \```"$($Ubuntu1404PMInstallScriptPrep -join '; ')\```""

    $Ubuntu1404ManualInstallScriptPrep = @(
        "wget -q $Ubuntu1404PackageUrl"
        "dpkg -i $Ubuntu1404PackageName"
        'apt install -f && echo powershellInstallComplete'
    )
    $Ubuntu1404ManualInstallScript = "sudo bash -c \```"$($Ubuntu1404ManualInstallScriptPrep -join '; ')\```""

    $Ubuntu1404UninstallScript = 'sudo apt remove powershell'

    $Ubuntu1404PwshRemotingScriptPrep = @(
        'pscorepath=$(command -v pwsh)'
        'subsystemline=$(echo \"\"Subsystem powershell $pscorepath -sshs -NoLogo -NoProfile\"\")'
        'sed -i \"\"s|sftp-server|sftp-server\n$subsystemline|\"\" /etc/ssh/sshd_config'
        'systemctl restart sshd'
    )
    $Ubuntu1404PwshRemotingScript = "sudo bash -c \```"$($Ubuntu1404PwshRemotingScriptPrep -join '; ')\```""
    
    # IMPORTANT NOTE: For Expect, we need to triple (i.e. \\\) for $, n, and "
    # We need to single (i.e. \) for [, ]
    # No need to escape |, -, /
    $Ubuntu1404PwshRemotingScriptPrepForExpect = @(
        'pscorepath=\\\$(command -v pwsh)'
        'subsystemline=\\\$(echo \\\"Subsystem powershell \\\$pscorepath -sshs -NoLogo -NoProfile\\\")'
        'sed -i \\\"s|sftp-server|sftp-server\\\n\\\$subsystemline|\\\" /etc/ssh/sshd_config'
        'systemctl restart sshd'
    )

    $Ubuntu1404 = [pscustomobject]@{
        PackageManagerInstallScript = $Ubuntu1404PMInstallScript
        ManualInstallScript         = $Ubuntu1404ManualInstallScript
        UninstallScript             = $Ubuntu1404UninstallScript
        ConfigurePwshRemotingScript = $Ubuntu1404PwshRemotingScript
        ExpectScripts               = [pscustomobject]@{
            PackageManagerInstallScript = $Ubuntu1404PMInstallScriptPrep
            ManualInstallScript         = $Ubuntu1404ManualInstallScriptPrep
            UninstallScript             = $Ubuntu1404UninstallScript
            ConfigurePwshRemotingScript = $Ubuntu1404PwshRemotingScriptPrepForExpect
        }
    }

    # Ubuntu 16.04 Install Info
    $Ubuntu1604PMInstallScriptPrep = @(
        'wget -q https://packages.microsoft.com/config/ubuntu/16.04/packages-microsoft-prod.deb'
        'dpkg -i packages-microsoft-prod.deb'
        'apt update'
        'apt install -y powershell && echo powershellInstallComplete'
    )
    $Ubuntu1604PMInstallScript = "sudo bash -c \```"$($Ubuntu1604PMInstallScriptPrep -join '; ')\```""

    $Ubuntu1604ManualInstallScriptPrep = @(
        "wget -q $Ubuntu1604PackageUrl"
        "dpkg -i $Ubuntu1604PackageName"
        'apt install -f && echo powershellInstallComplete'
    )
    $Ubuntu1604ManualInstallScript = "sudo bash -c \```"$($Ubuntu1604ManualInstallScriptPrep -join '; ')\```""

    $Ubuntu1604UninstallScript = 'sudo apt remove powershell'

    $Ubuntu1604PwshRemotingScriptPrep = @(
        'pscorepath=$(command -v pwsh)'
        'subsystemline=$(echo \"\"Subsystem powershell $pscorepath -sshs -NoLogo -NoProfile\"\")'
        'sed -i \"\"s|sftp-server|sftp-server\n$subsystemline|\"\" /etc/ssh/sshd_config'
        'systemctl restart sshd'
    )
    $Ubuntu1604PwshRemotingScript = "sudo bash -c \`"$($Ubuntu1604PwshRemotingScriptPrep -join '; ')\`""

    $Ubuntu1604PwshRemotingScriptPrepForExpect = @(
        'pscorepath=\\\$(command -v pwsh)'
        'subsystemline=\\\$(echo \\\"Subsystem powershell \\\$pscorepath -sshs -NoLogo -NoProfile\\\")'
        'sed -i \\\"s|sftp-server|sftp-server\\\n\\\$subsystemline|\\\" /etc/ssh/sshd_config'
        'systemctl restart sshd'
    )

    $Ubuntu1604 = [pscustomobject]@{
        PackageManagerInstallScript = $Ubuntu1604PMInstallScript
        ManualInstallScript         = $Ubuntu1604ManualInstallScript
        UninstallScript             = $Ubuntu1604UninstallScript
        ConfigurePwshRemotingScript = $Ubuntu1604PwshRemotingScript
        ExpectScripts               = [pscustomobject]@{
            PackageManagerInstallScript = $Ubuntu1604PMInstallScriptPrep
            ManualInstallScript         = $Ubuntu1604ManualInstallScriptPrep
            UninstallScript             = $Ubuntu1604UninstallScript
            ConfigurePwshRemotingScript = $Ubuntu1604PwshRemotingScriptPrepForExpect
        }
    }

    # Ubuntu 18.04 Install Info
    $Ubuntu1804PMInstallScriptPrep = @(
        'wget -q https://packages.microsoft.com/config/ubuntu/18.04/packages-microsoft-prod.deb'
        'dpkg -i packages-microsoft-prod.deb'
        'apt update'
        'apt install -y powershell && echo powershellInstallComplete'
    )
    $Ubuntu1804PMInstallScript = "sudo bash -c \```"$($Ubuntu1804PMInstallScriptPrep -join '; ')\```""

    $Ubuntu1804ManualInstallScriptPrep = @(
        "wget -q $Ubuntu1804PackageUrl"
        "dpkg -i $Ubuntu1804PackageName"
        'apt install -f && echo powershellInstallComplete'
    )
    $Ubuntu1804ManualInstallScript = "sudo bash -c \```"$($Ubuntu1804ManualInstallScriptPrep -join '; ')\```""

    $Ubuntu1804UninstallScript = 'sudo apt remove powershell'

    $Ubuntu1804PwshRemotingScriptPrep = @(
        'pscorepath=$(command -v pwsh)'
        'subsystemline=$(echo \"\"Subsystem powershell $pscorepath -sshs -NoLogo -NoProfile\"\")'
        'sed -i \"\"s|sftp-server|sftp-server\n$subsystemline|\"\" /etc/ssh/sshd_config'
        'systemctl restart sshd'
    )
    $Ubuntu1804PwshRemotingScript = "sudo bash -c \```"$($Ubuntu1804PwshRemotingScriptPrep -join '; ')\```""

    $Ubuntu1804PwshRemotingScriptPrepForExpect = @(
        'pscorepath=\\\$(command -v pwsh)'
        'subsystemline=\\\$(echo \\\"Subsystem powershell \\\$pscorepath -sshs -NoLogo -NoProfile\\\")'
        'sed -i \\\"s|sftp-server|sftp-server\\\n\\\$subsystemline|\\\" /etc/ssh/sshd_config'
        'systemctl restart sshd'
    )

    $Ubuntu1804 = [pscustomobject]@{
        PackageManagerInstallScript = $Ubuntu1804PMInstallScript
        ManualInstallScript         = $Ubuntu1804ManualInstallScript
        UninstallScript             = $Ubuntu1804UninstallScript
        ConfigurePwshRemotingScript = $Ubuntu1804PwshRemotingScript
        ExpectScripts               = [pscustomobject]@{
            PackageManagerInstallScript = $Ubuntu1804PMInstallScriptPrep
            ManualInstallScript         = $Ubuntu1804ManualInstallScriptPrep
            UninstallScript             = $Ubuntu1804UninstallScript
            ConfigurePwshRemotingScript = $Ubuntu1804PwshRemotingScriptPrepForExpect
        }
    }

    # Debian 8 Install Info
    $Debian8PMInstallScriptPrep = @(
        'apt update'
        'apt install curl apt-transport-https'
        'curl https://packages.microsoft.com/keys/microsoft.asc | sudo apt-key add -'
        "sh -c 'echo \`"\`"deb [arch=amd64] https://packages.microsoft.com/repos/microsoft-debian-jessie-prod jessie main\`"\`" > /etc/apt/sources.list.d/microsoft.list'"
        'apt update'
        'apt install -y powershell && echo powershellInstallComplete'
    )
    $Debian8PMInstallScript = "sudo bash -c \```"$($Debain8PMInstallScriptPrep -join '; ')\```""

    $Debian8PMInstallScriptPrepForExpect = @(
        'apt update'
        'apt install curl apt-transport-https'
        'curl https://packages.microsoft.com/keys/microsoft.asc | sudo apt-key add -'
        "sh -c 'echo \\\`"deb \[arch=amd64\] https://packages.microsoft.com/repos/microsoft-debian-jessie-prod jessie main\\\`" > /etc/apt/sources.list.d/microsoft.list'"
        'apt update'
        'apt install -y powershell && echo powershellInstallComplete'
    )

    $Debian8ManualInstallScriptPrep = @(
        "wget -q $Debian8PackageUrl"
        "dpkg -i $Debian8PackageName"
        'apt install -f && echo powershellInstallComplete'
    )
    $Debian8ManualInstallScript = "sudo bash -c \```"$($Debian8ManualInstallScriptPrep -join '; ')\```""

    $Debian8UninstallScript = 'sudo apt remove powershell'

    $Debian8PwshRemotingScriptPrep = @(
        'pscorepath=$(command -v pwsh)'
        'subsystemline=$(echo \"\"Subsystem powershell $pscorepath -sshs -NoLogo -NoProfile\"\")'
        'sed -i \"\"s|sftp-server|sftp-server\n$subsystemline|\"\" /etc/ssh/sshd_config'
        'systemctl restart sshd'
    )
    $Debian8PwshRemotingScript = "sudo bash -c \```"$($Debian8PwshRemotingScriptPrep -join '; ')\```""

    $Debian8PwshRemotingScriptPrepForExpect = @(
        'pscorepath=\\\$(command -v pwsh)'
        'subsystemline=\\\$(echo \\\"Subsystem powershell \\\$pscorepath -sshs -NoLogo -NoProfile\\\")'
        'sed -i \\\"s|sftp-server|sftp-server\\\n\\\$subsystemline|\\\" /etc/ssh/sshd_config'
        'systemctl restart sshd'
    )

    $Debian8 = [pscustomobject]@{
        PackageManagerInstallScript = $Debian8PMInstallScript
        ManualInstallScript         = $Debian8ManualInstallScript
        UninstallScript             = $Debian8UninstallScript
        ConfigurePwshRemotingScript = $Debian8PwshRemotingScript
        ExpectScripts               = [pscustomobject]@{
            PackageManagerInstallScript = $Debian8PMInstallScriptPrepForExpect
            ManualInstallScript         = $Debain8ManualInstallScriptPrep
            UninstallScript             = $Debian8UninstallScript
            ConfigurePwshRemotingScript = $Debian8PwshRemotingScriptPrepForExpect
        }
    }

    # Debian 9 Install Info
    $Debian9PMInstallScriptPrep = @(
        'apt update'
        'apt install install curl gnupg apt-transport-https'
        'curl https://packages.microsoft.com/keys/microsoft.asc | sudo apt-key add -'
        "sh -c 'echo \`"\`"deb [arch=amd64] https://packages.microsoft.com/repos/microsoft-debian-stretch-prod stretch main\`"\`" > /etc/apt/sources.list.d/microsoft.list'"
        'apt update'
        'apt install -y powershell && echo powershellInstallComplete'
    )
    $Debian9PMInstallScript = "sudo bash -c \```"$($Debain9PMInstallScriptPrep -join '; ')\```""

    $Debian9PMInstallScriptPrepForExpect = @(
        'apt update'
        'apt install install curl gnupg apt-transport-https'
        'curl https://packages.microsoft.com/keys/microsoft.asc | sudo apt-key add -'
        "sh -c 'echo \\\`"deb \[arch=amd64\] https://packages.microsoft.com/repos/microsoft-debian-stretch-prod stretch main\\\`" > /etc/apt/sources.list.d/microsoft.list'"
        'apt update'
        'apt install -y powershell && echo powershellInstallComplete'
    )

    $Debian9ManualInstallScriptPrep = @(
        "wget -q $Debian9PackageUrl"
        "dpkg -i $Debian9PackageName"
        'apt install -f && echo powershellInstallComplete'
    )
    $Debian9ManualInstallScript = "sudo bash -c \```"$($Debian9ManualInstallScriptPrep -join '; ')\```""

    $Debian9UninstallScript = 'sudo apt remove powershell'

    $Debian9PwshRemotingScriptPrep = @(
        'pscorepath=$(command -v pwsh)'
        'subsystemline=$(echo \"\"Subsystem powershell $pscorepath -sshs -NoLogo -NoProfile\"\")'
        'sed -i \"\"s|sftp-server|sftp-server\n$subsystemline|\"\" /etc/ssh/sshd_config'
        'systemctl restart sshd'
    )
    $Debian9PwshRemotingScript = "sudo bash -c \```"$($Debian9PwshRemotingScriptPrep -join '; ')\```""

    $Debian9PwshRemotingScriptPrepForExpect = @(
        'pscorepath=\\\$(command -v pwsh)'
        'subsystemline=\\\$(echo \\\"Subsystem powershell \\\$pscorepath -sshs -NoLogo -NoProfile\\\")'
        'sed -i \\\"s|sftp-server|sftp-server\\\n\\\$subsystemline|\\\" /etc/ssh/sshd_config'
        'systemctl restart sshd'
    )

    $Debian9 = [pscustomobject]@{
        PackageManagerInstallScript = $Debian9PMInstallScript
        ManualInstallScript         = $Debian9ManualInstallScript
        UninstallScript             = $Debian9UninstallScript
        ConfigurePwshRemotingScript = $Debian8PwshRemotingScript
        ExpectScripts               = [pscustomobject]@{
            PackageManagerInstallScript = $Debian9PMInstallScriptPrepForExpect
            ManualInstallScript         = $Debain9ManualInstallScriptPrep
            UninstallScript             = $Debian9UninstallScript
            ConfigurePwshRemotingScript = $Debian9PwshRemotingScriptPrepForExpect
        }
    }

    # CentOS 7 and RHEL 7 Install Info
    # 'curl -s https://packages.microsoft.com/config/rhel/7/prod.repo > /etc/yum.repos.d/microsoft.repo'
    $CentOS7PMInstallScriptPrep = $RHELPMInstallScriptPrep = @(
        'curl https://packages.microsoft.com/config/rhel/7/prod.repo | sudo tee /etc/yum.repos.d/microsoft.repo'
        'yum install -y powershell && echo powershellInstallComplete'
    )
    $CentOS7PMInstallScript = $RHEL7PMInstallScript = "sudo bash -c \```"$($CentOS7PMInstallScriptPrep -join '; ')\```""

    $CentOS7ManualInstallScriptPrep = $RHEL7ManualInstallScriptPrep = @(
        "yum install $CentOS7PackageUrl && echo powershellInstallComplete"
    )
    $CentOS7ManualInstallScript = $RHEL7ManualInstallScript = "sudo bash -c \```"$($CentOS7ManualInstallScriptPrep -join '; ')\```""

    $CentOS7UninstallScript = $RHEL7UninstallScript = 'sudo yum remove powershell'

    $CentOS7PwshRemotingScriptPrep = $RHEL7PwshRemotingScriptPrep = @(
        'pscorepath=$(command -v pwsh)'
        'subsystemline=$(echo \"\"Subsystem powershell $pscorepath -sshs -NoLogo -NoProfile\"\")'
        'sed -i \"\"s|sftp-server|sftp-server\n$subsystemline|\"\" /etc/ssh/sshd_config'
        'systemctl restart sshd'
    )
    $CentOS7PwshRemotingScript = $RHEL7PwshRemotingScript = "sudo bash -c \```"$($CentOS7PwshRemotingScriptPrep -join '; ')\```""

    $CentOS7PwshRemotingScriptPrepForExpect = @(
        'pscorepath=\\\$(command -v pwsh)'
        'subsystemline=\\\$(echo \\\"Subsystem powershell \\\$pscorepath -sshs -NoLogo -NoProfile\\\")'
        'sed -i \\\"s|sftp-server|sftp-server\\\n\\\$subsystemline|\\\" /etc/ssh/sshd_config'
        'systemctl restart sshd'
    )

    $CentOS7 = $RHEL7 = [pscustomobject]@{
        PackageManagerInstallScript = $CentOS7PMInstallScript
        ManualInstallScript         = $CentOS7ManualInstallScript
        UninstallScript             = $CentOS7UninstallScript
        ConfigurePwshRemotingScript = $CentOS7PwshRemotingScript
        ExpectScripts               = [pscustomobject]@{
            PackageManagerInstallScript = $CentOS7PMInstallScriptPrep
            ManualInstallScript         = $CentOS7ManualInstallScriptPrep
            UninstallScript             = $CentOS7UninstallScript
            ConfigurePwshRemotingScript = $CentOS7PwshRemotingScriptPrepForExpect
        }
    }

    # OpenSUSE 42.3 Install Info
    $OpenSUSE423PMInstallScriptPrep = @(
        'rpm --import https://packages.microsoft.com/keys/microsoft.asc'
        'zypper ar https://packages.microsoft.com/rhel/7/prod/'
        'zypper update'
        'zypper install powershell && echo powershellInstallComplete'
    )
    $OpenSUSE423PMInstallScript = "sudo bash -c \```"$($OpenSUSE423PMInstallScriptPrep -join '; ')\```""

    $OpenSUSE423ManualInstallScriptPrep = @(
        'rpm --import https://packages.microsoft.com/keys/microsoft.asc'
        "zypper install $OpenSUSE423PackageUrl && echo powershellInstallComplete"
    )
    $OpenSUSE423ManualInstallScript = "sudo bash -c \```"$($OpenSUSE423ManualInstallScriptPrep -join '; ')\```""

    $OpenSUSE423UninstallScript = 'sudo zypper remove powershell'

    $OpenSUSE423PwshRemotingScriptPrep = @(
        'pscorepath=$(command -v pwsh)'
        'subsystemline=$(echo \"\"Subsystem powershell $pscorepath -sshs -NoLogo -NoProfile\"\")'
        'sed -i \"\"s|sftp-server|sftp-server\n$subsystemline|\"\" /etc/ssh/sshd_config'
        'systemctl restart sshd'
    )
    $OpenSUSE423PwshRemotingScript = "sudo bash -c \```"$($OpenSUSE423PwshRemotingScriptPrep -join '; ')\```""

    $OpenSUSE423PwshRemotingScriptPrepForExpect = @(
        'pscorepath=\\\$(command -v pwsh)'
        'subsystemline=\\\$(echo \\\"Subsystem powershell \\\$pscorepath -sshs -NoLogo -NoProfile\\\")'
        'sed -i \\\"s|sftp-server|sftp-server\\\n\\\$subsystemline|\\\" /etc/ssh/sshd_config'
        'systemctl restart sshd'
    )

    $OpenSUSE423 = [pscustomobject]@{
        PackageManagerInstallScript = $OpenSUSE423PMInstallScript
        ManualInstallScript         = $OpenSUSE423ManualInstallScript
        UninstallScript             = $OpenSUSE423UninstallScript
        ConfigurePwshRemotingScript = $OpenSUSE423PwshRemotingScript
        ExpectScripts               = [pscustomobject]@{
            PackageManagerInstallScript = $OpenSUSE423PMInstallScriptPrep
            ManualInstallScript         = $OpenSUSE423ManualInstallScriptPrep
            UninstallScript             = $OpenSUSE423UninstallScript
            ConfigurePwshRemotingScript = $OpenSUSE423PwshRemotingScriptPrepForExpect
        }
    }

    # Fedora Install Info
    $FedoraPMInstallScriptPrep = @(
        'rpm --import https://packages.microsoft.com/keys/microsoft.asc'
        'curl https://packages.microsoft.com/config/rhel/7/prod.repo | sudo tee /etc/yum.repos.d/microsoft.repo'
        'dnf update'
        'dnf install compat-openssl10'
        'dnf install -y powershell && echo powershellInstallComplete'
    )
    $FedoraPMInstallScript = "sudo bash -c \```"$($FedoraPMInstallScriptPrep -join '; ')\```""

    $FedoraManualInstallScriptPrep = @(
        'dnf install compat-openssl10'
        "dnf install $FedoraPackageUrl && echo powershellInstallComplete"
    )
    $FedoraManualInstallScript = "sudo bash -c \```"$($FedoraManualInstallScriptPrep -join '; ')\```""

    $FedoraUninstallScript = 'sudo dnf remove powershell'

    $FedoraPwshRemotingScriptPrep = @(
        'pscorepath=$(command -v pwsh)'
        'subsystemline=$(echo \"\"Subsystem powershell $pscorepath -sshs -NoLogo -NoProfile\"\")'
        'sed -i \"\"s|sftp-server|sftp-server\n$subsystemline|\"\" /etc/ssh/sshd_config'
        'systemctl restart sshd'
    )
    $FedoraPwshRemotingScript = "sudo bash -c \```"$($FedoraPwshRemotingScriptPrep -join '; ')\```""

    $FedoraPwshRemotingScriptPrepForExpect = @(
        'pscorepath=\\\$(command -v pwsh)'
        'subsystemline=\\\$(echo \\\"Subsystem powershell \\\$pscorepath -sshs -NoLogo -NoProfile\\\")'
        'sed -i \\\"s|sftp-server|sftp-server\\\n\\\$subsystemline|\\\" /etc/ssh/sshd_config'
        'systemctl restart sshd'
    )

    $Fedora = [pscustomobject]@{
        PackageManagerInstallScript = $FedoraPMInstallScript
        ManualInstallScript         = $FedoraManualInstallScript
        UninstallScript             = $FedoraUninstallScript
        ConfigurePwshRemotingScript = $FedoraPwshRemotingScript
        ExpectScripts               = [pscustomobject]@{
            PackageManagerInstallScript = $FedoraPMInstallScriptPrep
            ManualInstallScript         = $FedoraManualInstallScriptPrep
            UninstallScript             = $FedoraUninstallScript
            ConfigurePwshRemotingScript = $FedoraPwshRemotingScriptPrepForExpect
        }
    }

    # Raspbian Install Info
    $RaspbianManualInstallScriptPrep = @(
        'apt install libunwind8'
        "wget -q $LinuxGenericArmPackageUrl"
        'mkdir ~/powershell'
        "tar -xvf ./$LinuxGenericArmPackageName -C ~/powershell && echo powershellInstallComplete"
    )
    $RaspbianManualInstallScript = "sudo bash -c \```"$($RaspbianManualInstallScriptPrep -join '; ')\```""

    $RaspbianUninstallScript = 'rm -rf ~/powershell'

    $RaspbianPwshRemotingScriptPrep = @(
        'pscorepath=$(command -v pwsh)'
        'subsystemline=$(echo \"\"Subsystem powershell $pscorepath -sshs -NoLogo -NoProfile\"\")'
        'sed -i \"\"s|sftp-server|sftp-server\n$subsystemline|\"\" /etc/ssh/sshd_config'
        'systemctl restart sshd'
    )
    $RaspbianPwshRemotingScript = "sudo bash -c \```"$($RaspbianPwshRemotingScriptPrep -join '; ')\```""

    $RaspbianPwshRemotingScriptPrepForExpect = @(
        'pscorepath=\\\$(command -v pwsh)'
        'subsystemline=\\\$(echo \\\"Subsystem powershell \\\$pscorepath -sshs -NoLogo -NoProfile\\\")'
        'sed -i \\\"s|sftp-server|sftp-server\\\n\\\$subsystemline|\\\" /etc/ssh/sshd_config'
        'systemctl restart sshd'
    )

    $Raspbian = [pscustomobject]@{
        PackageManagerInstallScript = $null
        ManualInstallScript         = $RaspbianManualInstallScript
        UninstallScript             = $RaspbianUninstallScript
        ConfigurePwshRemotingScript = $RaspbianPwshRemotingScript
        ExpectScripts               = [pscustomobject]@{
            PackageManagerInstallScript = $RaspbianPMInstallScriptPrep
            ManualInstallScript         = $RaspbianManualInstallScriptPrep
            UninstallScript             = $RaspbianUninstallScript
            ConfigurePwshRemotingScript = $RaspbianPwshRemotingScriptPrepForExpect
        }
    }

    #endregion >> Prep

    #region >> Main Body

    # Probe the Remote Host to get OS and Shell Info
    try {
        $GetSSHProbeSplatParams = @{
            RemoteHostNameOrIP  = $RemoteHostNameOrIP
        }
        if ($KeyFilePath) {
            $GetSSHProbeSplatParams.Add("KeyFilePath",$KeyFilePath)
        }
        elseif ($LocalUserName -and $LocalPasswordSS) {
            $GetSSHProbeSplatParams.Add("LocalUserName",$LocalUserName)
            $GetSSHProbeSplatParams.Add("LocalPasswordSS",$LocalPasswordSS)
        }
        elseif ($DomainUserName -and $DomainPasswordSS) {
            $GetSSHProbeSplatParams.Add("DomainUserName",$DomainUserName)
            $GetSSHProbeSplatParams.Add("DomainPasswordSS",$DomainPasswordSS)
        }
        
        $script:OSCheck = Get-SSHProbe @GetSSHProbeSplatParams
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

    Write-Host "Get-SSHProbe identified OS: $($OSCheck.OS); Shell: $($OSCheck.Shell)"

    if (!$OS) {
        switch ($OSCheck.OSVersionInfo) {
            {$_ -match 'Microsoft|Windows'} {
                $OS = "Windows"
                $WindowsVersion = $OSCheck.OSVersionInfo
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

    $script:OS = $OS

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
    )
    if ($KeyFilePath) {
        $null = $SSHCmdStringArray.Add("-i")
        $null = $SSHCmdStringArray.Add("'" + $KeyFilePath + "'")
    }
    elseif ($LocalUserName) {
        $null = $SSHCmdStringArray.Add("$FullUserName@$HostNameValue")
    }
    elseif ($DomainUserName) {
        $null = $SSHCmdStringArray.Add("$FullUserName@$DomainNameShort@$HostNameValue")
    }

    if ($OSCheck.OS -eq "Windows") {
        if ($UsePackageManagement) {
            if ($ConfigurePSRemoting) {
                $SSHCmdString = $($SSHCmdStringArray -join " ") + ' "' + $Windows.ConfigurePwshRemotingScript + '"'
            }
            else {
                $SSHCmdString = $($SSHCmdStringArray -join " ") + ' "' + $Windows.PackageManagerInstallScript + '"'
            }
        }
        else {
            if ($ConfigurePSRemoting) {
                $SSHCmdString = $($SSHCmdStringArray -join " ") + ' "' + $Windows.ConfigurePwshRemotingScript + '"'
            }
            else {
                $SSHCmdString = $($SSHCmdStringArray -join " ") + ' "' + $Windows.ManualInstallScript + '"'
            }
        }

        Write-Host "`$SSHCmdString is:`n    $SSHCmdString"

        try {
            $PwshConfigResult = [scriptblock]::Create($SSHCmdString).InvokeReturnAsIs()
            
            $FinalOutput = [pscustomobject]@{
                TentativeResult         = "Success"
                AllOutput               = $PwshConfigResult
                SSHProbeInfo            = $OSCheck
            }
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }
    }
    if ($OSCheck.OS -eq "Linux") {
        $BootstrapSB = {
            if ($UsePackageManagement) {
                if ($ConfigurePSRemoting) {
                    $SSHCmdString = $($SSHCmdStringArray -join " ") + ' "' + $args[0].PackageManagerInstallScript + '; ' + $args[0].ConfigurePwshRemotingScript + '"'
                }
                else {
                    $SSHCmdString = $($SSHCmdStringArray -join " ") + ' "' + $args[0].PackageManagerInstallScript + '"'
                }
            }
            else {
                if ($ConfigurePSRemoting) {
                    $SSHCmdString = $($SSHCmdStringArray -join " ") + ' "' + $args[0].ManualInstallScript + '; ' + $args[0].ConfigurePwshRemotingScript + '"'
                }
                else {
                    $SSHCmdString = $($SSHCmdStringArray -join " ") + ' "' + $args[0].ManualInstallScript + '"'
                }
            }

            $SSHCmdString
        }

        $SSHCmdString = Invoke-Command -ScriptBlock $BootstrapSB -ArgumentList $(Get-Variable -Name $OS -ValueOnly)

        Write-Host "`$SSHCmdString is:`n    $SSHCmdString"

        # Now we need to deal with passing the 'sudo' password to the Remote Host, so we need to use either Await or Expect

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
            while (![bool]$($($CheckForExpectedResponses -split "`n") -match [regex]::Escape("Are you sure you want to continue connecting (yes/no)?")) -and
            ![bool]$($($CheckForExpectedResponses -split "`n") -match [regex]::Escape("'s password:")) -and 
            ![bool]$($($CheckForExpectedResponses -split "`n") -match "^}") -and $Counter -le 30
            ) {
                $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse
                $null = $CheckForExpectedResponses.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                if ($CheckResponsesOutput -match "must be greater than zero" -or @($CheckResponsesOutput)[-1] -notmatch "[a-zA-Z]") {
                    break
                }
                Start-Sleep -Seconds 1
                $Counter++
            }
            if ($Counter -eq 31) {
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
                            while ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue)) {
                                Write-Verbose "Waiting for Await Module Process Id $($PSAwaitProcess.Id) to end..."
                                Start-Sleep -Seconds 1
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
                            while ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue)) {
                                Write-Verbose "Waiting for Await Module Process Id $($PSAwaitProcess.Id) to end..."
                                Start-Sleep -Seconds 1
                            }
                        }
                    }
                }

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
                while ($SuccessOrAcceptHostKeyOrPwdPrompt -notmatch [regex]::Escape("Are you sure you want to continue connecting (yes/no)?") -and
                $SuccessOrAcceptHostKeyOrPwdPrompt -notmatch [regex]::Escape("'s password:") -and 
                $SuccessOrAcceptHostKeyOrPwdPrompt -notmatch "^}" -and $Counter -le 30
                ) {
                    $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse
                    $null = $CheckForExpectedResponses.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                    Start-Sleep -Seconds 1
                    $Counter++
                }
                if ($Counter -eq 31) {
                    Write-Error "SSH via '$($SSHCmdStringArray -join " ")' timed out!"
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
                                while ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue)) {
                                    Write-Verbose "Waiting for Await Module Process Id $($PSAwaitProcess.Id) to end..."
                                    Start-Sleep -Seconds 1
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
                            while ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue)) {
                                Write-Verbose "Waiting for Await Module Process Id $($PSAwaitProcess.Id) to end..."
                                Start-Sleep -Seconds 1
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
                while (![bool]$($($CheckExpectedSendYesOutput -split "`n") -match [regex]::Escape("'s password:")) -and 
                ![bool]$($($CheckExpectedSendYesOutput -split "`n") -match "^}") -and $Counter -le 30
                ) {
                    $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse
                    $null = $CheckExpectedSendYesOutput.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                    Start-Sleep -Seconds 1
                    $Counter++
                }
                if ($Counter -eq 31) {
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
                                while ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue)) {
                                    Write-Verbose "Waiting for Await Module Process Id $($PSAwaitProcess.Id) to end..."
                                    Start-Sleep -Seconds 1
                                }
                            }
                        }
                    }

                    return
                }

                $CheckSendYesOutput = $CheckExpectedSendYesOutput | foreach {$_ -split "`n"}
                
                if ($CheckSendYesOutput -match [regex]::Escape("'s password:")) {
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
                    while (![bool]$($($SSHOutputPrep -split "`n") -match ".*") -and $Counter -le 30) {
                        $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse
                        if (![System.String]::IsNullOrWhiteSpace($SuccessOrAcceptHostKeyOrPwdPrompt)) {
                            $null = $SSHOutputPrep.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                        }
                        Start-Sleep -Seconds 1
                        $Counter++
                    }
                    if ($Counter -eq 31) {
                        Write-Error "Sending the user's password timed out!"
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
                                    while ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue)) {
                                        Write-Verbose "Waiting for Await Module Process Id $($PSAwaitProcess.Id) to end..."
                                        Start-Sleep -Seconds 1
                                    }
                                }
                            }
                        }

                        return
                    }
                }
            }
            elseif ($CheckResponsesOutput -match [regex]::Escape("'s password:")) {
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
                while (![bool]$($($SSHOutputPrep -split "`n") -match ".*") -and $Counter -le 30) {
                    $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse
                    if (![System.String]::IsNullOrWhiteSpace($SuccessOrAcceptHostKeyOrPwdPrompt)) {
                        $null = $SSHOutputPrep.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                    }
                    Start-Sleep -Seconds 1
                    $Counter++
                }
                if ($Counter -eq 31) {
                    Write-Error "Sending the user's password timed out!"
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
                                while ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue)) {
                                    Write-Verbose "Waiting for Await Module Process Id $($PSAwaitProcess.Id) to end..."
                                    Start-Sleep -Seconds 1
                                }
                            }
                        }
                    }

                    return
                }
            }

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
                        while ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue)) {
                            Write-Verbose "Waiting for Await Module Process Id $($PSAwaitProcess.Id) to end..."
                            Start-Sleep -Seconds 1
                        }
                    }
                }
            }

            $FinalOutput = [pscustomobject]@{
                TentativeResult         = "Success"
                AllOutput               = $SSHOutputPrep
                SSHProbeInfo            = $OSCheck
            }
        }

        if ($PSVersionTable.Platform -eq "Unix") {
            $FinalPassword = if ($DomainPassword) {$DomainPassword} else {$LocalPassword}
            $ExpectScripts = $(Get-Variable -Name $OS -ValueOnly).ExpectScripts

            if ($UsePackageManagement) {
                if ($ConfigurePSRemoting) {
                    #$SSHScript = $($args[0].PackageManagerInstallScript + '; ' + $args[0].ConfigurePwshRemotingScript) -split '; '
                    $SSHScript = $ExpectScripts.PackageManagerInstallScript + $ExpectScripts.ConfigurePwshRemotingScript
                }
                else {
                    #$SSHScript = $args[0].PackageManagerInstallScript -split '; '
                    $SSHScript = $ExpectScripts.PackageManagerInstallScript
                }
            }
            else {
                if ($ConfigurePSRemoting) {
                    #$SSHScript = $($args[0].ManualInstallScript + '; ' + $args[0].ConfigurePwshRemotingScript) -split '; '
                    $SSHScript = $ExpectScripts.ManualInstallScript + $ExpectScripts.ConfigurePwshRemotingScript
                }
                else {
                    #$SSHScript = $args[0].ManualInstallScript -split '; '
                    $SSHScript = $ExpectScripts.ManualInstallScript
                }
            }

            $SSHScript = $SSHScript | foreach {
                if ($_ -match "powershellInstallComplete") {
                    'send -- \"' + $_ + '\r\"' + "`n" + 'expect \"*powershellInstallComplete*\"'
                }
                else {
                    'send -- \"' + $_ + '\r\"' + "`n" + 'expect \"*\"'
                }
            }

            $ExpectScriptPrep = @(
                'expect - << EOF'
                'set timeout 120'
                "spawn $($SSHCmdStringArray -join " ")"
                'match_max 100000'
                'expect {'
                '    \"*(yes/no)?*\" {'
                '        send -- \"yes\r\"'
                '        exp_continue'
                '    }'
                '    \"*password:*\" {'
                "        send -- \`"$FinalPassword\r\`""
                '        expect \"*\"'
                '        exp_continue'
                '    }'
                '}'
                'send -- \"sudo su\r\"'
                'expect {'
                '    \"*password:*\" {'
                "        send -- \`"$FinalPassword\r\`""
                '        expect \"*\"'
                '        exp_continue'
                '    }'
                '}'
                'expect \"*\"'
                $SSHScript
                'expect eof'
                'EOF'
            )
            $ExpectScript = $ExpectScriptPrep -join "`n"
            
            # The below $ExpectOutput is an array of strings
            $ExpectOutput = bash -c "$ExpectScript"

            # NOTE: The below -replace regex string removes garbage escape sequences like: [116;1H
            $SSHOutputPrep = $ExpectOutput -replace "\e\[(\d+;)*(\d+)?[ABCDHJKfmsu]",""

            $FinalOutput = [pscustomobject]@{
                TentativeResult         = "Success"
                AllOutput               = $SSHOutputPrep
                SSHProbeInfo            = $OSCheck
            }
        }
    }

    $FinalOutput
    
    #endregion >> Main Body
}


<#
    .SYNOPSIS
        Use ssh to determine OS information and the default shell for a Remote Host.

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

    .EXAMPLE
        # Minimal parameters...

        $GetSSHProbeSplatParams = @{
            RemoteHostNameOrIP      = "zerowin16sshb"
            DomainUserNameSS        = "zero\zeroadmin"
            DomainPasswordSS        = $(Read-Host -Prompt "Enter password" -AsSecureString)
        }
        Get-SSHProbe @GetSSHProbeSplatParams

    .EXAMPLE
        # Using a local account on the Remote Host...

        $GetSSHProbeSplatParams = @{
            RemoteHostNameOrIP      = "centos7nodomain"
            LocalUserNameSS         = "centos7nodomain\vagrant"
            LocalPasswordSS         = $(Read-Host -Prompt "Enter password" -AsSecureString)
        }
        Get-SSHProbe @GetSSHProbeSplatParams

    .EXAMPLE
        # Using an ssh Key File instead of a password...

        $GetSSHProbeSplatParams = @{
            RemoteHostNameOrIP      = "centos7nodomain"
            LocalUserNameSS         = "centos7nodomain\vagrant"
            KeyFilePath             = $HOME/.ssh/my_ssh_key
        }
        Get-SSHProbe @GetSSHProbeSplatParams
        
#>
function Get-SSHProbe {
    [CmdletBinding(DefaultParameterSetName='Domain')]
    Param (
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
            Mandatory=$True,
            ParameterSetName='Local'    
        )]
        [securestring]$LocalPasswordSS,

        [Parameter(
            Mandatory=$True,
            ParameterSetName='Domain'
        )]
        [securestring]$DomainPasswordSS,

        [Parameter(Mandatory=$False)]
        [string]$KeyFilePath
    )

    #region >> Prep

    if (!$(Get-Command ssh -ErrorAction SilentlyContinue)) {
        Write-Error "Unable to find 'ssh'! Please make sure it is installed and part of your Environment/System Path! Halting!"
        $global:FunctionResult = "1"
        return
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

    if ($LocalPasswordSS) {
        $LocalPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($LocalPasswordSS))
    }
    If ($DomainPasswordSS) {
        $DomainPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($DomainPasswordSS))
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

    $TrySSHExe = $False

    #endregion >> Prep
    
    if (!$PSVersionTable.Platform -or $PSVersionTable.Platform -eq "Win32NT") {
        if ($RemoteOSGuess -eq "Windows") {
            if ($LocalUserName) {
                $FullUserName = $LocalUserName
            }
            if ($DomainUserName) {
                $FullUserName = $DomainUserName
            }

            if ($RemoteHostNetworkInfo.FQDN -match "unknown") {
                $HostNameValue = @(
                    $RemoteHostNetworkInfo.IPAddressList | Where-Object {$_ -notmatch "^169"}
                )[0]
            }
            else {
                $HostNameValue = $RemoteHostNetworkInfo.FQDN
            }

            # Install pwsh if it isn't already
            if (!$(Get-Command pwsh -ErrorAction SilentlyContinue)) {
                try {
                    if ($(Get-Module -ListAvailable).Name -notcontains 'ProgramManagement') {$null = Install-Module ProgramManagement -ErrorAction Stop}
                    if ($(Get-Module).Name -notcontains 'ProgramManagement') {$null = Import-Module ProgramManagement -ErrorAction Stop}
                    $InstallPwshResult = Install-Program -ProgramName powershell-core -CommandName pwsh.exe
                }
                catch {
                    Write-Error $_
                    $global:FunctionResult = "1"
                    return
                }
            }

            # This is basically what we're going for with the below string manipulation:
            #   & pwsh -c {Invoke-Command -HostName zerowin16sshb -KeyFilePath "$HOME\.ssh\zeroadmin_090618-cert.pub" -ScriptBlock {[pscustomobject]@{Output = "ConnectionSuccessful"}} | ConvertTo-Json}
            $PwshRemoteScriptBlockStringArray = @(
                '[pscustomobject]@{'
                '    Output = "ConnectionSuccessful"'
                '    Platform = $PSVersionTable.Platform'
                '    DistroInfo = $PSVersionTable.OS'
                '    Hostnamectl = hostnamectl'
                '}'
            ) | foreach {"    $_"}
            $PwshRemoteScriptBlockString = $PwshRemoteScriptBlockStringArray -join "`n"
            [System.Collections.ArrayList]$PwshInvCmdStringArray = @(
                'Invoke-Command'
                '-HostName'
                $HostNameValue
                '-UserName'
                $FullUserName
            )
            if ($KeyFilePath) {
                $null = $PwshInvCmdStringArray.Add('-KeyFilePath')
                $null = $PwshInvCmdStringArray.Add("'$KeyFilePath'")
            }
            $null = $PwshInvCmdStringArray.Add('-HideComputerName')
            $null = $PwshInvCmdStringArray.Add("-ScriptBlock {`n$PwshRemoteScriptBlockString`n}")
            $null = $PwshInvCmdStringArray.Add('|')
            $null = $PwshInvCmdStringArray.Add('ConvertTo-Json')
            $PwshInvCmdString = $PwshInvCmdStringArray -join " "
            $PwshCmdStringArray = @(
                '&'
                '"' + $(Get-Command pwsh).Source + '"'
                "-c {$PwshInvCmdString}"
            )
            $PwshCmdString = $script:PwshCmdString = $PwshCmdStringArray -join " "

            #region >> Await Attempt Number 1 of 2
            
            $null = Start-AwaitSession
            Start-Sleep -Seconds 1
            $null = Send-AwaitCommand '$host.ui.RawUI.WindowTitle = "PSAwaitSession"'
            $PSAwaitProcess = $($(Get-Process | Where-Object {$_.Name -eq "powershell"}) | Sort-Object -Property StartTime -Descending)[0]
            Start-Sleep -Seconds 1
            $null = Send-AwaitCommand "`$env:Path = '$env:Path'"
            Start-Sleep -Seconds 1
            $null = Send-AwaitCommand -Command $([scriptblock]::Create($PwshCmdString))
            Start-Sleep -Seconds 5

            # This will either not prompt at all, prompt to accept the RemoteHost's RSA Host Key, or prompt for a password
            $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse

            [System.Collections.ArrayList]$CheckForExpectedResponses = @()
            $null = $CheckForExpectedResponses.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
            $Counter = 0
            while (![bool]$($($CheckForExpectedResponses -split "`n") -match [regex]::Escape("Are you sure you want to continue connecting (yes/no)?")) -and
            ![bool]$($($CheckForExpectedResponses -split "`n") -match [regex]::Escape("'s password:")) -and 
            ![bool]$($($CheckForExpectedResponses -split "`n") -match "^}") -and $Counter -le 30
            ) {
                $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse
                $null = $CheckForExpectedResponses.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                if ($CheckResponsesOutput -match "must be greater than zero" -or @($CheckResponsesOutput)[-1] -notmatch "[a-zA-Z]") {
                    break
                }
                Start-Sleep -Seconds 1
                $Counter++
            }
            if ($Counter -eq 31) {
                Write-Verbose "SSH via 'pwsh -c {Invoke-Command ...}' timed out!"
                
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
                            while ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue)) {
                                Write-Verbose "Waiting for Await Module Process Id $($PSAwaitProcess.Id) to end..."
                                Start-Sleep -Seconds 1
                            }
                        }
                    }
                }
            }
            #endregion >> Await Attempt 1 of 2

            $CheckResponsesOutput = $CheckForExpectedResponses | foreach {$_ -split "`n"}
            # Make sure we didn't already throw an error related to the Remote Host not having PowerShell Remoting configured
            if ($CheckResponsesOutput -match "background process reported an error") {
                $TrySSHExe = $True
            }

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
                            while ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue)) {
                                Write-Verbose "Waiting for Await Module Process Id $($PSAwaitProcess.Id) to end..."
                                Start-Sleep -Seconds 1
                            }
                        }
                    }
                }

                $null = Start-AwaitSession
                Start-Sleep -Seconds 1
                $null = Send-AwaitCommand '$host.ui.RawUI.WindowTitle = "PSAwaitSession"'
                $PSAwaitProcess = $($(Get-Process | Where-Object {$_.Name -eq "powershell"}) | Sort-Object -Property StartTime -Descending)[0]
                Start-Sleep -Seconds 1
                $null = Send-AwaitCommand "`$env:Path = '$env:Path'"
                Start-Sleep -Seconds 1
                $null = Send-AwaitCommand -Command $([scriptblock]::Create($PwshCmdString))
                Start-Sleep -Seconds 5

                # This will either not prompt at all, prompt to accept the RemoteHost's RSA Host Key, or prompt for a password
                $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse

                [System.Collections.ArrayList]$CheckForExpectedResponses = @()
                $null = $CheckForExpectedResponses.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                $Counter = 0
                while ($SuccessOrAcceptHostKeyOrPwdPrompt -notmatch [regex]::Escape("Are you sure you want to continue connecting (yes/no)?") -and
                $SuccessOrAcceptHostKeyOrPwdPrompt -notmatch [regex]::Escape("'s password:") -and 
                $SuccessOrAcceptHostKeyOrPwdPrompt -notmatch "^}" -and $Counter -le 30
                ) {
                    $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse
                    $null = $CheckForExpectedResponses.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                    Start-Sleep -Seconds 1
                    $Counter++
                }
                if ($Counter -eq 31) {
                    Write-Verbose "SSH via 'pwsh -c {Invoke-Command ...}' timed out!"
                    
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
                                while ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue)) {
                                    Write-Verbose "Waiting for Await Module Process Id $($PSAwaitProcess.Id) to end..."
                                    Start-Sleep -Seconds 1
                                }
                            }
                        }
                    }
                }
            }

            #endregion >> Await Attempt 2 of 2

            $CheckResponsesOutput = $CheckForExpectedResponses | foreach {$_ -split "`n"}
            # Make sure we didn't already throw an error related to the Remote Host not having PowerShell Remoting configured
            if ($CheckResponsesOutput -match "background process reported an error") {
                $TrySSHExe = $True
            }

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
                            while ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue)) {
                                Write-Verbose "Waiting for Await Module Process Id $($PSAwaitProcess.Id) to end..."
                                Start-Sleep -Seconds 1
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
                while (![bool]$($($CheckExpectedSendYesOutput -split "`n") -match [regex]::Escape("'s password:")) -and 
                ![bool]$($($CheckExpectedSendYesOutput -split "`n") -match "^}") -and $Counter -le 30
                ) {
                    $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse
                    $null = $CheckExpectedSendYesOutput.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                    Start-Sleep -Seconds 1
                    $Counter++
                }
                if ($Counter -eq 31) {
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
                                while ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue)) {
                                    Write-Verbose "Waiting for Await Module Process Id $($PSAwaitProcess.Id) to end..."
                                    Start-Sleep -Seconds 1
                                }
                            }
                        }
                    }

                    return
                }

                $CheckSendYesOutput = $CheckExpectedSendYesOutput | foreach {$_ -split "`n"}
                
                if ($CheckSendYesOutput -match [regex]::Escape("'s password:")) {
                    if ($LocalPassword) {
                        $null = Send-AwaitCommand $LocalPassword
                    }
                    if ($DomainPassword) {
                        $null = Send-AwaitCommand $DomainPassword
                    }
                    Start-Sleep -Seconds 3

                    $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse

                    [System.Collections.ArrayList]$JsonOutputPrep = @()
                    $null = $JsonOutputPrep.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                    $Counter = 0
                    while (![bool]$($($JsonOutputPrep -split "`n") -match "^}") -and $Counter -le 30) {
                        $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse
                        if (![System.String]::IsNullOrWhiteSpace($SuccessOrAcceptHostKeyOrPwdPrompt)) {
                            $null = $JsonOutputPrep.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                        }
                        Start-Sleep -Seconds 1
                        $Counter++
                    }
                    if ($Counter -eq 31) {
                        Write-Verbose "Sending the user's password timed out!"

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
                                    while ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue)) {
                                        Write-Warning "Waiting for Await Module Process Id $($PSAwaitProcess.Id) to end..."
                                        Start-Sleep -Seconds 1
                                    }
                                }
                            }
                        }

                        $TrySSHExe = $True
                    }

                    [System.Collections.ArrayList]$JsonOutputPrep = $($JsonOutputPrep | foreach {$_ -split "`n"}) | Where-Object {$_ -notmatch "^PS "}
                    if (![bool]$($JsonOutputPrep[0] -match "^{")) {
                        $null = $JsonOutputPrep.Insert(0,'{')
                    }
                }
            }
            elseif ($CheckResponsesOutput -match [regex]::Escape("'s password:")) {
                if ($LocalPassword) {
                    $null = Send-AwaitCommand $LocalPassword
                }
                if ($DomainPassword) {
                    $null = Send-AwaitCommand $DomainPassword
                }
                Start-Sleep -Seconds 3

                $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse

                [System.Collections.ArrayList]$JsonOutputPrep = @()
                $null = $JsonOutputPrep.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                $Counter = 0
                while (![bool]$($($JsonOutputPrep -split "`n") -match "^}") -and $Counter -le 30) {
                    $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse
                    if (![System.String]::IsNullOrWhiteSpace($SuccessOrAcceptHostKeyOrPwdPrompt)) {
                        $null = $JsonOutputPrep.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                    }
                    Start-Sleep -Seconds 1
                    $Counter++
                }
                if ($Counter -eq 31) {
                    Write-Verbose "Sending the user's password timed out!"

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
                                while ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue)) {
                                    Write-Warning "Waiting for Await Module Process Id $($PSAwaitProcess.Id) to end..."
                                    Start-Sleep -Seconds 1
                                }
                            }
                        }
                    }

                    $TrySSHExe = $True
                }

                [System.Collections.ArrayList]$JsonOutputPrep = $($JsonOutputPrep | foreach {$_ -split "`n"}) | Where-Object {$_ -notmatch "^PS "}
                if (![bool]$($JsonOutputPrep[0] -match "^{")) {
                    $null = $JsonOutputPrep.Insert(0,'{')
                }
            }
            else {
                [System.Collections.ArrayList]$JsonOutputPrep = $($CheckResponsesOutput | foreach {$_ -split "`n"}) | Where-Object {
                    $_ -notmatch "^PS " -and ![System.String]::IsNullOrWhiteSpace($_)
                }
                $EndOfInputLineContent = $JsonOutputPrep -match [regex]::Escape("ConvertTo-Json}")
                $JsonOutputIndex = $JsonOutputPrep.IndexOf($EndOfInputLineContent) + 1

                [System.Collections.ArrayList]$JsonOutputPrep = $JsonOutputPrep[$JsonOutputIndex..$($JsonOutputPrep.Count-1)]

                if (![bool]$($JsonOutputPrep[0] -match "^{")) {
                    $null = $JsonOutputPrep.Insert(0,'{')
                }
            }

            if (!$TrySSHExe) {
                $IndexesOfOpenBracket = for ($i=0; $i -lt $JsonOutputPrep.Count; $i++) {
                    if ($JsonOutputPrep[$i] -match "^{") {
                        $i
                    }
                }
                $LastIndexOfOpenBracket = $($IndexesOfOpenBracket | Measure-Object -Maximum).Maximum
                $IndexesOfCloseBracket = for ($i=0; $i -lt $JsonOutputPrep.Count; $i++) {
                    if ($JsonOutputPrep[$i] -match "^}") {
                        $i
                    }
                }
                $LastIndexOfCloseBracket = $($IndexesOfCloseBracket | Measure-Object -Maximum).Maximum
                [System.Collections.ArrayList]$JsonOutputPrep = $JsonOutputPrep[$LastIndexOfOpenBracket..$LastIndexOfCloseBracket] | foreach {$_ -split "`n"}
                if (![bool]$($JsonOutputPrep[0] -match "^{")) {
                    $null = $JsonOutputPrep.Insert(0,'{')
                }

                $FinalJson = $JsonOutputPrep | foreach {if (![System.String]::IsNullOrWhiteSpace($_)) {$_.Trim()}}

                try {
                    $SSHCheckAsJson = $FinalJson | ConvertFrom-Json
                }
                catch {
                    $TrySSHExe = $True
                }
            }

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
                        while ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue)) {
                            Write-Verbose "Waiting for Await Module Process Id $($PSAwaitProcess.Id) to end..."
                            Start-Sleep -Seconds 1
                        }
                    }
                }
            }

            if ($SSHCheckAsJson.Output -ne "ConnectionSuccessful") {
                $TrySSHExe = $True
            }

            # TODO: Remove this after testing finished
            #$SSHCheckAsJson
            
            # NOTE: The below $ShellDetermination refers to the shell you will (probably) end up in if you use an ssh command, NOT PSRemoting
            if ($SSHCheckAsJson.Output -eq "ConnectionSuccessful") {
                if ($SSHCheckAsJson.Platform -eq "Win32NT") {
                    $OSDetermination = "Windows"
                    $ShellDetermination = "pwsh"
                    [System.Collections.ArrayList]$OSVersionInfo = @()
                    if ($SSHCheckAsJson.DistroInfo) {
                        $null = $OSVersionInfo.Add($SSHCheckAsJson.DistroInfo)
                    }
                    if ($SSHCheckAsJson.Hostnamectl) {
                        $null = $OSVersionInfo.Add($SSHCheckAsJson.Hostnamectl)
                    }
                }
                else {
                    $OSDetermination = "Linux"
                    $ShellDetermination = "pwsh"
                    [System.Collections.ArrayList]$OSVersionInfo = @()
                    if ($SSHCheckAsJson.DistroInfo) {
                        $null = $OSVersionInfo.Add($SSHCheckAsJson.DistroInfo)
                    }
                    if ($SSHCheckAsJson.Hostnamectl) {
                        $null = $OSVersionInfo.Add($SSHCheckAsJson.Hostnamectl)
                    }
                }

                $FinalOutput = [pscustomobject]@{
                    OS              = $OSDetermination
                    Shell           = $ShellDetermination
                    OSVersionInfo   = $OSVersionInfo
                }
            }
        }

        if ($RemoteOSGuess -eq "Linux" -or $TrySSHExe) {
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
            #     ssh -t pdadmin@192.168.2.10 "echo 'ConnectionSuccessful'"
            [System.Collections.ArrayList]$SSHCmdStringArray = @(
                'ssh'
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
            $Bytes = [System.Text.Encoding]::Unicode.GetBytes('$PSVersionTable | ConvertTo-Json')
            $EncodedCommandPSVerTable = [Convert]::ToBase64String($Bytes)
            $Bytes = [System.Text.Encoding]::Unicode.GetBytes('"Cim OS Info: " + $(Get-CimInstance Win32_OperatingSystem).Caption')
            $EncodedCommandWinOSCim = [Convert]::ToBase64String($Bytes)
            $SSHScript = @(
                "echo ConnectionSuccessful"
                "echo 111RootDirInfo111"
                "cd /"
                "dir"
                "echo 111ProcessInfo111"
                'Get-Process -Id `$PID'
                "echo 111PwshJson111"
                "pwsh -NoProfile -EncodedCommand $EncodedCommandPSVerTable"
                "echo 111PowerShellCimInfo111"
                "powershell -NoProfile -EncodedCommand $EncodedCommandWinOSCim"
                "echo 111UnameOutput111"
                "uname -a"
                "echo 111HostnamectlOutput111"
                "hostnamectl"
            )
            $SSHScript = $SSHScript -join "; "
            $null = $SSHCmdStringArray.Add($('"' + $SSHScript + '"'))
            # NOTE: The below -replace regex string removes garbage escape sequences like: [116;1H
            $SSHCmdString = $script:SSHCmdString = '@($(' + $($SSHCmdStringArray -join " ") + ') -replace "\e\[(\d+;)*(\d+)?[ABCDHJKfmsu]","") 2>$null'

            #region >> Await Attempt Number 1 of 2
            
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
            while (![bool]$($($CheckForExpectedResponses -split "`n") -match [regex]::Escape("Are you sure you want to continue connecting (yes/no)?")) -and
            ![bool]$($($CheckForExpectedResponses -split "`n") -match [regex]::Escape("'s password:")) -and 
            ![bool]$($($CheckForExpectedResponses -split "`n") -match "^}") -and $Counter -le 30
            ) {
                $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse
                $null = $CheckForExpectedResponses.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                if ($CheckResponsesOutput -match "must be greater than zero" -or @($CheckResponsesOutput)[-1] -notmatch "[a-zA-Z]") {
                    break
                }
                Start-Sleep -Seconds 1
                $Counter++
            }
            if ($Counter -eq 31) {
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
                            while ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue)) {
                                Write-Verbose "Waiting for Await Module Process Id $($PSAwaitProcess.Id) to end..."
                                Start-Sleep -Seconds 1
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
                            while ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue)) {
                                Write-Verbose "Waiting for Await Module Process Id $($PSAwaitProcess.Id) to end..."
                                Start-Sleep -Seconds 1
                            }
                        }
                    }
                }

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
                while ($SuccessOrAcceptHostKeyOrPwdPrompt -notmatch [regex]::Escape("Are you sure you want to continue connecting (yes/no)?") -and
                $SuccessOrAcceptHostKeyOrPwdPrompt -notmatch [regex]::Escape("'s password:") -and 
                $SuccessOrAcceptHostKeyOrPwdPrompt -notmatch "^}" -and $Counter -le 30
                ) {
                    $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse
                    $null = $CheckForExpectedResponses.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                    Start-Sleep -Seconds 1
                    $Counter++
                }
                if ($Counter -eq 31) {
                    Write-Error "SSH via '$($SSHCmdStringArray -join " ")' timed out!"
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
                                while ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue)) {
                                    Write-Verbose "Waiting for Await Module Process Id $($PSAwaitProcess.Id) to end..."
                                    Start-Sleep -Seconds 1
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
                            while ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue)) {
                                Write-Verbose "Waiting for Await Module Process Id $($PSAwaitProcess.Id) to end..."
                                Start-Sleep -Seconds 1
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
                while (![bool]$($($CheckExpectedSendYesOutput -split "`n") -match [regex]::Escape("'s password:")) -and 
                ![bool]$($($CheckExpectedSendYesOutput -split "`n") -match "^}") -and $Counter -le 30
                ) {
                    $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse
                    $null = $CheckExpectedSendYesOutput.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                    Start-Sleep -Seconds 1
                    $Counter++
                }
                if ($Counter -eq 31) {
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
                                while ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue)) {
                                    Write-Verbose "Waiting for Await Module Process Id $($PSAwaitProcess.Id) to end..."
                                    Start-Sleep -Seconds 1
                                }
                            }
                        }
                    }

                    return
                }

                $CheckSendYesOutput = $CheckExpectedSendYesOutput | foreach {$_ -split "`n"}
                
                if ($CheckSendYesOutput -match [regex]::Escape("'s password:")) {
                    if ($LocalPassword) {
                        $null = Send-AwaitCommand $LocalPassword
                    }
                    if ($DomainPassword) {
                        $null = Send-AwaitCommand $DomainPassword
                    }
                    Start-Sleep -Seconds 3

                    $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse

                    [System.Collections.ArrayList]$SSHOutputPrep = @()
                    $null = $SSHOutputPrep.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                    $Counter = 0
                    while (![bool]$($($SSHOutputPrep -split "`n") -match "^ConnectionSuccessful") -and $Counter -le 30) {
                        $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse
                        if (![System.String]::IsNullOrWhiteSpace($SuccessOrAcceptHostKeyOrPwdPrompt)) {
                            $null = $SSHOutputPrep.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                        }
                        Start-Sleep -Seconds 1
                        $Counter++
                    }
                    if ($Counter -eq 31) {
                        Write-Error "Sending the user's password timed out!"
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
                                    while ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue)) {
                                        Write-Verbose "Waiting for Await Module Process Id $($PSAwaitProcess.Id) to end..."
                                        Start-Sleep -Seconds 1
                                    }
                                }
                            }
                        }

                        return
                    }
                }
            }
            elseif ($CheckResponsesOutput -match [regex]::Escape("'s password:")) {
                if ($LocalPassword) {
                    $null = Send-AwaitCommand $LocalPassword
                }
                if ($DomainPassword) {
                    $null = Send-AwaitCommand $DomainPassword
                }
                Start-Sleep -Seconds 3

                $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse

                [System.Collections.ArrayList]$SSHOutputPrep = @()
                $null = $SSHOutputPrep.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                $Counter = 0
                while (![bool]$($($SSHOutputPrep -split "`n") -match "^ConnectionSuccessful") -and $Counter -le 30) {
                    $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse
                    if (![System.String]::IsNullOrWhiteSpace($SuccessOrAcceptHostKeyOrPwdPrompt)) {
                        $null = $SSHOutputPrep.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                    }
                    Start-Sleep -Seconds 1
                    $Counter++
                }
                if ($Counter -eq 31) {
                    Write-Error "Sending the user's password timed out!"
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
                                while ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue)) {
                                    Write-Verbose "Waiting for Await Module Process Id $($PSAwaitProcess.Id) to end..."
                                    Start-Sleep -Seconds 1
                                }
                            }
                        }
                    }

                    return
                }
            }

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
                        while ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue)) {
                            Write-Verbose "Waiting for Await Module Process Id $($PSAwaitProcess.Id) to end..."
                            Start-Sleep -Seconds 1
                        }
                    }
                }
            }

            # TODO: Remove this after testing finished
            #$SSHOutputPrep

            if ([bool]$($($SSHOutputPrep -split "`n") -match "^ConnectionSuccessful")) {
                if ($SSHOutputPrep -match "ConnectionSuccessful; echo 111RootDirInfo111;") {
                    $OSDetermination = "Windows"
                    $ShellDetermination = "cmd"
                    $OSVersionInfo = $null
                }
                elseif ($SSHOutputPrep -match "111RootDirInfo111" -and $SSHOutputPrep -match "Directory:.*[a-zA-Z]:\\") {
                    $OSDetermination = "Windows"
                    if ($SSHOutputPrep -match "111ProcessInfo111" -and $SSHOutputPrep -match "Name[\s]+:[\s]+powershell") {
                        $ShellDetermination = "powershell"
                        # The below $OSVersionInfo will be a string that looks something like:
                        #   Microsoft Windows Server 2016 Standard Evaluation
                        $OSVersionInfo = $($($($SSHOutputPrep -split "`n") -match "Cim OS Info:") -replace "Cim OS Info: ","").Trim()
                    }
                    elseif ($SSHOutputPrep -match "111ProcessInfo111" -and $SSHOutputPrep -match "Name[\s]+:[\s]+pwsh") {
                        $ShellDetermination = "pwsh"
                        # The below $OSVersionInfo will be a string that looks something like:
                        #   Microsoft Windows Server 2016 Standard Evaluation
                        $OSVersionInfo = $($($($SSHOutputPrep -split "`n") -match "Cim OS Info:") -replace "Cim OS Info: ","").Trim()
                    }
                }
                elseif ($SSHOutputPrep -match "111RootDirInfo111" -and $SSHOutputPrep -match " etc " -and 
                !$($SSHOutputPrep -match "111RootDirInfo111" -and $SSHOutputPrep -match "Directory:.*[a-zA-Z]:\\")
                ) {
                    $OSDetermination = "Linux"
                    if ($SSHOutputPrep -match "111ProcessInfo111" -and $SSHOutputPrep -match "Name[\s]+:[\s]+pwsh") {
                        $ShellDetermination = "pwsh"
                    }
                    else {
                        $ShellDetermination = "bash"
                    }

                    #$SSHOutputPrep | Export-Clixml "$HOME\SSHOutputPrep.xml"

                    $UnameOutputHeader = $($SSHOutputPrep -split "`n") -match "111UnameOutput111"
                    $UnameOutputHeaderIndex = $($SSHOutputPrep -split "`n").IndexOf($UnameOutputHeader)
                    if ($UnameOutputHeaderIndex -eq "-1") {
                        $UnameOutputHeaderIndex = $($SSHOutputPrep -split "`n").IndexOf($UnameOutputHeader[0])
                    }
                    $UnameOutput = $($SSHOutputPrep -split "`n")[$($UnameOutputHeaderIndex + 1)]
                    $HostnamectlOutput = $($SSHOutputPrep -split "`n")[$($UnameOutputHeaderIndex + 2)..$($($SSHOutputPrep -split "`n").Count-1)]
                    [System.Collections.ArrayList]$OSVersionInfo = @()
                    if ($UnameOutput) {
                        $null = $OSVersionInfo.Add($UnameOutput)
                    }
                    if ($HostnamectlOutput) {
                        $null = $OSVersionInfo.Add($HostnamectlOutput)
                    }
                }

                $FinalOutput = [pscustomobject]@{
                    OS              = $OSDetermination
                    Shell           = $ShellDetermination
                    OSVersionInfo   = $OSVersionInfo
                }
            }
        }

        if ($SSHCheckAsJson.Output -ne "ConnectionSuccessful" -and ![bool]$($($SSHOutputPrep -split "`n") -match "^ConnectionSuccessful")) {
            Write-Error "SSH attempts via PowerShell Core 'Invoke-Command' and ssh.exe have failed!"
            $global:FunctionResult = "1"
            return
        }
    }
    elseif ($PSVersionTable.Platform -eq "Unix") {
        if ($RemoteOSGuess -eq "Windows") {
            if ($LocalUserName) {
                $FullUserName = $LocalUserName
            }
            if ($DomainUserName) {
                $FullUserName = $DomainUserName
            }

            if ($RemoteHostNetworkInfo.FQDN -match "unknown") {
                $HostNameValue = @(
                    $RemoteHostNetworkInfo.IPAddressList | Where-Object {$_ -notmatch "^169"}
                )[0]
            }
            else {
                $HostNameValue = $RemoteHostNetworkInfo.FQDN
            }

            # This is basically what we're going for with the below string manipulation:
            #   & pwsh -c {Invoke-Command -HostName zerowin16sshb -KeyFilePath "$HOME\.ssh\zeroadmin_090618-cert.pub" -ScriptBlock {[pscustomobject]@{Output = "ConnectionSuccessful"}} | ConvertTo-Json}
            $PwshRemoteScriptBlockStringArray = @(
                '[pscustomobject]@{'
                '    Output = \"ConnectionSuccessful\"'
                '    Platform = (Get-Variable PSVersionTable -ValueOnly).Platform'
                '    DistroInfo = (Get-Variable PSVersionTable -ValueOnly).OS'
                '    Hostnamectl = hostnamectl'
                '}'
            ) | foreach {"    $_"}
            $PwshRemoteScriptBlockString = $PwshRemoteScriptBlockStringArray -join "`n"
            [System.Collections.ArrayList]$PwshInvCmdStringArray = @(
                'Invoke-Command'
                '-HostName'
                $HostNameValue
                '-UserName'
                $FullUserName
            )
            if ($KeyFilePath) {
                $null = $PwshInvCmdStringArray.Add('-KeyFilePath')
                $null = $PwshInvCmdStringArray.Add("'$KeyFilePath'")
            }
            $null = $PwshInvCmdStringArray.Add('-HideComputerName')
            $null = $PwshInvCmdStringArray.Add("-ScriptBlock {`n$PwshRemoteScriptBlockString`n}")
            $null = $PwshInvCmdStringArray.Add('|')
            $null = $PwshInvCmdStringArray.Add('ConvertTo-Json')
            $PwshInvCmdString = $PwshInvCmdStringArray -join " "
            $PwshCmdStringArray = @(
                $(Get-Command pwsh).Source
                "-c {$PwshInvCmdString}"
            )
            $PwshCmdString = $script:PwshCmdString = $PwshCmdStringArray -join " "

            $FinalPassword = if ($DomainPassword) {$DomainPassword} else {$LocalPassword}

            # NOTE: 'timeout' is in seconds
            $ExpectScriptPrep = @(
                'expect - << EOF'
                'set timeout 10'
                "spawn $PwshCmdString"
                'match_max 100000'
                'expect {'
                '    \"*(yes/no)?*\" {'
                '        send -- \"yes\r\"'
                '        exp_continue'
                '    }'
                '    \"*password:*\" {'
                "        send -- \`"$FinalPassword\r\`""
                '        expect \"*\"'
                '        expect eof'
                '    }'
                '}'
                'EOF'
            )
            $ExpectScript = $ExpectScriptPrep -join "`n"

            # The below $ExpectOutput is an array of strings
            $ExpectOutput = bash -c "$ExpectScript"

            $SSHOutputPrep = $ExpectOutput -replace "\e\[(\d+;)*(\d+)?[ABCDHJKfmsu]",""

            # Sample Contents of $ExpectOutput
            <#
            spawn pwsh -c Invoke-Command -HostName centos7nodomain -UserName vagrant -ScriptBlock {[pscustomobject]@{Output = "ConnectionSuccessful"}} | ConvertTo-Json
            vagrant@centos7nodomain's password:
            {
            "Output": "ConnectionSuccessful",
            "Platform": "Unix",
            "DistroInfo": "Linux 3.10.0-862.2.3.el7.x86_64 #1 SMP Wed May 9 18:05:47 UTC 2018",
            "PSComputerName": "centos7nodomain",
            "RunspaceId": "ce31711a-87eb-47b8-809d-6598990d54c4",
            "PSShowComputerName": true
            }
            #>

            $JsonStartIndex = $SSHOutputPrep.IndexOf($($SSHOutputPrep -match '"Output"'))
            $JsonEndIndex = $SSHOutputPrep.IndexOf($($SSHOutputPrep -match '^}$'))
            [System.Collections.ArrayList]$FinalJson = $SSHOutputPrep[$JsonStartIndex..$JsonEndIndex]
            $FinalJson.Insert(0,"{")

            try {
                $SSHCheckAsJson = $FinalJson | ConvertFrom-Json
            }
            catch {
                $TrySSHExe = $True
            }

            if ($SSHCheckAsJson.Output -ne "ConnectionSuccessful") {
                $TrySSHExe = $True
            }

            if ($SSHCheckAsJson.Output -eq "ConnectionSuccessful") {
                if ($SSHCheckAsJson.Platform -eq "Win32NT") {
                    $OSDetermination = "Windows"
                    $ShellDetermination = "pwsh"
                    [System.Collections.ArrayList]$OSVersionInfo = @()
                    if ($SSHCheckAsJson.DistroInfo) {
                        $null = $OSVersionInfo.Add($SSHCheckAsJson.DistroInfo)
                    }
                    if ($SSHCheckAsJson.Hostnamectl) {
                        $null = $OSVersionInfo.Add($SSHCheckAsJson.Hostnamectl)
                    }
                }
                else {
                    $OSDetermination = "Linux"
                    $ShellDetermination = "pwsh"
                    [System.Collections.ArrayList]$OSVersionInfo = @()
                    if ($SSHCheckAsJson.DistroInfo) {
                        $null = $OSVersionInfo.Add($SSHCheckAsJson.DistroInfo)
                    }
                    if ($SSHCheckAsJson.Hostnamectl) {
                        $null = $OSVersionInfo.Add($SSHCheckAsJson.Hostnamectl)
                    }
                }

                $FinalOutput = [pscustomobject]@{
                    OS              = $OSDetermination
                    Shell           = $ShellDetermination
                    OSVersionInfo   = $OSVersionInfo
                }
            }
        }

        if ($RemoteOSGuess -eq "Linux" -or $TrySSHExe) {
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
            #     ssh -t pdadmin@192.168.2.10 "echo 'ConnectionSuccessful'"
            [System.Collections.ArrayList]$SSHCmdStringArray = @(
                'ssh'
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
            $Bytes = [System.Text.Encoding]::Unicode.GetBytes('$PSVersionTable | ConvertTo-Json')
            $EncodedCommandPSVerTable = [Convert]::ToBase64String($Bytes)
            $Bytes = [System.Text.Encoding]::Unicode.GetBytes('"Cim OS Info: " + $(Get-CimInstance Win32_OperatingSystem).Caption')
            $EncodedCommandWinOSCim = [Convert]::ToBase64String($Bytes)
            $SSHScript = @(
                "echo ConnectionSuccessful"
                "echo 111RootDirInfo111"
                "cd /"
                "dir"
                "echo 111ProcessInfo111"
                'Get-Process -Id \\\$PID'
                "echo 111PwshJson111"
                "pwsh -NoProfile -EncodedCommand $EncodedCommandPSVerTable"
                "echo 111PowerShellCimInfo111"
                "powershell -NoProfile -EncodedCommand $EncodedCommandWinOSCim"
                "echo 111UnameOutput111"
                "uname -a"
                "echo 111HostnamectlOutput111"
                "hostnamectl"
            )
            #$SSHScript = $SSHScript -join "; "
            #$null = $SSHCmdStringArray.Add($($SSHScript))
            #$null = $SSHCmdStringArray.Add($('"' + $SSHScript + '"'))
            # NOTE: The below -replace regex string removes garbage escape sequences like: [116;1H
            #$SSHCmdString = $script:SSHCmdString = '@($(' + $($SSHCmdStringArray -join " ") + ') -replace "\e\[(\d+;)*(\d+)?[ABCDHJKfmsu]","") 2>$null'
            $SSHCmdString = $script:SSHCmdString = $SSHCmdStringArray -join " "

            $FinalPassword = if ($DomainPassword) {$DomainPassword} else {$LocalPassword}

            $ExpectScriptPrep = @(
                'expect - << EOF'
                'set timeout 10'
                "spawn $SSHCmdString"
                'match_max 100000'
                'expect {'
                '    \"*(yes/no)?*\" {'
                '        send -- \"yes\r\"'
                '        exp_continue'
                '    }'
                '    \"*password:*\" {'
                "        send -- \`"$FinalPassword\r\`""
                '        expect \"*\"'
                '        exp_continue'
                '    }'
                '}'
                'expect \"*\"'
                $SSHScript | foreach {'send -- \"' + $_ + '\r\"' + "`n" + 'expect \"*\"'}
                'expect eof'
                'EOF'
            )
            $ExpectScript = $ExpectScriptPrep -join "`n"
            
            # The below $ExpectOutput is an array of strings
            $ExpectOutput = bash -c "$ExpectScript"

            # NOTE: The below -replace regex string removes garbage escape sequences like: [116;1H
            $SSHOutputPrep = $ExpectOutput -replace "\e\[(\d+;)*(\d+)?[ABCDHJKfmsu]",""

            if ([bool]$($($SSHOutputPrep -split "`n") -match "^ConnectionSuccessful")) {
                if ([bool]$($($SSHOutputPrep -split "`n") -match "'Get-Process' is not recognized as an internal or external command")) {
                    $OSDetermination = "Windows"
                    $ShellDetermination = "cmd"
                    $OSVersionInfo = $null
                }
                elseif ($SSHOutputPrep -match "111RootDirInfo111" -and $SSHOutputPrep -match "Directory:.*[a-zA-Z]:\\") {
                    $OSDetermination = "Windows"
                    if ($($SSHOutputPrep -join "") -match "111ProcessInfo.*Process.*powershell.*111PwshJson111") {
                        $ShellDetermination = "powershell"
                        # The below $OSVersionInfo will be a string that looks something like:
                        #   Microsoft Windows Server 2016 Standard Evaluation
                        $OSVersionInfo = $($($($SSHOutputPrep -split "`n") -match "Cim OS Info:") -replace "Cim OS Info: ","").Trim()
                    }
                    elseif ($($SSHOutputPrep -join "") -match "111ProcessInfo.*Process.*pwsh.*111PwshJson111") {
                        $ShellDetermination = "pwsh"
                        # The below $OSVersionInfo will be a string that looks something like:
                        #   Microsoft Windows Server 2016 Standard Evaluation
                        $OSVersionInfo = $($($($SSHOutputPrep -split "`n") -match "Cim OS Info:") -replace "Cim OS Info: ","").Trim()
                    }
                }
                elseif ($($SSHOutputPrep -join "") -match "111RootDirInfo111.*etc.*111ProcessInfo111" -and 
                !$($($SSHOutputPrep -join "") -match "111RootDirInfo111.*Windows.*111ProcessInfo111")
                ) {
                    $OSDetermination = "Linux"
                    if ($($SSHOutputPrep -join "") -match "111ProcessInfo.*Process.*pwsh.*111PwshJson111") {
                        $ShellDetermination = "pwsh"
                    }
                    else {
                        $ShellDetermination = "bash"
                    }

                    $UnameOutputHeaderIndex = $($SSHOutputPrep -split "`n").IndexOf($($($SSHOutputPrep -split "`n") -match "uname -a"))
                    $UnameOutput = $($SSHOutputPrep -split "`n")[$($UnameOutputHeaderIndex + 1)]
                    $HostnamectlOutput = $($SSHOutputPrep -split "`n")[$($UnameOutputHeaderIndex + 2)..$($($SSHOutputPrep -split "`n").Count-1)]
                    [System.Collections.ArrayList]$OSVersionInfo = @()
                    if ($UnameOutput) {
                        $null = $OSVersionInfo.Add($UnameOutput)
                    }
                    if ($HostnamectlOutput) {
                        $null = $OSVersionInfo.Add($HostnamectlOutput)
                    }
                }

                $FinalOutput = [pscustomobject]@{
                    OS              = $OSDetermination
                    Shell           = $ShellDetermination
                    OSVersionInfo   = $OSVersionInfo
                }
            }
        }
    }
    else {
        Write-Error "Unable to test SSH! Halting!"
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
                    while ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue)) {
                        Write-Verbose "Waiting for Await Module Process Id $($PSAwaitProcess.Id) to end..."
                        Start-Sleep -Seconds 1
                    }
                }
            }
        }

        return
    }

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
                while ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue)) {
                    Write-Verbose "Waiting for Await Module Process Id $($PSAwaitProcess.Id) to end..."
                    Start-Sleep -Seconds 1
                }
            }
        }
    }

    $FinalOutput
}



if ($PSVersionTable.Platform -eq "Win32NT" -and $PSVersionTable.PSEdition -eq "Core") {
    if (![bool]$(Get-Module -ListAvailable WindowsCompatibility)) {
        try {
            Install-Module WindowsCompatibility -ErrorAction Stop
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }
    }
    if (![bool]$(Get-Module WindowsCompatibility)) {
        try {
            Import-Module WindowsCompatibility -ErrorAction Stop
        }
        catch {
            Write-Error $_
            Write-Warning "The $ThisModule Module was NOT loaded successfully! Please run:`n    Remove-Module $ThisModule"
            $global:FunctionResult = "1"
            return
        }
    }
}

[System.Collections.ArrayList]$script:FunctionsForSBUse = @(
    ${Function:AddWinRMTrustedHost}.Ast.Extent.Text
    ${Function:AddWinRMTrustLocalHost}.Ast.Extent.Text
    ${Function:GetElevation}.Ast.Extent.Text
    ${Function:GetModuleDependencies}.Ast.Extent.Text
    ${Function:InstallLinuxPackage}.Ast.Extent.Text
    ${Function:InvokeModuleDependencies}.Ast.Extent.Text
    ${Function:InvokePSCompatibility}.Ast.Extent.Text
    ${Function:ManualPSGalleryModuleInstall}.Ast.Extent.Text
    ${Function:ResolveHost}.Ast.Extent.Text
    ${Function:TestIsValidIPAddress}.Ast.Extent.Text
    ${Function:Bootstrap-PowerShellCore}.Ast.Extent.Text
    ${Function:Get-SSHProbe}.Ast.Extent.Text
)

# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUqjJu/MwAgZEHAomJPdVvo1QQ
# yPSgggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFGz1cjNvj5li2Pd2
# IeZYiII1fj7CMA0GCSqGSIb3DQEBAQUABIIBACJ7FQPaFribzWiE2UpgNNpdd1/f
# MFKlGKB7BNZ22SmsKlFO8w/onQMjYX62k6IFmeP2Tc1QvCHSqqXXx3Yl42tzRoiB
# LLdktFdu4tQRoVcGNZtHGUyOEOOD8ufX265keSFqPS/uYnWWmoJC4jqpCjk5pmui
# oTQoRgJ9XgttMPatGdEXyF554EYcjDiNzdvG5bbCpq3PocIqbu9hY0o50ZaX/hMA
# kMP84LSER5oJvFgZBTH6W9pTwRxRJgjg4AeAMXX7vCdNY/UDtbcI/imByEn35Jim
# 57sz8nfmyn57YeG6NG2/pSSP29teVs50PkX/Tt7kv5Jk20nF36FTqFi5LmQ=
# SIG # End signature block
