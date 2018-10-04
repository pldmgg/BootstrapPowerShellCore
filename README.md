[![Build status](https://ci.appveyor.com/api/projects/status/github/pldmgg/BootstrapPowerShellCore?branch=master&svg=true)](https://ci.appveyor.com/project/pldmgg/BootstrapPowerShellCore/branch/master)


# BootstrapPowerShellCore
This Module allows you to install PowerShell Core on a Remote Host and optionally configure pwsh for PSRemoting. The only requirement is that you have ssh available on your local workstation. (See my [WinSSH Module](https://github.com/pldmgg/WinSSH) if you would like an easy way to install/configure OpenSSH on Windows)

The target Remote Host can be (almost) any Operating System mentioned in Microsoft's official documentation (with the exception of MacOS): https://docs.microsoft.com/en-us/powershell/scripting/setup/installing-powershell?view=powershell-6

The Module itself can be installed and imported using Windows PowerShell 5.1 or and Powershell Core 6.X (Windows or Linux).

I will eventually add support for targeting MacOS.

## Getting Started

```powershell
# One time setup
    # Download the repository
    # Unblock the zip
    # Extract the BootstrapPowerShellCore folder to a module path (e.g. $env:USERPROFILE\Documents\WindowsPowerShell\Modules\)
# Or, with PowerShell 5 or later or PowerShellGet:
    Install-Module BootstrapPowerShellCore

# Import the module.
    Import-Module BootstrapPowerShellCore    # Alternatively, Import-Module <PathToModuleFolder>

# Get commands in the module
    Get-Command -Module BootstrapPowerShellCore

# Get help
    Get-Help <BootstrapPowerShellCore Function> -Full
    Get-Help about_BootstrapPowerShellCore
```

## Examples

### Scenario 1: Install pwsh on Remote Host

```powershell
$BootstrapPwshSplatParams = @{
    RemoteHostNameOrIP      = "zerowin16sshb"
    DomainUserNameSS        = "zero\zeroadmin"
    DomainPasswordSS        = $(Read-Host -Prompt "Enter password" -AsSecureString)
}
Bootstrap-PowerShellCore @BootstrapPwshSplatParams
```

### Scenario 2: Install pwsh AND configure sshd_config for PSRemoting...

```powershell
$BootstrapPwshSplatParams = @{
    RemoteHostNameOrIP      = "centos7nodomain"
    LocalUserNameSS         = "centos7nodomain\vagrant"
    LocalPasswordSS         = $(Read-Host -Prompt "Enter password" -AsSecureString)
    ConfigurePSRemoting     = $True
}
Bootstrap-PowerShellCore @BootstrapPwshSplatParams
```

### Scenario 3: Install pwsh using the latest package from GitHub (as opposed to the Package Management system of the target OS)

```powershell
$BootstrapPwshSplatParams = @{
    RemoteHostNameOrIP      = "centos7nodomain"
    LocalUserNameSS         = "centos7nodomain\vagrant"
    LocalPasswordSS         = $(Read-Host -Prompt "Enter password" -AsSecureString)
    UsePackageManagement    = $False
}
Bootstrap-PowerShellCore @BootstrapPwshSplatParams
```

## Notes

* PSGallery: https://www.powershellgallery.com/packages/BootstrapPowerShellCore
