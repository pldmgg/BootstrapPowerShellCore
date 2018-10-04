function InstallLinuxPackage {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$True)]
        [string[]]$PossiblePackageNames,

        [Parameter(Mandatory=$True)]
        [string]$CommandName
    )

    if (!$(command -v $CommandName)) {
        foreach ($PackageName in $PossiblePackageNames) {
            if ($(command -v pacman)) {
                $null = pacman -S $PackageName --noconfirm *> $null
            }
            elseif ($(command -v yum)) {
                $null = yum -y install $PackageName *> $null
            }
            elseif ($(command -v dnf)) {
                $null = dnf -y install $PackageName *> $null
            }
            elseif ($(command -v apt)) {
                $null = apt -y install $PackageName *> $null
            }
            elseif ($(command -v zypper)) {
                $null = zypper install $PackageName --non-interactive *> $null
            }

            if ($(command -v $CommandName)) {
                break
            }
        }

        if (!$(command -v $CommandName)) {
            Write-Error "Unable to find the command $CommandName! Install unsuccessful! Halting!"
            $global:FunctionResult = "1"
            return
        }
        else {
            Write-Host "$PackageName was successfully installed!" -ForegroundColor Green
        }
    }
    else {
        Write-Warning "The command $CommandName is already available!"
        return
    }
}
