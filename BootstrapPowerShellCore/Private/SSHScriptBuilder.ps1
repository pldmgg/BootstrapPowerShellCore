function SSHScriptBuilder {
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
        [string]$LocalPassword,

        [Parameter(
            Mandatory=$False,
            ParameterSetName='Domain'
        )]
        [string]$DomainPassword,

        [Parameter(Mandatory=$False)]
        [string]$KeyFilePath,

        [Parameter(Mandatory=$False)]
        [System.Collections.ArrayList]$SSHScriptArray, # NOTE: $SSHScriptArray will ALWAYS be run BEFORE $ElevatedSSHScriptArray

        [Parameter(Mandatory=$False)]
        [System.Collections.ArrayList]$ElevatedSSHScriptArray, # NOTE: $SSHScriptArray will ALWAYS be run BEFORE $ElevatedSSHScriptArray

        [Parameter(Mandatory=$False)]
        [string]$ScriptCompleteFlag, # This should be a regex string

        [Parameter(Mandatory=$False)]
        [int]$PotentialAdditionalPwdPrompts,

        [Parameter(Mandatory=$False)]
        [int]$PwdPromptTimeoutMin = 10,

        [Parameter(Mandatory=$False)]
        [int]$PwdPromptDelaySeconds,

        [Parameter(Mandatory=$False)]
        [float]$WindowsWaitTimeMin = 2,

        [Parameter(Mandatory=$False)]
        [switch]$WindowsTarget
    )

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
        '-t'
    )
    if ($KeyFilePath) {
        $null = $SSHCmdStringArray.Add("-i")
        $null = $SSHCmdStringArray.Add('"' + $KeyFilePath + '"')
    }
    if ($LocalUserName) {
        $null = $SSHCmdStringArray.Add("$FullUserName@$HostNameValue")
    }
    if ($DomainUserName) {
        $null = $SSHCmdStringArray.Add("$FullUserName@$DomainNameShort@$HostNameValue")
    }
    
    if ($SSHScriptArray) {
        [System.Collections.ArrayList][array]$AwaitScriptArray = @($SSHScriptArray) | foreach {
            $FinalLine = $_ -replace [regex]::Escape('\'),'\\'
            $FinalLine = $FinalLine -replace [regex]::Escape('$'),'\`$'
            $FinalLine = $FinalLine -replace [regex]::Escape('"'),'\`"\`"'
            if ($FinalLine -match 'sed.*subsystemline') {
                $FinalLine = $FinalLine -replace [regex]::Escape('\`"\`"'),'\\\`"'
            }
            $FinalLine
        }
        #$AwaitScriptArray.Insert($($AwaitScriptArray.Count-1),"echo $ScriptCompleteFlag")
        #$null = $AwaitScriptArray.Add("echo $ScriptCompleteFlag")
        $FinalAwaitScript = $AwaitScriptArray -join "; "
        
        [System.Collections.ArrayList][array]$ExpectScriptArray = @($SSHScriptArray) | foreach {
            $FinalLine = $_ -replace [regex]::Escape('\'),'\\\'
            $FinalLine = $FinalLine -replace [regex]::Escape('$'),'\\\$'
            $FinalLine = $FinalLine -replace [regex]::Escape('"'),'\\\"'
            #$FinalLine = $FinalLine -replace [regex]::Escape('\n'),'\\\n"'
            $FinalLine = $FinalLine -replace [regex]::Escape('['),'\['
            $FinalLine = $FinalLine -replace [regex]::Escape(']'),'\]'
            $FinalLine
        }
        #$null = $ExpectScriptArray.Add("echo $ScriptCompleteFlag")
        # No need for $FinalExpectScript, because we loop through the $ExpectScriptArray to send each command one at a time
    }

    if ($ElevatedSSHScriptArray) {
        [System.Collections.ArrayList][array]$ElevatedAwaitScriptArray = @($ElevatedSSHScriptArray) | foreach {
            $FinalLine = $_ -replace [regex]::Escape('\'),'\\'
            $FinalLine = $FinalLine -replace [regex]::Escape('$'),'\`$'
            $FinalLine = $FinalLine -replace [regex]::Escape('"'),'\`"\`"'
            if ($FinalLine -match 'sed.*subsystemline') {
                $FinalLine = $FinalLine -replace [regex]::Escape('\`"\`"'),'\\\`"'
            }
            $FinalLine
        }
        #$ElevatedAwaitScriptArray.Insert($($ElevatedAwaitScriptArray.Count-1),"echo $ScriptCompleteFlag")
        #$null = $ElevatedAwaitScriptArray.Add("echo $ScriptCompleteFlag")
        $FinalElevatedAwaitScript = $ElevatedAwaitScriptArray -join "; "
        
        [System.Collections.ArrayList][array]$ElevatedExpectScriptArray = @($ElevatedSSHScriptArray) | foreach {
            $FinalLine = $_ -replace [regex]::Escape('\'),'\\\'
            $FinalLine = $FinalLine -replace [regex]::Escape('$'),'\\\$'
            $FinalLine = $FinalLine -replace [regex]::Escape('"'),'\\\"'
            #$FinalLine = $FinalLine -replace [regex]::Escape('\n'),'\\\n"'
            $FinalLine = $FinalLine -replace [regex]::Escape('['),'\['
            $FinalLine = $FinalLine -replace [regex]::Escape(']'),'\]'
            $FinalLine
        }
        #$null = $ExpectScriptArray.Add("echo $ScriptCompleteFlag")
        # No need for $FinalElevatedExpectScript, because we loop through the $ExpectScriptArray to send each command one at a time
    }

    if (!$PSVersionTable.Platform -or $PSVersionTable.Platform -eq "Win32NT") {
        if (!$WindowsTarget) {
            if ($SSHScriptArray -and !$ElevatedSSHScriptArray) {
                $SSHCmdString = $($SSHCmdStringArray -join " ") + ' ' + '"bash -c \`"' + $FinalAwaitScript + '\`""'
            }
            if (!$SSHScriptArray -and $ElevatedSSHScriptArray) {
                $SSHCmdString = $($SSHCmdStringArray -join " ") + ' ' + '"sudo bash -c \`"' + $FinalElevatedAwaitScript + '\`""'
            }
            if ($SSHScriptArray -and $ElevatedSSHScriptArray) {
                $SSHCmdString = $($SSHCmdStringArray -join " ") + ' ' + '"bash -c \`"' + $FinalAwaitScript + '\`"; ' +
                'sudo bash -c \`"' + $FinalElevatedAwaitScript + '\`""'
            }
        }
        else {
            $SSHCmdString = $($SSHCmdStringArray -join " ") + ' ' +  '"' + $FinalAwaitScript + '"'
        }

        Write-Host "`$SSHCmdString is:`n    $SSHCmdString"

        #region >> Await Attempt Number 1 of 2
        
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
        while (![bool]$($($CheckForExpectedResponses -split "`n") -match [regex]::Escape("Are you sure you want to continue connecting (yes/no)?")) -and
        ![bool]$($($CheckForExpectedResponses -split "`n") -match "assword.*:") -and 
        ![bool]$($($CheckForExpectedResponses -split "`n") -match $ScriptCompleteFlag) -and $Counter -le 30
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
                        $Counter = 0
                        while ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue) -and $Counter -le 15) {
                            Write-Verbose "Waiting for Await Module Process Id $($PSAwaitProcess.Id) to end..."
                            Start-Sleep -Seconds 1
                            $Counter++
                        }
                    }
                }
                $PSAwaitProcess = $null
            }
        }

        #endregion >> Await Attempt 1 of 2

        $CheckResponsesOutput = $CheckForExpectedResponses | foreach {$_ -split "`n"}
            
        #region >> Await Attempt 2 of 2
        
        # If $CheckResponsesOutput contains the string "must be greater than zero", then something broke with the Await Module.
        # Most of the time, just trying again resolves any issues
        if ($CheckResponsesOutput -match "must be greater than zero" -or @($CheckResponsesOutput)[-1] -notmatch "[a-zA-Z]" -or
        $CheckResponsesOutput -match "background process reported an error") {
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
            while (![bool]$($SuccessOrAcceptHostKeyOrPwdPrompt -match [regex]::Escape("Are you sure you want to continue connecting (yes/no)?")) -and
            ![bool]$($SuccessOrAcceptHostKeyOrPwdPrompt -match "assword.*:") -and 
            ![bool]$($SuccessOrAcceptHostKeyOrPwdPrompt -match $ScriptCompleteFlag) -and $Counter -le 30
            ) {
                $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse
                $null = $CheckForExpectedResponses.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                Start-Sleep -Seconds 1
                $Counter++
            }
            if ($Counter -eq 31) {
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
        if ($CheckResponsesOutput -match "must be greater than zero" -or @($CheckResponsesOutput)[-1] -notmatch "[a-zA-Z]" -or
        $CheckResponsesOutput -match "background process reported an error") {
            if ($CheckResponsesOutput -match "must be greater than zero" -or @($CheckResponsesOutput)[-1] -notmatch "[a-zA-Z]") {
                Write-Error "Something went wrong with the PowerShell Await Module! Halting!"
            }
            if ($CheckResponsesOutput -match "background process reported an error") {
                Write-Error "Please check your credentials! Halting!"
            }
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
            while (![bool]$($($CheckExpectedSendYesOutput -split "`n") -match "assword.*:") -and 
            ![bool]$($($CheckExpectedSendYesOutput -split "`n") -match $ScriptCompleteFlag) -and $Counter -le 30
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
            
            # This will handle EITHER the ssh login password prompt OR the sudo prompt (neither of which are guaranteed to happen)
            if ($CheckSendYesOutput -match "assword.*:") {
                if ($LocalPassword) {
                    $null = Send-AwaitCommand $LocalPassword
                }
                if ($DomainPassword) {
                    $null = Send-AwaitCommand $DomainPassword
                }
                Start-Sleep -Seconds 3

                if ($PwdPromptDelaySeconds) {
                    Start-Sleep -Seconds $PwdPromptDelaySeconds
                }

                $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse

                if (!$SSHOutputPrep) {
                    [System.Collections.ArrayList]$script:SSHOutputPrep = @()
                    if (![System.String]::IsNullOrWhiteSpace($SuccessOrAcceptHostKeyOrPwdPrompt)) {
                        $null = $SSHOutputPrep.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                    }
                }
                $Counter = 0
                $PwdPromptTimeoutSeconds = $PwdPromptTimeoutMin*60
                $CounterLimit = $PwdPromptTimeoutSeconds/10
                while (![bool]$($($SSHOutputPrep -split "`n") -match "assword.*:") -and 
                ![bool]$($($SSHOutputPrep -split "`n") -match $ScriptCompleteFlag) -and $Counter -le $CounterLimit) {
                    $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse
                    if (![System.String]::IsNullOrWhiteSpace($SuccessOrAcceptHostKeyOrPwdPrompt)) {
                        $null = $SSHOutputPrep.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                    }
                    Start-Sleep -Seconds 10
                    $Counter++
                }
                if ($Counter -eq $($CounterLimit+1)) {
                    Write-Verbose "Sending the user's password timed out!"

                    #$SSHOutputPrep

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
                
                # This will handle EITHER the sudo prompt or another generic password prompt (neither of which are guaranteed to happen)
                if ($SuccessOrAcceptHostKeyOrPwdPrompt -match "assword.*:" -or @($($SSHOutputPrep -split "`n"))[-1] -match "assword.*:") {
                    if ($LocalPassword) {
                        $null = Send-AwaitCommand $LocalPassword
                    }
                    if ($DomainPassword) {
                        $null = Send-AwaitCommand $DomainPassword
                    }
                    Start-Sleep -Seconds 3

                    if ($PwdPromptDelaySeconds) {
                        Start-Sleep -Seconds $PwdPromptDelaySeconds
                    }
    
                    $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse

                    if (!$SSHOutputPrep) {
                        [System.Collections.ArrayList]$script:SSHOutputPrep = @()
                        if (![System.String]::IsNullOrWhiteSpace($SuccessOrAcceptHostKeyOrPwdPrompt)) {
                            $null = $SSHOutputPrep.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                        }
                    }
                    $Counter = 0
                    $PwdPromptTimeoutSeconds = $PwdPromptTimeoutMin*60
                    $CounterLimit = $PwdPromptTimeoutSeconds/10
                    while (![bool]$($($SSHOutputPrep -split "`n") -match "assword.*:") -and 
                    ![bool]$($($SSHOutputPrep -split "`n") -match $ScriptCompleteFlag) -and $Counter -le $CounterLimit) {
                        $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse
                        if (![System.String]::IsNullOrWhiteSpace($SuccessOrAcceptHostKeyOrPwdPrompt)) {
                            $null = $SSHOutputPrep.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                        }
                        Start-Sleep -Seconds 10
                        $Counter++
                    }
                    if ($Counter -eq $($CounterLimit+1)) {
                        Write-Verbose "Sending the user's password timed out!"

                        #$SSHOutputPrep

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

                    # We need this extra if block for MacOS because there is one more Password prompt
                    if ($SuccessOrAcceptHostKeyOrPwdPrompt -match "assword.*:" -or @($($SSHOutputPrep -split "`n"))[-1] -match "assword.*:") {
                        if ($LocalPassword) {
                            $null = Send-AwaitCommand $LocalPassword
                        }
                        if ($DomainPassword) {
                            $null = Send-AwaitCommand $DomainPassword
                        }
                        Start-Sleep -Seconds 3

                        if ($PwdPromptDelaySeconds) {
                            Start-Sleep -Seconds $PwdPromptDelaySeconds
                        }
        
                        $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse
        
                        if (!$SSHOutputPrep) {
                            [System.Collections.ArrayList]$script:SSHOutputPrep = @()
                            if (![System.String]::IsNullOrWhiteSpace($SuccessOrAcceptHostKeyOrPwdPrompt)) {
                                $null = $SSHOutputPrep.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                            }
                        }
                        $Counter = 0
                        $PwdPromptTimeoutSeconds = $PwdPromptTimeoutMin*60
                        $CounterLimit = $PwdPromptTimeoutSeconds/10
                        while (![bool]$($($SSHOutputPrep -split "`n") -match "assword.*:") -and 
                        ![bool]$($($SSHOutputPrep -split "`n") -match $ScriptCompleteFlag) -and $Counter -le $CounterLimit) {
                            $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse
                            if (![System.String]::IsNullOrWhiteSpace($SuccessOrAcceptHostKeyOrPwdPrompt)) {
                                $null = $SSHOutputPrep.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                            }
                            Start-Sleep -Seconds 10
                            $Counter++
                        }
                        if ($Counter -eq $($CounterLimit+1)) {
                            Write-Verbose "Sending the user's password timed out!"
        
                            #$SSHOutputPrep
        
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
                    }
                }
            }
            else {
                $SSHOutputPrep = $($CheckSendYesOutput | Out-String) -split "`n"
            }
        }
        elseif ($CheckResponsesOutput -match "assword.*:") {
            if ($LocalPassword) {
                $null = Send-AwaitCommand $LocalPassword
            }
            if ($DomainPassword) {
                $null = Send-AwaitCommand $DomainPassword
            }
            Start-Sleep -Seconds 3

            if ($PwdPromptDelaySeconds) {
                Start-Sleep -Seconds $PwdPromptDelaySeconds
            }

            $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse

            if (!$SSHOutputPrep) {
                [System.Collections.ArrayList]$script:SSHOutputPrep = @()
                if (![System.String]::IsNullOrWhiteSpace($SuccessOrAcceptHostKeyOrPwdPrompt)) {
                    $null = $SSHOutputPrep.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                }
            }
            $Counter = 0
            $PwdPromptTimeoutSeconds = $PwdPromptTimeoutMin*60
            $CounterLimit = $PwdPromptTimeoutSeconds/10
            while (![bool]$($($SSHOutputPrep -split "`n") -match "assword.*:") -and 
            ![bool]$($($SSHOutputPrep -split "`n") -match $ScriptCompleteFlag) -and $Counter -le $CounterLimit) {
                $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse
                if (![System.String]::IsNullOrWhiteSpace($SuccessOrAcceptHostKeyOrPwdPrompt)) {
                    $null = $SSHOutputPrep.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                }
                Start-Sleep -Seconds 10
                $Counter++
            }
            if ($Counter -eq $($CounterLimit+1)) {
                Write-Verbose "Sending the user's password timed out!"

                #$SSHOutputPrep

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

            #Write-Host "`$SuccessOrAcceptHostKeyOrPwdPrompt is:`n$SuccessOrAcceptHostKeyOrPwdPrompt" -ForegroundColor Yellow
            #Write-Host "`$SSHOutputPrep is:`n$SSHOutputPrep" -ForegroundColor Yellow

            #$SuccessOrAcceptHostKeyOrPwdPrompt | Export-CliXml "$HOME\SuccessOrAcceptHostKeyOrPwdPrompt.xml"
            #$SSHOutputPrep | Export-CliXml "$HOME\SSHOutputPrep.xml"
            
            # This will handle EITHER the sudo prompt or another generic password prompt (neither of which are guaranteed to happen)
            if ($SuccessOrAcceptHostKeyOrPwdPrompt -match "assword.*:" -or @($($SSHOutputPrep -split "`n"))[-1] -match "assword.*:") {
                if ($LocalPassword) {
                    $null = Send-AwaitCommand $LocalPassword
                }
                if ($DomainPassword) {
                    $null = Send-AwaitCommand $DomainPassword
                }
                Start-Sleep -Seconds 3

                if ($PwdPromptDelaySeconds) {
                    Start-Sleep -Seconds $PwdPromptDelaySeconds
                }

                $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse

                if (!$SSHOutputPrep) {
                    [System.Collections.ArrayList]$script:SSHOutputPrep = @()
                    if (![System.String]::IsNullOrWhiteSpace($SuccessOrAcceptHostKeyOrPwdPrompt)) {
                        $null = $SSHOutputPrep.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                    }
                }
                $Counter = 0
                $PwdPromptTimeoutSeconds = $PwdPromptTimeoutMin*60
                $CounterLimit = $PwdPromptTimeoutSeconds/10
                while (![bool]$($($SSHOutputPrep -split "`n") -match "assword.*:") -and 
                ![bool]$($($SSHOutputPrep -split "`n") -match $ScriptCompleteFlag) -and $Counter -le $CounterLimit) {
                    $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse
                    if (![System.String]::IsNullOrWhiteSpace($SuccessOrAcceptHostKeyOrPwdPrompt)) {
                        $null = $SSHOutputPrep.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                    }
                    Start-Sleep -Seconds 10
                    $Counter++
                }
                if ($Counter -eq $($CounterLimit+1)) {
                    Write-Verbose "Sending the user's password timed out!"

                    #$SSHOutputPrep

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

                #Write-Host "`$SuccessOrAcceptHostKeyOrPwdPrompt is:`n$SuccessOrAcceptHostKeyOrPwdPrompt" -ForegroundColor Yellow
                #Write-Host "`$SSHOutputPrep is:`n$SSHOutputPrep" -ForegroundColor Yellow

                #$SuccessOrAcceptHostKeyOrPwdPrompt | Export-CliXml "$HOME\SuccessOrAcceptHostKeyOrPwdPrompt2.xml"
                #$SSHOutputPrep | Export-CliXml "$HOME\SSHOutputPrep2.xml"

                # We need this extra if block for MacOS because there is one moe Password prompt
                if ($SuccessOrAcceptHostKeyOrPwdPrompt -match "assword.*:" -or @($($SSHOutputPrep -split "`n"))[-1] -match "assword.*:") {
                    if ($LocalPassword) {
                        $null = Send-AwaitCommand $LocalPassword
                    }
                    if ($DomainPassword) {
                        $null = Send-AwaitCommand $DomainPassword
                    }
                    Start-Sleep -Seconds 3

                    if ($PwdPromptDelaySeconds) {
                        Start-Sleep -Seconds $PwdPromptDelaySeconds
                    }
    
                    $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse
    
                    if (!$SSHOutputPrep) {
                        [System.Collections.ArrayList]$script:SSHOutputPrep = @()
                        if (![System.String]::IsNullOrWhiteSpace($SuccessOrAcceptHostKeyOrPwdPrompt)) {
                            $null = $SSHOutputPrep.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                        }
                    }
                    $Counter = 0
                    $PwdPromptTimeoutSeconds = $PwdPromptTimeoutMin*60
                    $CounterLimit = $PwdPromptTimeoutSeconds/10
                    while (![bool]$($($SSHOutputPrep -split "`n") -match "assword.*:") -and 
                    ![bool]$($($SSHOutputPrep -split "`n") -match $ScriptCompleteFlag) -and $Counter -le $CounterLimit) {
                        $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse
                        if (![System.String]::IsNullOrWhiteSpace($SuccessOrAcceptHostKeyOrPwdPrompt)) {
                            $null = $SSHOutputPrep.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                        }
                        Start-Sleep -Seconds 10
                        $Counter++
                    }
                    if ($Counter -eq $($CounterLimit+1)) {
                        Write-Verbose "Sending the user's password timed out!"
    
                        #$SSHOutputPrep
    
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
                }
            }
        }
        else {
            $SSHOutputPrep = $($CheckResponsesOutput | Out-String) -split "`n"
        }

        Write-Host "Waiting for up to $WindowsWaitTimeMin minutes for operation to finish..."
        Start-Sleep -Seconds $($WindowsWaitTimeMin*60)

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
        elseif (![bool]$($SSHOutputPrep -match $ScriptCompleteFlag)) {
            $TentativeResult = "ReviewAllOutput"
        }
        else {
            $TentativeResult = "Success"
        }

        $FinalOutput = [pscustomobject]@{
            TentativeResult         = $TentativeResult
            AllOutput               = $SSHOutputPrep
        }
    }

    if ($PSVersionTable.Platform -eq "Unix") {
        $FinalPassword = if ($DomainPassword) {$DomainPassword} else {$LocalPassword}
        #$FinalPassword = $FinalPassword -replace [regex]::Escape('$'),'\\\$' -replace [regex]::Escape('"'),'\\\"'

        if ($SSHScriptArray -and $ElevatedSSHScriptArray) {
            $ScriptA = $ExpectScriptArray | foreach {
                if ($_ -match "brew cask reinstall powershell") {
                    $SendLine = $_ -replace ' && echo powershellInstallComplete',''
                    $ExpectPwdPrompt = @(
                        "send -- \`"$SendLine\r\`""
                        'expect {'
                        '    -re \".*assword.*:\" {'
                        '        send -- \"\$password\r\"'
                        '        exp_continue'
                        '    }'
                        '    -re \"was successfully installed!\" {'
                        '        send -- \"echo powershellInstallComplete\r\"'
                        '        expect \"*\"'
                        '    }'
                        '}'
                    )
                    $ExpectPwdPrompt -join "`n"
                }
                elseif ($_ -match "powershellInstallComplete") {
                    'send -- \"' + $_ + '\r\"' + "`n" + $('expect \"*{0}*\"' -f 'powershellInstallComplete')
                }
                elseif ($_ -match 'pwshConfigComplete') {
                    'send -- \"' + $_ + '\r\"' + "`n" + $('expect \"*{0}*\"' -f 'pwshConfigComplete')
                }
                else {
                    'send -- \"' + $_ + '\r\"' + "`n" + 'expect -re \"$prompt\"'
                }
            }

            $ScriptB = $ElevatedExpectScriptArray | foreach {
                if ($_ -match "powershellInstallComplete") {
                    'send -- \"' + $_ + '\r\"' + "`n" + $('expect \"*{0}*\"' -f 'powershellInstallComplete')
                }
                elseif ($_ -match 'pwshConfigComplete') {
                    'send -- \"' + $_ + '\r\"' + "`n" + $('expect \"*{0}*\"' -f 'pwshConfigComplete')
                }
                else {
                    'send -- \"' + $_ + '\r\"' + "`n" + 'expect -re \"$prompt\"'
                }
            }
        }
        if (!$SSHScriptArray -and $ElevatedSSHScriptArray) {
            $ScriptB = $ElevatedExpectScriptArray | foreach {
                if ($_ -match "powershellInstallComplete") {
                    'send -- \"' + $_ + '\r\"' + "`n" + $('expect \"*{0}*\"' -f 'powershellInstallComplete')
                }
                elseif ($_ -match 'pwshConfigComplete') {
                    'send -- \"' + $_ + '\r\"' + "`n" + $('expect \"*{0}*\"' -f 'pwshConfigComplete')
                }
                else {
                    'send -- \"' + $_ + '\r\"' + "`n" + 'expect -re \"$prompt\"'
                }
            }
        }
        if ($SSHScriptArray -and !$ElevatedSSHScriptArray) {
            $ScriptA = $ExpectScriptArray | foreach {
                if ($_ -match "brew cask reinstall powershell") {
                    $SendLine = $_ -replace ' && echo powershellInstallComplete',''
                    $ExpectPwdPrompt = @(
                        "send -- \`"$SendLine\r\`""
                        'expect {'
                        '    -re \".*assword.*:\" {'
                        '        send -- \"\$password\r\"'
                        '        exp_continue'
                        '    }'
                        '    -re \"was successfully installed!\" {'
                        '        send -- \"echo powershellInstallComplete\r\"'
                        '        expect \"*\"'
                        '    }'
                        '}'
                    )
                    $ExpectPwdPrompt -join "`n"
                }
                elseif ($_ -match "powershellInstallComplete") {
                    'send -- \"' + $_ + '\r\"' + "`n" + $('expect \"*{0}*\"' -f 'powershellInstallComplete')
                }
                elseif ($_ -match 'pwshConfigComplete') {
                    'send -- \"' + $_ + '\r\"' + "`n" + $('expect \"*{0}*\"' -f 'pwshConfigComplete')
                }
                else {
                    'send -- \"' + $_ + '\r\"' + "`n" + 'expect -re \"$prompt\"'
                }
            }
        }

        [System.Collections.ArrayList]$ExpectScriptPrep = @(
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
        )
        if ($ScriptA) {
            $ScriptA | foreach {
                $null = $ExpectScriptPrep.Add($_)
            }
        }
        if ($ScriptB) {
            $null = $ExpectScriptPrep.Add('send -- \"sudo su\r\"')
            $null = $ExpectScriptPrep.Add('expect {')
            $null = $ExpectScriptPrep.Add('    -re \".*assword.*:\" {')
            $null = $ExpectScriptPrep.Add('        send -- \"\$password\r\"')
            $null = $ExpectScriptPrep.Add('        exp_continue')
            $null = $ExpectScriptPrep.Add('    }')
            $null = $ExpectScriptPrep.Add('    -re \"\$prompt\" {')
            $null = $ExpectScriptPrep.Add('        send -- \"echo StartSudoersUpdate\r\"')
            $null = $ExpectScriptPrep.Add('        expect \"StartSudoersUpdate\"')
            $null = $ExpectScriptPrep.Add('    }')
            $null = $ExpectScriptPrep.Add('}')
            $ScriptB | foreach {
                $null = $ExpectScriptPrep.Add($_)
            }
            $null = $ExpectScriptPrep.Add('send -- \"exit\r\"')
            $null = $ExpectScriptPrep.Add('expect -re \"\$prompt\"')
            $null = $ExpectScriptPrep.Add('send -- \"exit\r\"')
            $null = $ExpectScriptPrep.Add('expect eof')
            $null = $ExpectScriptPrep.Add('EOF')
        }
        else {
            $null = $ExpectScriptPrep.Add('send -- \"exit\r\"')
            $null = $ExpectScriptPrep.Add('expect eof')
            $null = $ExpectScriptPrep.Add('EOF')
        }
        $ExpectScript = $ExpectScriptPrep -join "`n"

        #Write-Host "`$ExpectScript is:`n$ExpectScript"
        #$ExpectScript | Export-CliXml "$HOME/ExpectScript2.xml"
        
        # The below $ExpectOutput is an array of strings
        $ExpectOutput = bash -c "$ExpectScript"

        # NOTE: The below -replace regex string removes garbage escape sequences like: [116;1H
        #$SSHOutputPrep = $ExpectOutput -replace "\e\[(\d+;)*(\d+)?[ABCDHJKfmsu]",""
        $SSHOutputPrep = $ExpectOutput

        if (!$SSHOutputPrep) {
            $TentativeResult = "ManualVerificationRequired"
        }
        elseif (![bool]$($SSHOutputPrep -match $ScriptCompleteFlag)) {
            $TentativeResult = "ReviewAllOutput"
        }
        else {
            $TentativeResult = "Success"
        }

        $FinalOutput = [pscustomobject]@{
            TentativeResult         = $TentativeResult
            AllOutput               = $SSHOutputPrep
        }
    }

    $FinalOutput
}

# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUwAqWzI8gGoSTwiHea0E+doBK
# xjigggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFD4dFcEFHmjufd0C
# 3qz+TbtAvM0jMA0GCSqGSIb3DQEBAQUABIIBAH5GXGXYF737sU7lSzPu+pYErXMe
# V8eXoP52/z0hFvUAbjYiG/t4NulXHx5pQIuF7PcDZ5Byu/1lpv6N1vtKnXrW4aHP
# RHOHr1SaKOdR9/TqcyXZbMj8rDhQwsqYuQbII3SDav3D8CQc82bfPeBNBby6NbpS
# Mhar579AcToWSryVGYhRwZ6qgsyt727IoDMNoJdP8AAhFF+/+w68bYm3GQ/1OupL
# 3a8V5nV9wf9ud92NdV0S0BEu8Pf3xQ5B3IckLQ1/2nVorDevjRnmgRG4V/LeH5O2
# 2v9ZvT7bkLb98wJQgbwdf+rzIijMttKkW0eFvOeYOqAa9bgEgcWwE3PUH0o=
# SIG # End signature block
