#Global Var for QC Function
$global:PasswordsDontMatch = $True
[securestring]$global:Password1 = $null
#[securestring]$Password2


function QC{
    param (
        [string]$ComputerName,
        [switch]$Shutdown,
        [switch]$RepairSCCM,
        [switch]$RepairAgent
        )
    <#
    Tests for the presence of 4 programs
    Runs the Fix CDP User Reg Edit
    Sets the Local Admin Password
    #>
    $ComputerName = $ComputerName.ToUpper()
    #test to see if computer is in Staging
    if((get-adcomputer -Identity $ComputerName | Select -ExpandProperty DistinguishedName) -match "Staging"){
        Write-Warning "Found $ComputerName in Staging. Please move into proper OU and prompt a Group Policy Update`n`tEnsure we are pre-staging objects!"
        return -1
    }

    switch(Test-Online -ComputerName $ComputerName){
        0{
            if($global:PasswordsDontMatch){ #Get the password if we haven't yet
                do{
                    $global:Password1 = Read-Host -AsSecureString "Enter The Admin Password to be assigned"
                    [securestring]$Password2 = Read-Host -AsSecureString "Confirm New Password"
                    $pwd1_text = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password1))
                    $pwd2_text = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password2))
    
                    if ($pwd1_text -ceq $pwd2_text){
                        Write-Host "Passwords Match."
                        $global:PasswordsDontMatch = $False
                    }else{
                        Write-Host "Passwords don't Match. Please try again."
                        $global:PasswordsDontMatch = $True
                    }
                }while($PasswordsDontMatch)
                Remove-Variable 'pwd1_text','pwd2_text','Password2'
            }
            
            [bool]$Continue = $False
            $BES = test-path "\\$ComputerName\C$\Program Files (x86)\BigFix Enterprise\BES Client\besclient.exe"
            $SCCM = test-path "\\$ComputerName\C$\Windows\CCM\ccmexec.exe"
            $Agent = test-path "\\$ComputerName\C$\Program Files\McAfee\Agent\macmnsvc.exe"
            $Activ = test-path "\\$ComputerName\C$\Program Files (x86)\HID Global\ActivClient\aicommapi.exe"

            If ($BES -and $SCCM -and $Agent -and $Activ){
                write-host "$ComputerName has all required software" -ForegroundColor Green
                $Continue = $true
            }else{
                write-host "BigFix:          $BES" -ForegroundColor Yellow
                write-host "Software Center: $SCCM" -ForegroundColor Yellow
                write-host "McAfee Agent:    $Agent" -ForegroundColor Yellow
                Write-Host "ActivClient:     $Activ" -ForegroundColor Yellow

                #Attempt to remediate any issues
                if(!$BES){
                    Write-Host "Installing BigFix Client" -ForegroundColor Red
                    New-Item -ItemType Directory -Path \\$ComputerName\C$\Software -ErrorAction SilentlyContinue
                    Copy-Item '\\nent95quanvs006\Quantico$\G6\07 - TMB\6 - RSM\Tech Profiles\Installers\BigFixInstaller' \\$ComputerName\C$\Software -Recurse -Force
                    Invoke-Command -ComputerName $ComputerName -ScriptBlock{
                        & C:\Software\BigFixInstaller\Setup.exe --% /s /v/qn
                    }
                }
                if(!$SCCM -or $RepairSCCM){
                    Write-Host "Installing SCCM" -ForegroundColor Red
                    try{
                        Write-Host "Copying Installation Files to $ComputerName"
                        new-item -path "\\$ComputerName\C$\Client" -itemtype Directory -Force
                        Copy-Item "\\ecss6921\client\" "\\$ComputerName\C$\" -Recurse -Force
                        write-host "Kicking Off Installation. If a previous installating exists it will be removed."
                
                        #Test to see if an old install exists
                        If(test-path \\$ComputerName\C$\Windows\ccmsetup\ccmsetup.exe){
                            #Old install exists. Call the old uninstaller
                            psexec \\$ComputerName C:\Windows\ccmsetup\ccmsetup.exe /uninstall
                            write-host "Waiting 1 min for Uninstall."
                            sleep 60
                            [bool]$sucessful = $false
                            do{
                                write-host "Checking to see if Uninstall was Sucessful"
                                $LogTail = Get-Content \\$ComputerName\C$\windows\ccmsetup\logs\ccmsetup.log -tail 2
                                Write-Host $LogTail #Debugging
                                $sucessful = [bool]($LogTail -like "*CcmSetup is exiting with return code 0*")
                                if(!$sucessful){
                                    if ($LogTail -like "*error code*"){
                                        Write-warning "Uninstall attempt failed. Will re-attempt using new media."
                                        Break
                                    }
                                    write-host "Uninstall still in progress - waiting 30 sec. before next check"
                                    sleep 30
                                }
                            }while(!$sucessful)
                        }
                        #previous install was either removed or no longer exists, install fresh copy
                        Write-Host "Beginning New Installation"
                        sleep 2
                        #create bat file on remote system
                        New-Item -ItemType File -Value "C:\Client\ccmsetup.exe /forceinstall" -Path \\$ComputerName\C$\Client\install.bat -Force | Out-Null
                        psexec \\$ComputerName C:\Client\install.bat #Call Bat File
                        #Write-Host "LastExitCode "$LASTEXITCODE #Debugging
                        if($LASTEXITCODE -notlike "0"){
                            Write-Warning "Installation attempt failed. Recommend manual uninstall/reinstall."
                            "$(Get-Date) - $ComputerName - Push SCCM Script failed. Error: PSExec Did not exit with 0 - $(whoami)" | Out-file '\\nent95quanvs006\Quantico$\G6\07 - TMB\6 - RSM\Tech Profiles\Logs\SCCM.log' -Append -Force
                            break
                        }
                        #write-host "Giving the Installer 2 Mins to work."
                        sleep 5
                        do{
                            $LogTail = Get-Content \\$ComputerName\C$\windows\ccmsetup\logs\ccmsetup.log -tail 1
                            Write-Host $LogTail #Debugging
                            $sucessful = [bool](($LogTail -like "*exiting with return code *") -or ($LogTail -like "*error code*") -or ($LogTail -match "Next retry in"))#This could be written better. Started out as a single elseif but then just kept growing with more conditions
                            if(!$sucessful){
                                write-host "Install still in progress - waiting 30 sec. before next check" -ForegroundColor Yellow
                                sleep 30
                            }elseif ($LogTail -like "*exiting with return code 0*"){
                                write-host "Install Successful. No Reboot Required" -ForegroundColor Green
                                "$(Get-Date) - $ComputerName - Push-SCCM Script Completed Successfully by $(whoami)" | Out-file '\\nent95quanvs006\Quantico$\G6\07 - TMB\6 - RSM\Tech Profiles\Logs\SCCM.log' -Append -Force
                            }elseif ($LogTail -like "*exiting with return code 7*"){
                                write-host "Install Successful. Reboot Required" -ForegroundColor Yellow
                                do{
                                    $Restart = Read-Host "Reboot Now? (y/n)"
                                }while($restart -notlike 'y' -and $restart -notlike 'n')
                                if ($restart -like 'y'){
                                    Restart-Computer -ComputerName $ComputerName -Force
                                    Write-Host "Restart command sent to $ComputerName" -ForegroundColor Green
                                }
                                "$(Get-Date) - $ComputerName - Push-SCCM Script Completed Successfully by $(whoami)" | Out-file '\\nent95quanvs006\Quantico$\G6\07 - TMB\6 - RSM\Tech Profiles\Logs\SCCM.log' -Append -Force
                            }elseif ($LogTail -like "*error code*"){
                                throw "Install Failed"
                                break
                            }elseif ($LogTail -match "Next retry in"){
                                write-warning "Install Failed. System has scheduled a retry in 2 hours, but it probably won't work"
                                throw "Install Delayed 120 Min"
                                break
                            }
                        }while(!$sucessful)
                    }catch{
                        "$(Get-Date) - $ComputerName - Push SCCM Script failed. Error: $_ - $(whoami)" | Out-file '\\nent95quanvs006\Quantico$\G6\07 - TMB\6 - RSM\Tech Profiles\Logs\SCCM.log' -Append -Force
                        if($_ -like "Install Failed"){
                            Write-Warning "The Installation Failed. Here is the last line of the Log: `n$LogTail"
                        }else{
                            Write-Warning "Failed: $_"
                        }
                    }
                }
                
                if(!$Agent -or $RepairAgent){
                    Write-Host "Attempting to install McAfee Agent" -ForegroundColor Red
                    new-item -ItemType Directory -Path \\$ComputerName\C$\Software -ErrorAction SilentlyContinue
                    Copy-Item '\\nent95quanvs006\Quantico$\G6\07 - TMB\6 - RSM\Tech Profiles\Installers\Agent.exe' \\$ComputerName\C$\Software -Force
                    psexec -s \\$ComputerName --% C:\Software\Agent.exe /ForceInstall /Install=Agent /Silent
                    Remove-Item \\$ComputerName\C$\Software -Recurse
                }
                if(!$Activ){
                    Write-Host "Attempting to install ActivClient" -ForegroundColor Red
                    New-item -ItemType Directory -Path \\$ComputerName\C$\Software -ErrorAction SilentlyContinue
                    Copy-Item '\\nent95quanvs006\Quantico$\G6\07 - TMB\6 - RSM\Tech Profiles\Installers\ActivClient' \\$ComputerName\C$\Software -Force -Recurse
                    Invoke-Command -ComputerName $ComputerName -ScriptBlock {& C:\Software\ActivClient\install.cmd}
                    Remove-Item \\$ComputerName\C$\Software -Recurse
                }
            }
            if ($Continue){
                try{
                    #check if the Software Folder Exists and create it if doesn't
                    if (!(test-path "\\$ComputerName\C$\Software")){
                        New-Item -ItemType Directory -Path "\\$ComputerName\C$\Software" -Force | Out-Null
                    }
                    #copy over reg file
                    Copy-Item '\\nent95quanvs006\QUANTICO$\G6\07 - TMB\6 - RSM\Tech Profiles\CPDU_Fix.reg' \\$ComputerName\C$\Software\
                    #execute reg file
                    psexec \\$ComputerName regedit.exe --% /S C:\Sofware\CPDU_Fix.reg
                    Write-Host "CPDUser Fix Applied" -ForegroundColor Green
                    Remove-Item \\$ComputerName\C$\Software\ -Recurse -ErrorAction SilentlyContinue
                }catch{
                    Write-Warning "$ComputerName Failed. Error: $_"
                }
                try{
                    $pwd1_text = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($global:Password1))
                    $account = [ADSI]("WinNT://$ComputerName/MCEDS-Admin,user")
                    $account.psbase.invoke("SetPassword",$pwd1_text)
                    Write-Host "Password Change completed successfully" -ForegroundColor Green
                }catch{
                    Write-Warning "Failed to Change the administrator password. Error: $_"
                }
                #set Power
                Invoke-Command -ComputerName $ComputerName -ScriptBlock{
                    &powercfg.exe -x standby-timeout-ac 0
                    &powercfg.exe -x hibernate-timeout-ac 0
                }

                #Set Site
                Invoke-WmiMethod -Namespace root\ccm -Class sms_client -Name setassignedsite -ArgumentList "MC1" -ComputerName $ComputerName | Out-Null
                Write-Host "Set Site to MC1" -ForegroundColor Green
                if($Continue -and $Shutdown){
                    Stop-Computer -ComputerName $ComputerName -Force
                    write-host "Shutdown Command sent to $ComputerName"
                }elseif($Continue){
                    Restart-Computer -ComputerName $ComputerName -Force
                    Write-Host "Restart Command sent to $ComputerName"
                }
            }
        }
    }
}