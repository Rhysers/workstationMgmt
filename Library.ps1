
$global:SCCMImported = $Null
Copy-Item '\\nent95kbazvs003\MCFPAC\3DMLG\CLB-3\Longboard 2018\H&S Company\S-6\3. Data Section\Scripts\QC.ps1' "$Env:USERPROFILE\Documents\WindowsPowerShell\QC.ps1" -force
Unblock-File "$Env:USERPROFILE\Documents\WindowsPowerShell\QC.ps1" -confirm:$false
Import-Module "$Env:USERPROFILE\Documents\WindowsPowerShell\QC.ps1" -ErrorAction SilentlyContinue
Copy-Item '\\nent95kbazvs003\MCFPAC\3DMLG\CLB-3\Longboard 2018\H&S Company\S-6\3. Data Section\Scripts\SCCMStatus.ps1' "$Env:USERPROFILE\Documents\WindowsPowerShell\SCCMStatus.ps1" -force
Unblock-File "$Env:USERPROFILE\Documents\WindowsPowerShell\SCCMStatus.ps1" -confirm:$false
Import-Module "$Env:USERPROFILE\Documents\WindowsPowerShell\SCCMStatus.ps1" -ErrorAction SilentlyContinue

function Import-SCCM{
    Try{
        Write-Host "Importing SCCM Module" -ForegroundColor Gray
        Import-Module "C:\Program Files (x86)\ConfigMgr\bin\ConfigurationManager\ConfigurationManager.psd1" -ErrorAction Stop
        Write-Host "Completed Importing SCCM Module" -ForegroundColor Gray
        $global:SCCMImported = $True
    }catch{
        Write-Warning "Unable to import the SCCM Module. Some functions will not work"
        $global:SCCMImported = $False
    }
}
function Help-Me{
write-host "
IF YOU NEED TO:                             " -NoNewline -ForegroundColor Yellow
write-host "TYPE THIS:" -ForegroundColor Cyan
Write-Host 'Fix the "CDPUserSVC" prompt:                ' -NoNewline -ForegroundColor Yellow
Write-Host "Fix-CDPUser <computerName>" -ForegroundColor Cyan
Write-Host "Open admin CMD Prompt:                      " -NoNewline -ForegroundColor Yellow
Write-Host "cmd" -ForegroundColor Cyan
Write-Host "Open SCCM as an admin:                      " -NoNewline -ForegroundColor Yellow
Write-Host "SCCM" -ForegroundColor Cyan
Write-Host "Restart BES Client on Remote Comp.:         " -NoNewline -ForegroundColor Yellow
Write-Host "Restart-BES <CompName>" -ForegroundColor Cyan
Write-Host "Get Programs on Remote Comp:                " -NoNewline -ForegroundColor Yellow
Write-Host "Get-RemoteProgram -ComputerName <CompName> -Software <name of Software> -Property <Comma Seperate Properties>" -ForegroundColor Cyan
Write-Host "Push the most up-to-date Flash:             " -NoNewline -ForegroundColor Yellow
Write-Host "Push-Flash <CompName>" -ForegroundColor Cyan
Write-Host "Push the most up-to-date Java:              " -NoNewline -ForegroundColor Yellow
Write-Host "Push-Java <CompName>" -ForegroundColor Cyan
Write-Host "Push the most up-to-date Adobe Reader:      " -NoNewline -ForegroundColor Yellow
Write-Host "Push-Reader <CompName>" -ForegroundColor Cyan
Write-Host "Push the SCCM Client                        " -NoNewline -ForegroundColor Yellow
Write-Host "Push-SCCM <ComputerName>" -ForegroundColor Cyan
Write-Host "Check the Version of Windows                " -NoNewline -ForegroundColor Yellow
Write-Host "Get-WinVersion <ComputerName>" -ForegroundColor Cyan
Write-Host "See how long a computer has been on.        " -NoNewline -ForegroundColor Yellow
Write-Host "Get-Uptime -ComputerName <ComputerName>" -ForegroundColor Cyan
Write-Host "Open Event Viewer                           " -NoNewline -ForegroundColor Yellow
Write-Host "EventViewer" -ForegroundColor Cyan
Write-Host "Open Remote Control Viewer                  " -NoNewline -ForegroundColor Yellow
Write-Host "RemoteAssist" -ForegroundColor Cyan
Write-Host "Retrieve a BitLocker Key                    " -NoNewline -ForegroundColor Yellow
Write-Host "Get-BitLockerKey <ComputerName>" -ForegroundColor Cyan
Write-Host "Check the Version of Flash Installed        " -NoNewline -ForegroundColor Yellow
Write-Host "Check-Flash <ComputerName>" -ForegroundColor Cyan
Write-Host "Check the Version of Java Installed         " -NoNewline -ForegroundColor Yellow
Write-Host "Check-Java <ComputerName>" -ForegroundColor Cyan
Write-Host "Get the Serial of a Remote Machine          " -NoNewline -ForegroundColor Yellow
Write-Host "Get-SerialNumber <ComputerName>" -ForegroundColor Cyan
Write-Host "Display this Help Menu                      " -NoNewline -ForegroundColor Yellow
Write-Host "Help-Me" -ForegroundColor Cyan
Write-Host "Get users currently logged onto a machine   " -NoNewline -ForegroundColor Yellow
Write-Host 'Get-RemoteLogonStatus <ComputerName>' -ForegroundColor Cyan
Write-Host "Re-Register the IE DLLs                     " -NoNewline -ForegroundColor Yellow
Write-Host 'Reset-IEProxy <ComputerName>' -ForegroundColor Cyan
Write-Host "Get the SCCM Primary Device(s) for a User   " -NoNewline -ForegroundColor Yellow
Write-Host 'Get-PrimaryDevice -UserName <user.name>' -ForegroundColor Cyan
Write-Host "Get the SCCM Primary User(s) for a Device   " -NoNewline -ForegroundColor Yellow
Write-Host 'Get-PrimaryUser -ComputerName <ComputerName>' -ForegroundColor Cyan
Write-Host "Rebuild a user profile on a remote machine  " -NoNewline -ForegroundColor Yellow
Write-Host 'Reset-Profile -ComputerName <ComputerName>' -ForegroundColor Cyan
Write-Host "Get MS Exchange Info for a user:            " -NoNewline -ForegroundColor Yellow
Write-Host "Get-Exchange <userName>" -ForegroundColor Cyan
Write-Host "Get LAPS Password for Computer:             " -NoNewline -ForegroundColor Yellow
Write-Host "Get-LAPS <ComputerName>" -ForegroundColor Cyan
Write-Host "QC A Freshly Imaged Computer:               " -NoNewline -ForegroundColor Yellow
Write-Host "QC <ComputerName>" -ForegroundColor Cyan
Write-Host "QC Several Computers at the same time:      " -NoNewline -ForegroundColor Yellow
Write-Host "QC-Many" -ForegroundColor Cyan
Write-Host "Check list of computers to see whats online:" -NoNewline -ForegroundColor Yellow
Write-Host "Ping-Sweep" -ForegroundColor Cyan
Write-Host "Change Permissions on a File/Folder:        " -NoNewline -ForegroundColor Yellow
Write-Host "Modify-Permissions -Path <Path> -TargetObject <MCDSUS\<User/Group>> -add/-remove -permissionlevel"  -ForegroundColor Cyan
Write-Host "Generate a list of Computer Names:          " -NoNewline -ForegroundColor Yellow
Write-Host 'Generate-Names -StartNumber <Number to start at> -NumberToMake <How many names you need> -Type <"L" or "D" (Default L)> -UIC <The Desired UIC (Default 00264)>' -ForegroundColor Cyan
Write-Host "Get status of SCCM Client(s)                " -NoNewline -ForegroundColor Yellow 
Write-Host 'Get-CCMExecStatus <ComputerName1>[,<ComputerName2>]' -ForegroundColor Cyan
Write-Host "Get the install date of Windows             " -NoNewline -ForegroundColor Yellow
Write-Host 'Get-WindowsInstallDate <ComputerName>' -ForegroundColor Cyan
Write-Host "Gracefully Uninstall All Java               " -NoNewline -ForegroundColor Yellow
Write-Host 'Uninstall-Java <ComputerName>' -ForegroundColor Cyan
Write-Host "Forcefully Uninstall All Java               " -NoNewline -ForegroundColor Yellow
Write-Host 'Destroy-Java <ComputerName>' -ForegroundColor Cyan
Write-Host "Gracefully Uninstall PAPI Flash             " -NoNewline -ForegroundColor Yellow
Write-Host 'Uninstall-Flash <ComputerName>' -ForegroundColor Cyan
Write-Host "Forcefully Uninstall PAPI Flash             " -NoNewline -ForegroundColor Yellow
Write-Host 'Destroy-Flash <ComputerName>' -ForegroundColor Cyan
}
function helpme{help-me}

function Hidden-Functions{
Write-Host "Open the McAfee Console (Disable OnAccess)   " -NoNewline -ForegroundColor Yellow
Write-Host 'VirusScanConsole' -ForegroundColor Cyan
Write-Host "Open the Fixlet Debugger                     " -NoNewline -ForegroundColor Yellow
Write-Host 'FixletDebugger' -ForegroundColor Cyan
Write-Host "Deep Clean the WMI Repository                " -NoNewline -ForegroundColor Yellow
Write-Host 'Deep-Clean <ComputerName>' -ForegroundColor Cyan
Write-Host "Generate a list of Computer Names            " -NoNewline -ForegroundColor Yellow
Write-Host 'Generate-Names -StartNumber <the beginning number> -NumberToMake <Number of names you need>' -ForegroundColor Cyan
Write-Host "Prompt SCCM To Install a Package             " -NoNewline -ForegroundColor Yellow 
Write-Host 'Start-SCCMAppInstall -ComputerList <ComputerName(s)> -PackageName <Package Name>' -ForegroundColor Cyan
Write-Host "Set SCCM Site to 'MC3'                       " -NoNewline -ForegroundColor Yellow 
Write-Host 'Set-SCCMSite <ComputerName1>[,<ComputerName2>]' -ForegroundColor Cyan
Write-Host "Kick off all SCCM Actions                    " -NoNewline -ForegroundColor Yellow 
Write-Host 'Trigger-ClientCycles <ComputerName>' -ForegroundColor Cyan
Write-Host "Remove Registry.pol                          " -NoNewline -ForegroundColor Yellow 
Write-Host 'Remove-RegPol <ComputerName>' -ForegroundColor Cyan
Write-Host "Install All Pending SCCM Updates             " -NoNewline -ForegroundColor Yellow 
Write-Host 'Install-SCCMUpdates <ComputerName>' -ForegroundColor Cyan
}

function Get-Exchange{
    <#
    .SYNOPSIS
    Retrieves basic Exchange info on an account.
    .DESCRIPTION
    Retrieves Mailbox Database and Exchange Server for a user.
    .EXAMPLE
    Get-Exchange rhys.j.ferris
    .PARAMETER UserName
    The User you want to know about.
    #>
    Param ($UserName)
    get-ADUser $UserName -Properties homeMDB,msexchhomeservername | FL -Property name,MSExchHomeServerName,HomeMDB
}

function Modify-Permissions{
    <#
    .SYNOPSIS
    Modify ACLs on a file or folder
    .DESCRIPTION
    Add or remove permissions on a file or folder.
    .EXAMPLE
    Modify-Permissions C:\Users\Rhys.j.ferris\ MCDSUS\richard.boterf Modify -add
    .PARAMETER Path
    The File or Folder that you want to modify permissions
    .PARAMETER TargetObject
    The Object you want to give or take away permissions
    .PARAMETER Permission Level
    The Level of permission to grant or remove
    .PARAMETER Add
    Include to Grant Permissions
    .PARAMETER Remove
    Include to Remove Permissions
    .PARAMETER SingleItem
    Include to prevent applying permissions recursively
    #>
    Param (
        [string][Parameter(Mandatory=$True, Position=0)]$Path,
        [string][Parameter(Mandatory=$True, Position=1)]$TargetObject,
        [string][Parameter(Mandatory=$True, Position=2)][ValidateSet("Modify","FullControl","View")] $PermissionLevel,
        [switch]$Add,
        [switch]$Remove,
        [switch]$SingleItem
        )
    if(!(test-path $Path -ErrorAction SilentlyContinue)){
        Write-Warning "No Access to $Path.`nIt may not exist or you may not have permissions to it."
    }else{
        [string]$Command = "icacls $Path"
        if($Add){
            $Command += " /grant "
        }elseif($Remove){
            $Command += " /remove "
        }
        $Domain = $TargetObject.split("\") | select -First 1
        while(!(($Domain -eq "MCDSUS") -or ($Domain -eq "NT AUTHORITY") -or ($Domain -eq "BUILTIN"))){
            Write-Warning "Invalid Target Object. Follow Format Domain\Object`n  ex. MCDSUS\john.schmuckatelli"
            $TargetObject = Read-Host "Target Object"
            $Domain = $TargetObject.split("\") | select -First 1
        }
        $Command += "$TargetObject`:"
        switch($PermissionLevel){
            "FullControl"{
                $Command += "F"
            }"Modify"{
                $Command += "M"
            }"View"{
                $Command += "R"
            }
        }
        if(!$SingleItem){
            $Command += " /T"
        }
        Invoke-Expression -Command $Command
    }#End of Test-Path to validate access
}

function get-PrimaryDevice{
    <#
    .SYNOPSIS
    Get the Primary Devices for a user
    .DESCRIPTION
    Retrieve the list of primary devices for a user from SCCM
    .EXAMPLE
    Get-Primary Device rhys.j.ferris
    .PARAMETER UserName
    The User for which you want to retrieve primary devices
    #>
    Param ([string][Parameter(Mandatory=$True, Position=0)]$UserName)
    switch($global:SCCMImported){
        $Null{
            Import-SCCM
        }
        $False{
            Write-Warning "Function requires SCCM which failed to load"
        }
    }
    $UserName = $UserName.ToLower()
    $WorkingDirectory = Get-Location
    try{
        cd MC3:\
        #Check if MCDSUS was already provided
        if($UserName -notlike "MCDSUS\*"){
            $UserName = "MCDSUS\"+$UserName
        }
        $Computers = Get-CMUserDeviceAffinity -UserName $UserName | Select -ExpandProperty ResourceName
        Write-Host "Primary Devices for $($UserName):"
        $Computers | % {Write-Host $_}
        cd $WorkingDirectory
    }catch{
        write-warning "Unable to get Primary Device(s). Please make sure you have read access to SCCM`n$_"
    }
}

function get-PrimaryUser{
    <#
    .SYNOPSIS
    Get the Primary Users for a device
    .DESCRIPTION
    Retrieve the list of primary users for a user from SCCM
    .EXAMPLE
    Get-Primary User WLQUAN00264K29N
    .PARAMETER ComputerName
    The Computer for which you want to retrieve primary users
    #>
    Param ([string]$ComputerName)
    switch($global:SCCMImported){
        $Null{
            Import-SCCM
        }
        $False{
            Write-Warning "Function requires SCCM which failed to load"
        }
    }

    $ComputerName = $ComputerName.ToUpper()
    $WorkingDirectory = Get-Location
    try{
        cd MC3:\
        $Users = Get-CMUserDeviceAffinity -DeviceName $ComputerName | Select -ExpandProperty UniqueUserName
        Write-Host "Primary User(s) for $($ComputerName):"
        Foreach ($User in $Users) {
            if($User -like "mcdsus\*"){
                $User = $User.Split('\') | Select -Last 1
            }
            Write-Host $User
        }
        cd $WorkingDirectory
    }catch{
        write-warning "Unable to get Primary User. Please make sure you have read access to SCCM`n$_"
        cd $WorkingDirectory
    }
}

Function Reset-Profile{
    <#
    .SYNOPSIS
    Rebuild a User's Profile
    .DESCRIPTION
    Guided profile rebuild. This will prompt you for what profile you would like to rebuild. Remove the appropriate Registry Keys, and reboot the machine.
    Then it will rename the user profile .old, tell you when to allow the user to log in, and move the data back into the newly created profile.
    .EXAMPLE
    Reset-Profile WLQUAN00264K29N
    .PARAMETER ComputerName
    The Computer name on which the user's profile needs to be rebuilt
    #>
    Param ([string][Parameter(Mandatory=$True, Position=0)]$ComputerName)
    $PSRemoting = $null
    Switch (Test-Online -ComputerName $ComputerName){
        0{
            try{
                $Session = New-PSSession -ComputerName $ComputerName -ErrorAction Stop
                write-host "Remoting enabled. Pulling user keys." #Debugging
                [bool]$PSRemoting = $True
            }catch{
                [bool]$PSRemoting = $False
                write-host "Remoting not enabled`n$_`n`nExiting" #Debugging
                break
            }
            if($PSRemoting){
                
                    Invoke-Command -Session $Session -ScriptBlock{
                        
                    #Remove the Registry Key
                        $Users = (get-childitem "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\ProfileList\")|Get-ItemPropertyValue -Name ProfileImagePath
                        $Users = $Users.Replace("C:\Users\","")

                        $Keys = (get-childitem "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\ProfileList\").Name
                        $Keys = $Keys.Replace("HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\ProfileList\", "")

                        $Max = ($Users,$Key | Measure-Object -Maximum -Property Count).Maximum #Generates the maximum 'pairs'

                        $Array = @()

                        for ($i = 0; $i -lt $Max; $i++){ #loops from 0 to one below max (equals # pairs)
                        #Create a custom PSObject for each user
                        $UserObject = New-Object -TypeName PSObject
                        #Add the properties to the Object
                        $UserObject | Add-Member -MemberType NoteProperty -Name Index -Value ($i+1)
                        $UserObject | Add-Member -MemberType NoteProperty -Name UserName -Value $Users[$i]
                        $UserObject | Add-Member -MemberType NoteProperty -Name Key -Value $Keys[$i]
                        #Add the Object to the array
                        $Array += $UserObject
                        }

                        $Array|FT|Out-Host

                        $Selection = Read-Host "Select the number of the profile to be reset"
                        $Delete = $Array[($Selection-1)].Key
                            

                        Remove-Item "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\ProfileList\$Delete"
                    }

                #Reboot the Computer
                    Restart-Computer -ComputerName $ComputerName -Force
                    Write-Host "Giving the remote machine 2 min to reboot"
                    Write-Warning "Instruct User not to log in until you tell them to"
                    start-sleep 120 #Give the computer 2 minutes to reboot
                    [bool]$ComputerUp = $false
                    do{
                        try{
                            $Session = New-PSSession -ComputerName $ComputerName -ErrorAction Stop
                            $ComputerUp = $True
                        }catch{
                            write-host "Computer still rebooting. Try again in 45 Seconds" #Debugging
                            start-sleep 45
                        }
                    }until($ComputerUp -eq $True)

                    Invoke-Command -Session $Session -ScriptBlock{

                    #Rename Folder
                        Write-Host "Rename Cx folder to username.old"
                        $Users = Get-ChildItem -Path C:\Users
                        $Users = $Users.Name
                        Write-Output $Users
                        $Name = Read-Host -Prompt "`nFolder to rename? [Copy/Paste] "
                        $NewName = Read-Host -Prompt "`nRename to?"
                        Rename-Item -Path "C:\Users\$Name" -NewName "$NewName"
                    
                    #Choose Destination
                        Read-Host -Prompt "Instruct Cx to log in [Press enter once Cx logs in]"#Acts as pause
                        $Users = Get-ChildItem -Path C:\Users
                        $Users = $Users.Name
                        $i=1
                        Foreach ($user in $Users){
                            write-host "$i   $User"
                            $i++
                        }
                        $Selection = Read-Host "Select NEW Cx folder number [NOT username.old]"
                        $Destination =  $($Users[$Selection-1])

                    #Exclude/Copy Items to New Profile
                        $Subfolders = Get-ChildItem -Path "C:\Users\$NewName" #-Recurse
                        $i=1
                        Foreach ($Folder in $SubFolders){
                            write-host "$i   $Folder"
                            $i++
                        }
                        $ExcludeArray = @()
                        do{
                            $Exclude = Read-Host "One at a time, enter the numbers for the folders to be excluded. Leave blank and press enter when done"
                            if($Exclude -ne ''){$ExcludeArray += ($Exclude - 1)}
                        }
                        until($Exclude -eq '')
                        $NumberofFolders = $i-1
                        For ($i=0; $i -lt $NumberofFolders;$i++){
                            if (($ExcludeArray -notcontains $i) -and !($Subfolders[$i].name.substring(0,1) -eq '.')){ #Check to see if on exclude list or if it starts with a '.'
                                #write-host $Subfolders[$i].name #Debugging - writes names of folders to be copied
                                Copy-Item -Path $Subfolders[$i].FullName -Destination "C:\users\$Destination" -Recurse -Force
                            }
                        }

                        #Potentially add Cx logoff as the background may be blacked out

                  
                    }
                }else{
                    Write-Host "PSRemoting has failed despite returning True."
                    break
            }
        }
    }
    try{
        Remove-PSSession -Session $Session -ErrorAction Stop
    }catch{
    } #Housekeeping
}#End of Reset-Profile

function Fix-CDPUser{
    <#
    .SYNOPSIS
    Fixes the CDPUser Error.
    .DESCRIPTION
    Disables the CDPUser Service via the registry. Requires a reboot to be effective.
    .EXAMPLE
    Fix-CDPUser WLQUAN00264J19N
    .PARAMETER ComputerName
    The Computer that is having the error.
    #>
    Param ([string][Parameter(Mandatory=$True, Position=0)]$ComputerName)
    #Check if computer is online
    switch (Test-Online -ComputerName $ComputerName){
        0{
            try{
                #check if the Software Folder Exists and create it if doesn't
                if (!(test-path "\\$ComputerName\C$\Software")){
                    New-Item -ItemType Directory -Path "\\$ComputerName\C$\Software" -Force | Out-Null
                }
                #copy over reg file
                Copy-Item '\\nent95kbazvs003\MCFPAC\3DMLG\CLB-3\Longboard 2018\H&S Company\S-6\3. Data Section\Scripts\CPDU_Fix.reg' \\$ComputerName\C$\Software\
                #execute reg file
                psexec \\$ComputerName regedit.exe --% /S C:\Sofware\CPDU_Fix.reg
                Write-Host "Completed" -ForegroundColor Green
                Remove-Item \\$ComputerName\C$\Software\ -Recurse
                do{
                    $Restart = Read-Host "Would you like to restart the remote computer to finalize changes? (y/n)"
                }while($restart -notlike 'y' -and $restart -notlike 'n')
                if ($restart -like 'y'){
                    Restart-Computer -ComputerName $ComputerName -Force
                    Write-Host "Restart command sent to $ComputerName"
                }
            }catch{
                Write-Warning "$ComputerName Failed. Error: $_"
            }
        }
        1{
            Write-Warning "$ComputerName is Offline"
        }
        2{
            Write-Warning "$ComputerName is in Active Directory but does not resolve to an IP Address"
        }
        3{
            Write-Warning "No Object named $ComputerName in Active Directory"
        }
    }
}

Function Reset-IEProxy{
    <#
    .SYNOPSIS
    Reregisters the IE DLLs.
    .DESCRIPTION
    Reregisters the Internet Explorer DLLs.
    .EXAMPLE
    Reset-IEProxy WLQUAN002634K29N
    .PARAMETER ComputerName
    The Computer on which to reregister the IE DLLs.
    #>
    Param ([string][Parameter(Mandatory=$True, Position=0)]$ComputerName)
    $PSRemoting = $null
    Switch (Test-Online -ComputerName $ComputerName){
        0{
            try{
                $Session = New-PSSession -ComputerName $ComputerName -ErrorAction Stop
                write-host "Remoting enabled, resetting IEProxy.dll" #Debugging
                [bool]$PSRemoting = $True
            }catch{
                [bool]$PSRemoting = $False
                write-host "Remoting not enabled`n$_`n`nExiting" #Debugging
                break
            }
            switch($PSRemoting){
                True{
                    Invoke-Command -Session $Session -ScriptBlock{
                        regsvr32 /s /u "C:\Windows\System32\ieproxy.dll"
                        start-sleep 5
                        regsvr32 /s "C:\Windows\System32\ieproxy.dll"
                        start-sleep 5
                        regsvr32 /s /u "C:\Windows\SysWOW64\ieproxy.dll"
                        start-sleep 5
                        regsvr32 /s "C:\Windows\SysWOW64\ieproxy.dll"
                        #Write-Host "IEProxy.dll Reset" #Debugging
                    }
                    Write-Host "IEProxy.dll Reset"
                }else{#Stuff Goes Here...lol
                }

            }
        }
        1{
            Write-Warning "$ComputerName is Offline"
        }
        2{
            Write-Warning "$ComputerName is in Active Directory but does not resolve to an IP Address"
        }
        3{
            Write-Warning "No Object named $ComputerName in Active Directory"
        }
    }
    try{
        Remove-PSSession -Session $Session -ErrorAction Stop
    }catch{}
}

function Ping-Sweep{
    <#
    .SYNOPSIS
    Tests a list of computers to see which are online
    .DESCRIPTION
    Accepts a list of IPs or Hostnames and test each one to see if it is online. Opens a text document containing a list of the online computers.
    .EXAMPLE
    Ping-Sweep
    #>
    enter-info
    $Comps = $global:results
    new-item -ItemType File -Force C:\FerrisStuff\OnlineComps.txt | Out-Null
    foreach ($Comp in $comps){
        $comp = $comp.Trim()
        #$comp | gm
        write-host "Testing $Comp"
        Switch([bool](Test-Connection -ComputerName $Comp -Count 1 -Quiet)){
            True{
                $Comp | Out-File C:\FerrisStuff\OnlineComps.txt -Append -Force
            }
        }
    }
    ii C:\FerrisStuff\OnlineComps.txt
}

function Validate-MultiInput{
    <#
    .SYNOPSIS
    Test multiple computers to see if they are online.
    .DESCRIPTION
    Accepts and array of strings containing computer names and runs them through Test-Online. Returns an array of strings only containing online computers.
    This is an internal function for use inside other scripts.
    .EXAMPLE
    My-Function -computerNames Validate-MultiInput $ObjectContainingArrayOfStrings
    .PARAMETER ComputerName
    An Array of Strings to run through Test-Online
    #>
    param([string[]]$ComputerName)
    [String[]]$OutputObj = @()
    $ComputerName|ForEach-Object{
        if ((Test-Online -computerName $_) -eq 0){
            $OutputObj += $_
        }
    }
    return $OutputObj
}

function Test-Online{
	<#
	Returns 0 for computer is online,
	Returns 1 for computer exists in Active Directory, has an IP Address, but isn't responding,
	Returns 2 for computer exists in Active Directory, but doesn't resolve to an IP Address,
	Returns 3 for computer doesn't exists in Active Directory.
	#>
    param ([string]$ComputerName)
	if (test-connection -ComputerName $ComputerName -Count 2 -Quiet){
		return 0
	}Else{
		try{
			get-adcomputer -identity $ComputerName
			$IPAddress = Resolve-DnsName $ComputerName -type A -ErrorAction Stop | Select -ExpandProperty IPAddress
			write-warning "$ComputerName at $IPAddress not responding"
			return 1
		}catch{
			$ErrString = $_.toString() # | gm
			if ($ErrString -like "*DNS name does not exist"){
				write-warning "$ComputerName is in Active Directory but does not resolve to an IP Address"
				return 2
			}else{ #should probably swap this for an else if, but I don't know the exact exception returned by get-adcomputer.
				write-warning "No Object named $ComputerName in Active Directory"
				return 3
			}
		}
	}
}

function VirusScanConsole{
    <#
    .SYNOPSIS
    Opens the McAfee Virus Scan Console
    .DESCRIPTION
    <None>
    .EXAMPLE
    VirusScanConsole
    #>
    start "C:\Program Files (x86)\McAfee\VirusScan Enterprise\mcconsol.exe"
}

function RemoteAssist{
    <#
    .SYNOPSIS
    Opens SCCM's Remote Assist Console.
    .DESCRIPTION
    <None>
    #>
    try{
        start "C:\Program Files (x86)\ConfigMgr\bin\i386\CmRcViewer.exe"
    }catch{
        Write-Warning "Remote Assist Software Not Installed"
    }
}

function FixletDebugger{<#
    .SYNOPSIS
    Starts the BigFix Fixlet Debugger
    .DESCRIPTION
    <None>
    #>
    Start 'C:\Program Files (x86)\BigFix Enterprise\BES Console\QnA\FixletDebugger.exe'
}

function cmd{
    start cmd
}

function MCConsole{
    Invoke-Item 'C:\Program Files (x86)\McAfee\VirusScan Enterprise\mcconsol.exe'
}

function Get-WinVersion{
    <#    
.SYNOPSIS    
    List Windows Version from computer.  
    
.DESCRIPTION  
    List Windows Version from computer. 
     
.PARAMETER ComputerName 
    Name of server to list Windows Version from remote computer.

.PARAMETER SearchBase 
    AD-SearchBase of server to list Windows Version from remote computer.
                         
.NOTES    
    Name: Get-WindowsVersion.psm1 
    Author: Johannes Sebald
    Version: 1.2.1
    DateCreated: 2016-09-13
    DateEdit: 2016-09-14
            
.LINK    
    http://www.dertechblog.de

.EXAMPLE    
    Get-WindowsVersion
    List Windows Version on local computer.
.EXAMPLE    
    Get-WindowsVersion -ComputerName pc1
    List Windows Version on remote computer.   
.EXAMPLE    
    Get-WindowsVersion -ComputerName pc1,pc2
    List Windows Version on multiple remote computer.  
.EXAMPLE    
    Get-WindowsVersion -SearchBase "OU=Computers,DC=comodo,DC=com"
    List Windows Version on Active Directory SearchBase computer. 
.EXAMPLE    
    Get-WindowsVersion -ComputerName pc1,pc2 -Force
    List Windows Version on multiple remote computer and disable the built-in Format-Table and Sort-Object by ComputerName.                         
#>  
[cmdletbinding()]
param (
[parameter(ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
[string[]]$ComputerName = "localhost",
[string]$SearchBase,
[switch]$Force
)

if($SearchBase)
{
    if(Get-Command Get-AD* -ErrorAction SilentlyContinue)
    {
        if(Get-ADOrganizationalUnit -Filter "distinguishedName -eq '$SearchBase'" -ErrorAction SilentlyContinue)
            {
                $Table = Get-ADComputer -SearchBase $SearchBase -Filter *
                $ComputerName = $Table.Name
            }
        else{Write-Warning "No SearchBase found"}
    }
    else{Write-Warning "No Active Directory cmdlets found"}
}

# Parameter Force
if(-not($Force)){$tmp = New-TemporaryFile}

foreach ($Computer in $ComputerName) 
{
    switch(test-online $Computer){
        0{ 
            if(Get-Item -Path "\\$Computer\c$" -ErrorAction SilentlyContinue)
            {                    
                # Variables
                $WMI = [WmiClass]"\\$Computer\root\default:stdRegProv"
                $HKLM = 2147483650
                $Key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion"

                $ValueName = "CurrentMajorVersionNumber"
                $Major = $WMI.GetDWordValue($HKLM,$Key,$ValueName).UValue

                $ValueName = "CurrentMinorVersionNumber"
                $Minor = $WMI.GetDWordValue($HKLM,$Key,$ValueName).UValue

                $ValueName = "CurrentBuildNumber"
                $Build = $WMI.GetStringValue($HKLM,$Key,$ValueName).sValue

                $ValueName = "UBR"
                $UBR = $WMI.GetDWordValue($HKLM,$Key,$ValueName).UValue

                $ValueName = "ReleaseId"
                $ReleaseId = $WMI.GetStringValue($HKLM,$Key,$ValueName).sValue

                $ValueName = "ProductName"
                $ProductName = $WMI.GetStringValue($HKLM,$Key,$ValueName).sValue

                $ValueName = "ProductId"
                $ProductId = $WMI.GetStringValue($HKLM,$Key,$ValueName).sValue

                # Variables for Windows 6.x
                if($Major.Length -le 0)
                    {
                        $ValueName = "CurrentVersion"
                        $Major = $WMI.GetStringValue($HKLM,$Key,$ValueName).sValue 
                    }
                            
                if($ReleaseId.Length -le 0)
                    {
                        $ValueName = "CSDVersion"
                        $ReleaseId = $WMI.GetStringValue($HKLM,$Key,$ValueName).sValue 
                    }

                # Add Points
                if(-not($Major.Length -le 0)){$Major = "$Major."}
                if(-not($Minor.Length -le 0)){$Minor = "$Minor."}
                if(-not($UBR.Length -le 0)){$UBR = ".$UBR"}

                # Table Output
                $OutputObj = New-Object -TypeName PSobject
                $OutputObj | Add-Member -MemberType NoteProperty -Name ComputerName -Value $Computer.toUpper()
                $OutputObj | Add-Member -MemberType NoteProperty -Name ProductName -Value $ProductName
                $OutputObj | Add-Member -MemberType NoteProperty -Name WindowsVersion -Value $ReleaseId
                $OutputObj | Add-Member -MemberType NoteProperty -Name WindowsBuild -Value "$Major$Minor$Build$UBR"
                $OutputObj | Add-Member -MemberType NoteProperty -Name ProductId -Value $ProductId
                            
                # Parameter Force
                if(-not($Force)){$OutputObj | Export-Csv -Path $tmp -Append}else{$OutputObj}
            }
            else
            {            
                Write-Warning "$Computer no access"       
            } 
        }
    }
}

    # Parameter Force
    if(-not($Force))
    {                            
        Import-Csv -Path $tmp | Sort-Object -Property ComputerName | Format-Table -AutoSize
        Remove-Item $tmp -Force -ErrorAction SilentlyContinue
    }
}

function EventViewer{
    <#
    .SYNOPSIS
    Opens the EventViewer as an Admin
    .DESCRIPTION
    <None>
    .EXAMPLE
    EventViewer
    #>
    start C:\Windows\System32\eventvwr.msc /s
}

function SCCM{
    <#
    .SYNOPSIS
    Opens the SCCM Console
    .DESCRIPTION
    <None>
    #>
    Switch(Test-Path "C:\Program Files (x86)\ConfigMgr\bin\Microsoft.ConfigurationManagement.exe"){
        True{
            start "C:\Program Files (x86)\ConfigMgr\bin\Microsoft.ConfigurationManagement.exe"
        }False{
            Write-Warning "SCCM Not Installed"
        }
    }
}
function Restart-BES{
    <#
    .SYNOPSIS
    Restarts the BES Service on a remote Machine
    .DESCRIPTION
    Accepts a list of IPs or Hostnames and test each one to see if it is online. Opens a text document containing a list of the online computers.
    .EXAMPLE
    Restart-BES WLQUAN00264J19N
    #>
     param ([string][Parameter(Mandatory=$True, Position=0)]$ComputerName)
     $ComputerName = $ComputerName.toupper()
     try{
         (get-service -computername $ComputerName -servicename BESClient).stop()
         write-host "Successfully stopped BES Client on $ComputerName" -foregroundcolor Yellow
         Write-Host "Giving BES Client Time to Finish up before restarting it."
         start-sleep 15
     }catch{
         Write-Warning "Failed to Stop BES Client. It may have already been stopped. Error: $_"
     }
     try{
         (get-service -computername $ComputerName -servicename BESClient).start()
         write-host "Successfully re-started BES Client on $ComputerName" -foregroundcolor Green
     }catch{
         Write-Warning "Failed to Start BES Client. We may not have waited long enough or there may be a bigger problem. Error: $_"
     }
}

Function Get-SerialNumber{
    <#
    .SYNOPSIS
    Get the serial number of a remote machine.
    .DESCRIPTION
    Get the serial number of a remote machine.
    .EXAMPLE
    Get-SerialNumber WLQUAN00264K29N
    .PARAMETER ComputerName
    The Computer you want to get the Serial Number of.
    #>
    Param ([string][Parameter(Mandatory=$True, Position=0)]$ComputerName)
    Get-WmiObject -computername $ComputerName -class Win32_BIOS | Select -Property PSComputerName,BiosVersion,Manufacturer,SerialNumber | Format-List
}

Function Get-BitLockerKey{
    <#
    .SYNOPSIS
    Gets any Bit Locker Keys stored in AD for a machine
    .DESCRIPTION
    Gets any Bit Locker Keys that are stored in AD. Also retrieves their identifier.
    .EXAMPLE
    Get-BitLockerKey WLQUAN00264J19N
    .PARAMETER ComputerName
    The Computer You need the Bit Locker Key for.
    #>
Param ([string][Parameter(Mandatory=$True, Position=0)]$ComputerName)
$ComputerName = $ComputerName.toupper()

$BLResult = @()

# Get Computer Object
$computer = Get-ADComputer -Filter {Name -eq $ComputerName}

# Get all BitLocker Recovery Keys for that Computer. Note the 'SearchBase' parameter
$BitLockerObjects = Get-ADObject -Filter {objectclass -eq 'msFVE-RecoveryInformation'} -SearchBase $computer.DistinguishedName -Properties msFVE-RecoveryPassword
foreach ($BitLockerObject in $BitLockerObjects)
{
    $BLKey = $BitLockerObject | select -ExpandProperty msFVE-RecoveryPassword
    $BLID = $BitLockerObject | select -ExpandProperty name
    $BLObj = New-Object -TypeName psobject -Property(
        @{
            #"Computername"=$computer.Name
            "Identifier"=$BLID
            "Key"=$BLKey
        }
    )
    $BLResult += $BLObj
}

# Output the results!
Write-Host "Key(s) for $($Computer.name)" -NoNewline -ForegroundColor Green
$BLResult | FL
}#End GetBitLockerKey

function Get-LAPS{
    Param ($CompName)
    Get-ADComputer $CompName -Properties ms-Mcs-AdmPwd,ms-Mcs-AdmPwdExpirationTime | FL -Property Name,Enabled,ms-Mcs-AdmPwd
}

function Get-WindowsInstallDate{
    Param ($computerName)
    if(test-connection $computerName -Count 2 -Quiet){
        psexec \\$computerName systeminfo --% | find /i "install date"
    }else{
        Write-Warning "$computerName is Offline"
    }
}


#---------------------------------------------------------------------------------------------------------------------


Function Get-RemoteProgram {
<#
.Synopsis
Generates a list of installed programs on a computer

.DESCRIPTION
This function generates a list by querying the registry and returning the installed programs of a local or remote computer.

.NOTES   
Name: Get-RemoteProgram
Author: Jaap Brasser
Version: 1.2.1
DateCreated: 2013-08-23
DateUpdated: 2015-02-28
Blog: http://www.jaapbrasser.com

.LINK
http://www.jaapbrasser.com

.PARAMETER ComputerName
The computer to which connectivity will be checked

.PARAMETER Property
Additional values to be loaded from the registry. Can contain a string or an array of string that will be attempted to retrieve from the registry for each program entry

.EXAMPLE
Get-RemoteProgram

Description:
Will generate a list of installed programs on local machine

.EXAMPLE
Get-RemoteProgram -ComputerName server01,server02

Description:
Will generate a list of installed programs on server01 and server02

.EXAMPLE
Get-RemoteProgram -ComputerName Server01 -Property DisplayVersion,VersionMajor

Description:
Will gather the list of programs from Server01 and attempts to retrieve the displayversion and versionmajor subkeys from the registry for each installed program

.EXAMPLE
'server01','server02' | Get-RemoteProgram -Property Uninstallstring

Description
Will retrieve the installed programs on server01/02 that are passed on to the function through the pipeline and also retrieves the uninstall string for each program
#>
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [Parameter(ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName=$true,
            Position=0)]
        [string[]]$ComputerName,
        [Parameter(Position=0)]
        [string[]]$Property,
        [Parameter(Position=0)]
        [string[]]$Software
    )

    begin {
        $RegistryLocation = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\',
                            'SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\'
        $HashProperty = @{}
        $SelectProperty = @('ProgramName','ComputerName')
        if ($Property) {
            $SelectProperty += $Property
        }
    }

    process {
        $ComputerName = $ComputerName.toupper()
        foreach ($Computer in $ComputerName) {
            Switch (Test-Online -ComputerName $Computer){
                0{
                    $remoteregcheck = gwmi -ComputerName $ComputerName -Class win32_service -Filter "name='RemoteRegistry'" | Select state
                    Switch($remoteregcheck.state){
                        "Stopped"{(gwmi -ComputerName $ComputerName -Class win32_service -Filter "name='RemoteRegistry'").startservice() | Out-Null}
                    }
                    $RegBase = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$Computer)
                    foreach ($CurrentReg in $RegistryLocation) {
                        if ($RegBase) {
                            $CurrentRegKey = $RegBase.OpenSubKey($CurrentReg)
                            if ($CurrentRegKey) {
                                $CurrentRegKey.GetSubKeyNames() | ForEach-Object {
                                    if ($Property) {
                                        foreach ($CurrentProperty in $Property) {
                                            $HashProperty.$CurrentProperty = ($RegBase.OpenSubKey("$CurrentReg$_")).GetValue($CurrentProperty)
                                        }
                                    }
                                    $HashProperty.ComputerName = $Computer
                                    $HashProperty.ProgramName = ($DisplayName = ($RegBase.OpenSubKey("$CurrentReg$_")).GetValue('DisplayName'))
                                    if ($DisplayName) {
                                        New-Object -TypeName PSCustomObject -Property $HashProperty |
                                        Select-Object -Property $SelectProperty
                                    }  
                                } | Where-Object {$_.programname -match "$software"} | Select *
                            } 
                        }
                    }
                }
            }
        }
    }
}


Function Push-Flash{
	<#
	.Synopsis
	Uninstalls and Re-installs Adobe Flash

	.DESCRIPTION
	Attempts a gaceful uninstall and re-install of Adobe Flash PAPI version. Also will install the Windows 10 Patch if it is not installed.
    Can be out of date as the source files must be manually mainitaine.
    Not the prefered method of installing Flash.

	.PARAMETER ComputerName
	The computer to which to install/update/fix Adobe Flash.

	.EXAMPLE
	Push-Flash WLQUAN00264123N

	Description:
	Will uninstall and reinstall Adobe Flash on computer WLQUAN00264123N.
	#>
    Param ([string][Parameter(Mandatory=$True, Position=0)]$Comp)
    $Comp = $Comp.toupper()
    Switch (Test-Online -ComputerName $Comp){
        0{
            Try{
                $session = New-PSSession -ComputerName $Comp
                Write-Host "Pushing PAPI files to $Comp" -ForegroundColor Yellow
                new-item -ItemType Directory -Path "\\$Comp\C$\Flash" -ErrorAction SilentlyContinue | out-null
                
                #Copying over all filles in directory
                Robocopy.exe '\\nent95kbazvs003\MCFPAC\3DMLG\CLB-3\Longboard 2018\H&S Company\S-6\3. Data Section\Scripts\Flash' "\\$Comp\C$\flash" /MIR /xf *.msu | Out-Null 


                Write-Host "Beginning PAPI Installation" -ForegroundColor Yellow
                #PSExec -s \\$Comp C:\Flash\fixflash.bat
                write-host "Attempting to update to Flash 32" # <------------------------------------------------------------------------------------------UPDATE HERE


                Invoke-Command -Session $session -ScriptBlock{
                    try{
                    
                        Stop-Process -Name firefox -Force -ErrorAction stop}
                    
                    catch{
                    
                        #No Action Required
                    
                    }
                    write-host "Starting Uninstall"
                    
                    $MyProcess = Start-Process -FilePath C:\Flash\Uninstall.exe -ArgumentList "-uninstall" -PassThru
                    Wait-Process -Id $MyProcess.Id
                    write-verbose "Uninstall.exe Completed" -verbose

                    #Getting UninstallString for FlashPAPI

                    
                                     
                    
                    $MyArgs = " /X","{6006D428-182D-4FED-BE45-5C226A66C8FD}"," /qn"
                    
                    
                    
                    try{$MyProcess = Start-Process -FilePath "c:\Windows\System32\msiexec.exe" -ArgumentList $MyArgs -PassThru
                        Wait-Process -Id $MyProcess.Id}catch{}
                    try{Stop-Process -Name firefox -Force -ErrorAction stop}catch{}

                    write-host "Starting PAPI Install"
                    $MyProcess = Start-Process -FilePath C:\Flash\FlashPAPI.msi -ArgumentList "/qn" -PassThru
                    Wait-Process -Id $MyProcess.Id

                    
                }
                <#
                Write-Host "Checking for Windows Patch" -ForegroundColor Yellow
                $DISM = invoke-command -Session $session  -scriptblock{dism /online /get-packages}
                $DISMArray = $DISM.split("`n")
                $length = $DISMArray.count
                $PackagePresent = $False
                $installMSU = $False
                    for($i=0;$i -lt $length; $i++){
                    if($DISMArray[$i] -match "KB4471331"){ # <------------------------------------------------------------------------------------------UPDATE HERE
                        $PackagePresent = $True
                        if($DISMArray[$i+1] -match "Installed"){
                            write-host "Win 10 Flash update already installed (KB4471331)" -ForegroundColor Green # <------------------------------------------------------------------------------------------UPDATE HERE
                            $installMSU = $False
                            break
                        }else{
                            write-host "Win 10 Flash not update installed (KB4471331)" -ForegroundColor Yellow # <------------------------------------------------------------------------------------------UPDATE HERE
                            $installMSU = $True
                        }
                    }
                }
                #Write-Host $installMSU
                if(!$PackagePresent){
                    Write-Host "Package Not Present" -ForegroundColor Yellow
                    $installMSU = $True
                }
                #>

                #if($installMSU){
                write-host "Copying Patch to Computer" -ForegroundColor DarkYellow
                    $WinVersion = Get-WinVersion -ComputerName localhost -Force | Select-Object -ExpandProperty WindowsVersion
                    switch ($WinVersion){
                        "1607"{
                            write-host "Remote Host is 1607"
                            Copy-Item -Path '\\nent95kbazvs003\MCFPAC\3DMLG\CLB-3\Longboard 2018\H&S Company\S-6\3. Data Section\Scripts\Flash\Flash1607.msu' "\\$Comp\C$\Flash\Flash.msu"
                        }"1709"{
                            write-host "Remote Host is 1709"
                            Copy-Item -Path '\\nent95kbazvs003\MCFPAC\3DMLG\CLB-3\Longboard 2018\H&S Company\S-6\3. Data Section\Scripts\Flash\Flash1709.msu' "\\$Comp\C$\Flash\Flash.msu"
                        }default{
                            write-warning "Remote Host is not 1607 or 1709. Unable to install MSU"
                            $installMSU = $False
                        }
                    }
                #}
                #if($installMSU){
                    
                    
                    Write-Host "Installing Windows Update"
                    invoke-command -Session $session  -ScriptBlock{
                        try{Get-Process -name WUSA -ErrorAction Stop | Stop-Process}catch{}
                        $MyCommand = "C:\windows\system32\wusa.exe C:\Flash\Flash.msu /quiet /norestart"
                        $Mycommand | Out-File c:\flash\Install.CMD

                        $myProcess = Start-Process -FilePath c:\flash\Install.CMD -PassThru
                            Wait-Process -id $myProcess.Id
                    }#
                    #& "\\clquan00264001o\e`$\SysinternalsSuite\PsExec.exe" -s \\$Comp wusa.exe C:\Flash\Flash.msu /quiet /norestart
                    #Start-Sleep -s 60
                #}
                Write-Host "Completed $Comp, Cleaning Up." -ForegroundColor Green
                Remove-Item \\$Comp\C$\Flash -Recurse -Force
                Remove-PSSession $session
                "$(Get-Date) - $Comp - Push-Flash Script Completed Successfully by $(whoami)" | Out-file '\\nent95kbazvs003\MCFPAC\3DMLG\CLB-3\Longboard 2018\H&S Company\S-6\3. Data Section\Scripts\Logs\Flash.log' -Append -Force
            }catch{
                Write-host "$Comp Failed. $_" -ForegroundColor Magenta
                Remove-PSSession $session
                "$(Get-Date) - $Comp - Push-Flash Script Failed $_ by $(whoami)" | Out-file '\\nent95kbazvs003\MCFPAC\3DMLG\CLB-3\Longboard 2018\H&S Company\S-6\3. Data Section\Scripts\Logs\Flash.log' -Append -Force
            }
            $Output = get-RemoteProgram -ComputerName $Comp -Software "Adobe Flash" -Property DisplayVersion
            #$Output |  Out-file '\\nent95kbazvs003\MCFPAC\3DMLG\CLB-3\Longboard 2018\H&S Company\S-6\3. Data Section\Scripts\Logs\Flash.log' -Append -Force
            $Output | select computername,programname,displayversion |  FT
        }
    }
    Get-Process -Id $PID | Invoke-FlashWindow
}#End Function Push-Flash


function Check-Flash{
   	<#
	.Synopsis
    Check the currently installed Flash version.

	.DESCRIPTION
	Checks the remote machine for its currently installed version of NPAPI Adobe Flash and if the current Windows 10 Flash Patch is installed.

	.PARAMETER ComputerName
	The computer on which to check the Flash Version.

	.EXAMPLE
	Check-Flash WLQUAN00265A63N

	Description:
	Gets the Flash version installed on the computer.
	#>
    param ([string][Parameter(Mandatory=$True, Position=0)]$CompName)
    if((Test-Online -ComputerName $CompName) -eq 0){
    Get-WinVersion -ComputerName $CompName
    $DISM = invoke-command -computerName $CompName -scriptblock{dism /online /get-packages}
    $DISMArray = $DISM.split("`n")
    $length = $DISMArray.count
    $PackagePresent = $False
    $Installed = $False
        for($i=0;$i -lt $length; $i++){
        if($DISMArray[$i] -match "KB4471331"){
            $PackagePresent = $True
            if($DISMArray[$i+1] -match "Installed"){
                write-host "Win 10 Flash update installed (KB4471331)" -ForegroundColor Green
                $Installed = $True
            }else{
                write-host "Win 10 Flash not update installed (KB4471331)" -ForegroundColor Yellow
            }
        }
    }
    if (!$Installed){
        Write-Host "Windows Patch Installed: $Installed" -ForegroundColor Red
    }
    Get-RemoteProgram -ComputerName $CompName -Software "Adobe Flash" -Property DisplayVersion,InstallDate
    }
}

Function Uninstall-Flash{
   	<#
    .SYNOPSIS
    Attempts a greaceful uninstall of Adobe Flash
    .DESCRIPTION
    Attempts to gracefully uninstall any registered version of Adobe Flash found on the remote system.
    .EXAMPLE
    Uninstall-Java -ComputerName WLQUAN00264123N
    Remove Java from WLQUAN00264123N
    .PARAMETER ComputerName
    The computer name on which to remove Java
    #>
    param ([string][Parameter(Mandatory=$True, Position=0)]$ComputerName)
    Invoke-Command -ComputerName $ComputerName -ScriptBlock{
        $currentreg = @(
            'SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\',
            'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\'
        )
        foreach($regkey in $currentreg){
            $RegBase = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,"$env:computername")
            $CurrentRegKey = $RegBase.OpenSubKey($regkey)
                $CurrentRegKey.GetSubKeyNames() | ForEach-Object {
                $a = ($RegBase.OpenSubKey("$regkey$_")).GetValue('displayname')
                $b = $_
                switch(($a -match "adobe flash") -and ($a -notmatch "Micro")){
                    $true{
                        $a #+ $b
                        msiexec /X$b /qn REBOOT=ReallySuppress /l*v c:\users\public\$a.log | Out-Null
                    }
                }
            }
        }
    }
}


Function Destroy-Flash{
    <#
    .SYNOPSIS
    Forcibly Removes Flash from the system.
    .DESCRIPTION
    First it attempts to gracefully uninstall Flash. Aftwards it searchs known locations in the file system and the registry and removes them.
    Also available with -Murder paramater which skips the gracefull uninstall in the event that it hangs or otherwise causes issues.
    .EXAMPLE
    Destroy-Flash -ComputerName WLQUAN00264123N
    Remove Flash from WLQUAN00264123N
    .EXAMPLE
    Destroy-Flash -ComputerName WLQUAN00264123N -Murder
    Remove Flash from WLQUAN00264123N without first attempting a graceful uninstall
    .PARAMETER ComputerName
    The computer name on which to remove Flash
    .PARAMETER Murder
    Switch to skip the graceful uninstall
    #>
    Param ([String][Parameter(Mandatory=$True, Position=0)]$ComputerName,[switch]$Murder)
    if(!$Murder){
        Uninstall-Flash -ComputerName $ComputerName
    }
    Invoke-Command -ComputerName $ComputerName -ScriptBlock {

        #This Section looks for Flash Keys that are left over from previous installs.
        $Locations = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall","HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\uninstall"
        foreach ($Location in $Locations){
        $Keys = gci $Location #Get all the Keys (x64)
            Foreach ($Key in $Keys){
                $DisplayName = $Key.getValue("DisplayName")
                If ($DisplayName -like "Adobe Flash*"){ #Find the Flash Keys
                    Write-Host "Found $DisplayName in the Registry - Removing"
                    Remove-Item -Path ($Key.PSPath) -Recurse -Force
                }
            }
        }

        #Take ownership of the Flash.ocx file
        $TakeOwn = takeown /F 'C:\Windows\System32\Macromed\Flash\Flash.ocx'
        if($TakeOwn -notmatch "SUCCESS"){
            Write-Warning "Failed to take ownership of C:\Windows\System32\Macromed\Flash\Flash.ocx. This may result in errors or failure."
        }

        #This Section looks for leftover Program Files and deletes them
        $Folders = 'C:\WINDOWS\SysWOW64\Macromed\Flash\','C:\Windows\System32\Macromed'
        ForEach ($RootFolder in $Folders){
            if(test-path $RootFolder){
                write-host "Found $($RootFolder)"
                $JavaFolders = Get-ChildItem $RootFolder
                foreach($Folder in $JavaFolders){
                    write-host "Deleting $($Folder.fullname)"
                    Remove-Item -Path $Folder.fullname -Force -Recurse
                }
                write-host "Removing $($RootFolder)"
                Remove-Item $RootFolder -Force -Recurse
            }
        }
        #This section looks for left over AppData and deletes it
        $Files = Get-Item C:\Users\*\AppData\Roaming\Macromedia
        if ($Files -ne $Null){
            write-host "Found left over files:"
            $Files | Foreach-object {Write-host $_.FullName -foregroundColor Red}
            write-host "Removing them"
            $Files | Remove-Item -Force -Recurse
        }
    }
}

<#function Push-Java{
	<#
	.Synopsis
	Uninstalls and Re-installs Java

	.DESCRIPTION
	Attempts a gaceful uninstall and re-install of Java PAPI version. Also will install the Windows 10 Patch if it is not installed.
    Can be out of date as the source files must be manually mainitaine.
    Not the prefered method of installing Flash.

	.PARAMETER ComputerName
	The computer to which to install/update/fix Java.

	.EXAMPLE
	Push-Flash WLQUAN00264123N

	Description:
	Will uninstall and reinstall Java on computer WLQUAN00264123N.
	
    Param ([string][Parameter(Mandatory=$True, Position=0)]$Comp)
    $Comp = $Comp.toupper() #Because OCD
    Switch (Test-Online -ComputerName $Comp){
        0{
            [bool]$DontDoIt = $False
            if(Test-Path \\$Comp\C$\Java){
                $lastwritetime = Get-item -Path \\$Comp\C$\Java | Select -ExpandProperty Lastwritetime
                #$Owner = get-acl -Path \\$Comp\C$\Java | Select -ExpandProperty Owner
                Write-Warning "Possible Collision! Java folder already exists. It was created $lastwritetime."
                do{
                    $read = Read-Host "Continue? (y/n)"
                }while(($read -notlike 'y') -and ($read -notlike 'n'))
                switch ($read){
                    'y'{
                        Remove-Item -Path "\\$Comp\C$\Java" -Recurse -Force
                        New-Item -ItemType Directory -Path "\\$Comp\C$\Java" -Force | Out-Null
                        $DontDoIt = $False
                    }
                    'n'{
                        Write-Host "Exiting"
                        $DontDoIt = $True
                    }
                }
            }
            if (!$DontDoIt){
                Try{
                    Write-Host "Pushing installation files to $Comp" -ForegroundColor Yellow
                    Copy-Item '\\nent95kbazvs003\MCFPAC\3DMLG\CLB-3\Longboard 2018\H&S Company\S-6\3. Data Section\Scripts\Java' \\$Comp\C$\ -Recurse -Force -Verbose -ErrorAction Stop
                    Write-Host "Beginning Installation" -ForegroundColor Yellow
                    #PSExec -s \\$Comp cshmd /c powerell -executionpolicy bypass -file "C:\Java\Stripper With Coffee 1.1.ps1"
                    $Session = New-PSSession -ComputerName $Comp
                    Invoke-Command -Session $Session -ScriptBlock {
                        #Stripper with Coffee 1.1
                        taskkill /F /IM iexplore.exe /T
                        taskkill /F /IM firefox.exe /T
                        $currentreg = @(
                            'SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\',
                            'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\'
                        )
                        foreach($regkey in $currentreg){
                            $RegBase = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,"$env:computername")
                            $CurrentRegKey = $RegBase.OpenSubKey($regkey)
                                $CurrentRegKey.GetSubKeyNames() | ForEach-Object {
                                $a = ($RegBase.OpenSubKey("$regkey$_")).GetValue('displayname')
                                $b = $_
                                switch(($a -match "java") -and ($a -notmatch "Micro")){
                                    $true{
                                        write-host Removing $a
                                        msiexec /X$b /qn REBOOT=ReallySuppress /l*v c:\users\public\$a.log | Out-Null
                                    }
                                }
                            }
                        }
                    }
                    if (test-path "\\$Comp\C$\Program Files (x86)\Java"){
                        Remove-Item "\\$Comp\C$\Program Files (x86)\Java" -Recurse -Force
                    }
                    if (test-path "\\$Comp\C$\Program Files\Java"){
                        Remove-Item "\\$Comp\C$\Program Files\Java" -Recurse -Force
                    }
                    Start-Sleep 20
                    Invoke-Command -Session $Session -ScriptBlock{
                        taskkill /F /IM iexplore.exe /T
                        taskkill /F /IM firefox.exe /T
                        $myProcess = Start-Process -FilePath C:\Java\jre-8u201-windows-i586.exe -ArgumentList "/s" -PassThru
                                Wait-Process -id $myProcess.Id
                        $myProcess = Start-Process -FilePath C:\Java\jre-8u201-windows-x64.exe -ArgumentList "/s" -PassThru
                                Wait-Process -id $myProcess.Id
                    }
                    Write-Host "Completed $Comp, Cleaning Up." -ForegroundColor Green
                    Remove-Item "\\$Comp\C$\Java" -Recurse -Force
                    Clean-Java -ComputerName $Comp
                    "$(Get-Date) - $Comp - Push-Java Script Completed Successfully by $(whoami)" | Out-file '\\nent95kbazvs003\MCFPAC\3DMLG\CLB-3\Longboard 2018\H&S Company\S-6\3. Data Section\Scripts\Logs\Java.log' -Append -Force
                }catch{
                    Write-host "$Comp Failed. $_" -ForegroundColor Magenta
                    "$(Get-Date) - $Comp - Push-Java Script by $(whoami) Failed: $_" | Out-file '\\nent95kbazvs003\MCFPAC\3DMLG\CLB-3\Longboard 2018\H&S Company\S-6\3. Data Section\Scripts\Logs\Java.log' -Append -Force
                }
                $Output = get-RemoteProgram -ComputerName $Comp -Software "Java 8" -Property DisplayVersion,InstallDate
                #$Output |  Out-file '\\nent95kbazvs003\MCFPAC\3DMLG\CLB-3\Longboard 2018\H&S Company\S-6\3. Data Section\Scripts\Logs\Java.log' -Append -Force
                $Output | select computername,programname,displayversion |  FT
            }
        }
    }
    Get-Process -Id $PID | Invoke-FlashWindow
}#End Function Push-Java #>

Function Clean-Java{
	<#
	.Synopsis
	Compares the registry with files on the system and resolves any discrepencies.

	.DESCRIPTION
	Compares the registry with files on the system and resolves any discrepencies.

	.PARAMETER ComputerName
	The computer to which clean the Jave files.

	.EXAMPLE
	Clean-Java WLQUAN0024123N
	#>
    Param ([String][Parameter(Mandatory=$True, Position=0)]$ComputerName)
    try{
        $Session = New-PSSession -ComputerName $ComputerName -ErrorAction Stop
        #write-host "Remoting enabled" #Debugging
        [bool]$PSRemoting = $True
    }catch{
        [bool]$PSRemoting = $False
        write-host "Remoting not enabled`n$_`n`nExiting" #Debugging
        break
    }
    If ($PSRemoting){
        Invoke-Command -Session $Session -ScriptBlock {

            #This Section looks for Java Keys that are left over from previous installs.
            $Locations = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall","HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\uninstall"
            foreach ($Location in $Locations){
            $Keys = gci $Location #Get all the Keys (x64)
                Foreach ($Key in $Keys){
                    $DisplayName = $Key.getValue("DisplayName")
                    If ($DisplayName -like "Java*"){ #Find the Java Keys
                        Write-Host "Found $DisplayName in the Registry"
                        If($DisplayName -like "Java Auto Updater"){
                            Write-Host "Found Java Auto Updater. Uninstall Initiated. Not waiting for it to finish" -ForegroundColor Red
                            $KeyName = $Key.Name.split("\") | Select-Object -Last 1
                            & msiexec.exe /X$KeyName /qn
                        }else{
                            $InstallLocation = $Key.GetValue("InstallLocation")
                            If(!(Test-Path $InstallLocation)){
                                #If the Java Path doesn't exist, remove the old key
                                Remove-Item -Path ($Key.PSPath) -Recurse -Force
                                Write-Host "No Matching Files for $DisplayName, Removed Registry entry" -ForegroundColor Yellow
                            }else{
                                Write-Host "Found matching files for $DisplayName" -ForegroundColor Green
                            }
                        }
                    }
                }
            }
        }
    }
}

Function Uninstall-Java{
    <#
    .SYNOPSIS
    Gracefully uninstalls any Java registered on the machine
    .DESCRIPTION
    Gracefully uninstalls any Java registered on the machine
    .EXAMPLE
    Uninstall-Java -ComputerName WLQUAN00264123N
    Remove Java from WLQUAN00264123N
    .PARAMETER ComputerName
    The computer name on which to remove Java
    #>
    param ([string][Parameter(Mandatory=$True, Position=0)]$ComputerName)
    Invoke-Command -ComputerName $ComputerName -ScriptBlock{
        $currentreg = @(
            'SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\',
            'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\'
        )
        foreach($regkey in $currentreg){
            $RegBase = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,"$env:computername")
            $CurrentRegKey = $RegBase.OpenSubKey($regkey)
                $CurrentRegKey.GetSubKeyNames() | ForEach-Object {
                $a = ($RegBase.OpenSubKey("$regkey$_")).GetValue('displayname')
                $b = $_
                switch(($a -match "java") -and ($a -notmatch "Micro")){
                    $true{
                        $a #+ $b
                        msiexec /X$b /qn REBOOT=ReallySuppress /l*v c:\users\public\$a.log | Out-Null
                    }
                }
            }
        }
    }
}


Function Destroy-Java{
    <#
    .SYNOPSIS
    Forcibly Removes Java from the system.
    .DESCRIPTION
    First it attempts to gracefully uninstall Java. Aftwards it searchs known locations in the file system and the registry and removes them.
    Also available with -Murder paramater which skips the gracefull uninstall in the event that it hangs or otherwise causes issues.
    .EXAMPLE
    Destroy-Java -ComputerName WLQUAN00264123N
    Remove Java from WLQUAN00264123N
    .EXAMPLE
    Destroy-Java -ComputerName WLQUAN00264123N -Murder
    Remove Java from WLQUAN00264123N without first attempting a graceful uninstall
    .PARAMETER ComputerName
    The computer name on which to remove Java
    .PARAMETER Murder
    Switch to skip the graceful uninstall
    #>
    Param ([String][Parameter(Mandatory=$True, Position=0)]$ComputerName,[switch]$Murder)
    if(!$Murder){
        Uninstall-Java -ComputerName $ComputerName
    }
    Invoke-Command -ComputerName $ComputerName -ScriptBlock {

        #This Section looks for Java Keys that are left over from previous installs.
        $Locations = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall","HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\uninstall"
        foreach ($Location in $Locations){
        $Keys = gci $Location #Get all the Keys (x64)
            Foreach ($Key in $Keys){
                $DisplayName = $Key.getValue("DisplayName")
                If ($DisplayName -like "Java*"){ #Find the Java Keys
                    Write-Host "Found $DisplayName in the Registry - Removing"
                    Remove-Item -Path ($Key.PSPath) -Recurse -Force
                }
            }
        }
        #This Section looks for leftover Program Files and deletes them
        $Folders = 'C:\Program Files\Java','C:\Program Files (x86)\Java'
        ForEach ($RootFolder in $Folders){
            if(test-path $RootFolder){
                write-host "Found $($RootFolder)"
                $JavaFolders = Get-ChildItem $RootFolder
                foreach($Folder in $JavaFolders){
                    write-host "Deleting $($Folder.fullname)"
                    Remove-Item -Path $Folder.fullname -Force -Recurse
                }
                write-host "Removing $($RootFolder)"
                Remove-Item $RootFolder -Force -Recurse
            }
        }
        #This section looks for left over AppData and deletes it
        $Files = Get-Item C:\users\*\AppData\LocalLow\Sun
        if ($Files -ne $Null){
            write-host "Found left over files:"
            $Files | Foreach-object {Write-host $_.FullName -foregroundColor Red}
            write-host "Removing them"
            $Files | Remove-Item -Force -Recurse -WhatIf
        }
        $Files = Get-Item C:\users\*\AppData\Roaming\Sun
        if ($files -ne $null){
            write-host "Found left over files:"
            $Files | Foreach-object {Write-host $_.FullName -foregroundColor Red}
            write-host "Removing them"
            $Files | Remove-Item -Force -Recurse
        }
    }
}

function Check-Java{
	<#
	.Synopsis
	Gets the installed versions of Java on the remote machine.

	.DESCRIPTION
	A wrapper for Get-RemoteProgram that pulls Java Display Version and Install Date.

	.PARAMETER ComputerName
	The Computer to get Java info about.
	#>
    param ($CompName)
    Get-RemoteProgram -ComputerName $CompName -Software "Java 8" -Property DisplayVersion,InstallDate
}


<#function Push-Reader{
    Param ($Comp)
    $Comp = $Comp.toupper()
    Switch (Test-Online -ComputerName $Comp){
        0{
            Try{
                Write-Host "Pushing installation files to $Comp" -ForegroundColor Yellow
                Copy-Item '\\nent95kbazvs003\MCFPAC\3DMLG\CLB-3\Longboard 2018\H&S Company\S-6\3. Data Section\Scripts\AdobeReader' \\$Comp\C$\ -Recurse -Force -Verbose
                Write-Host "Beginning Installation" -ForegroundColor Yellow
                #PSExec -s \\$Comp cmd /c powershell -executionpolicy bypass -file "C:\AdobeReader\AdobeReaderRemover.ps1"
                $Session = New-PSSession -ComputerName $Comp
                invoke-command -Session $Session -ScriptBlock{
                    Write-Host "Removing any installed versions"
                    try{(Get-Process -name iexplore -ErrorAction Stop).Kill()}catch{}
                    try{(Get-Process -name firefox -ErrorAction Stop).kill()}catch{}
                    try{(Get-Process -name AcroRd32 -ErrorAction Stop).kill()}catch{}
                    $currentreg = @(
                        'SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\',
                        'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\'
                    )
                    foreach($regkey in $currentreg){
                        $RegBase = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,"$env:computername")
                        $CurrentRegKey = $RegBase.OpenSubKey($regkey)
                            $CurrentRegKey.GetSubKeyNames() | ForEach-Object {
                            $a = ($RegBase.OpenSubKey("$regkey$_")).GetValue('displayname')
                            $b = $_
                            switch($a -match "Adobe Acrobat Reader"){
                                $true{
                                    Write-Host "Removing $a. $b"
                                    msiexec /X$b /qn REBOOT=ReallySuppress /l*v c:\users\public\$a.log | Out-Null
                                }
                            }
                        }
                    }
                }
                write-host "Waiting"
                Start-Sleep 20
                #PSExec \\$Comp C:\AdobeReader\InstallReader.bat
                Invoke-Command -Session $Session -ScriptBlock{
                    Write-Host "Installing New Reader"
                    try{(Get-Process -name iexplore -ErrorAction Stop).Kill()}catch{}
                    try{(Get-Process -name firefox -ErrorAction Stop).kill()}catch{}
                    try{(Get-Process -name AcroRd32 -ErrorAction Stop).kill()}catch{}
                    $InstallProcess = Start-Process -FilePath C:\AdobeReader\AcroRdrDC1801120058_en_US.exe -ArgumentList "/sAll" -PassThru
                    Wait-Process $InstallProcess.Id
                }
                Write-Host "Completed $Comp, Cleaning Up." -ForegroundColor Green
                Remove-PSSession $Session
                Remove-Item "\\$Comp\C$\AdobeReader" -Recurse -Force
                "$(Get-Date) - $Comp - Push-Reader Script Completed Successfully by $(whoami)" | Out-file '\\nent95kbazvs003\MCFPAC\3DMLG\CLB-3\Longboard 2018\H&S Company\S-6\3. Data Section\Scripts\Logs\AdobeReader.log' -Append -Force
            }catch{
                Write-host "$Comp Failed. $_" -ForegroundColor Magenta
                "$(Get-Date) - $Comp - Push-Reader Script by $(whoami) Failed: $_" | Out-file '\\nent95kbazvs003\MCFPAC\3DMLG\CLB-3\Longboard 2018\H&S Company\S-6\3. Data Section\Scripts\Logs\AdobeReader.log' -Append -Force
            }
            get-RemoteProgram -ComputerName $Comp -Software "Adobe Acrobat Reader" -Property DisplayVersion,InstallDate
        }
    }
    Get-Process -Id $PID | Invoke-FlashWindow
}#End Function Push-Reader#>

#80004005 and a couple others
function Remove-RegPol{
    <#
	.Synopsis
	Deletes the Registry.pol file and prompts a GPUpdate to rebuild group policy on the remote machine.

	.DESCRIPTION
	Deletes the Registry.pol file and prompts a GPUpdate to rebuild group policy on the remote machine.

	.PARAMETER ComputerName
	The computer to which to delete Registry.pol

	.EXAMPLE
	Remove-RegPol WLQUAN00264J45N
	#>
    param([string[]]$ComputerName)
    $ComputerName = Validate-MultiInput $ComputerName
    Invoke-Command -ScriptBlock{
        if((test-path C:\windows\System32\grouppolicy\machine\Registry.pol) -ne $false){
            ri C:\windows\System32\grouppolicy\machine\Registry.pol
        }
        gpupdate.exe /force
    } -ComputerName $ComputerName
    sleep 15
    Trigger-ClientCycles -ComputerName $ComputerName
    Write-host "Reg.pol removed, GPUpdate Run."
}

#Getting it moving again
function Trigger-ClientCycles{
    <#
	.Synopsis
	Kicks off the 5 primary cycles on the SCCM Client

	.DESCRIPTION
	Kicks off the 5 primary cycles on the SCCM Client.

	.PARAMETER ComputerName
	The computer to which to delete Registry.pol

	.EXAMPLE
	Remove-RegPol WLQUAN00264J45N
	#>
    param([string[]]$ComputerName)
    $ComputerName = Validate-MultiInput $ComputerName
    Invoke-Command -ScriptBlock{
    try{Invoke-WmiMethod -Namespace root\ccm -Class sms_client -Name TriggerSchedule -ArgumentList '{00000000-0000-0000-0000-000000000121}' | out-null}catch{}
    try{Invoke-WmiMethod -Namespace root\ccm -Class sms_client -Name TriggerSchedule -ArgumentList '{00000000-0000-0000-0000-000000000021}' | out-null}catch{}
    try{Invoke-WmiMethod -Namespace root\ccm -Class sms_client -Name TriggerSchedule -ArgumentList '{00000000-0000-0000-0000-000000000022}' | out-null}catch{}
    try{Invoke-WmiMethod -Namespace root\ccm -Class sms_client -Name TriggerSchedule -ArgumentList '{00000000-0000-0000-0000-000000000113}' | out-null}catch{}
    try{Invoke-WmiMethod -Namespace root\ccm -Class sms_client -Name TriggerSchedule -ArgumentList '{00000000-0000-0000-0000-000000000108}' | out-null}catch{}
    write-host "Cycles kicked off on $env:COMPUTERNAME"
    } -ComputerName $ComputerName
}

#Errorcode for Failed SUP Install = ~Missing WSUS Server Policy~
function Fix-SupReg{
    param([string[]]$ComputerName)
    $ComputerName = Validate-MultiInput $ComputerName
    Invoke-Command -ScriptBlock{
        New-Item HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name AU -ItemType KEY -Force
        New-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name WUServer -Value "https://QUAN6911.MCDSUS.MCDS.USMC.MIL:8531" -PropertyType String -Force
        New-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name WUStatusServer -Value "https://QUAN6911.MCDSUS.MCDS.USMC.MIL:8531" -PropertyType String -Force
        New-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU -Name UseWUServer -Value "1" -PropertyType Dword -Force
    } -ComputerName $ComputerName
    Trigger-ClientCycles -ComputerName $ComputerName
}

#Installs all avial updates
function Install-SCCMUpdates{
	<#
	.Synopsis
	Kicks off all pending Updates / Installs on the remote SCCM Client

	.DESCRIPTION
	Kicks off all pending Updates / Installs on the remote SCCM Client

	.PARAMETER ComputerName
	Computer on which to kick off installs.

	.EXAMPLE
    Install-SCCMUpdates WLQUAN00264K29N
	#>
    param([string[]]$ComputerName)
    $ComputerName = Validate-MultiInput $ComputerName
    Invoke-Command -ScriptBlock{
        $Application = (Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_SoftwareUpdate)
        $Application | select name,evaluationstate,errorcode,pscomputername
        Invoke-WmiMethod -Class CCM_SoftwareUpdatesManager -Name InstallUpdates -Namespace root\ccm\clientsdk -ArgumentList (,$Application) | out-null
    } -ComputerName $ComputerName
}

function Push-SCCM{
	<#
	.Synopsis
	Uninstalls and Re-installs the SCCM Client

	.DESCRIPTION
    A tool for repairing the SCCM Client. First attempts a gracefull uninstall of the client using a fresh copy of the executible pulled straigt from MCCOG's server. Then attempts to remove some folders that sometimes cause issues. These frequently fail and provide a warning. These do not indicate failure.
    If the -Deep switch is included the function will then attempt to repair the WMI framework including a Deep-Clean at level 4.
    Finally, the SCCM Client is re-installed.

	.PARAMETER ComputerName
	The computer on which to repair the SCCM Client

	.PARAMETER Deep
	Causes the script to conduct a repair of WMI after the uninstall and before the re-install.

	.EXAMPLE
	Push-SCCM WLQUAN00264J19N

	Description:
	Will uninstall and re-install the SCCM Client on the named computer.

    .EXAMPLE
    Push-SCCM WLQUAN00264K29N -Deep

    Description:
    Will uninstall, attempt repairs of the WMI Repository, and then reinstall a fresh copy of the SCCM Client on the remote machine.
	#>
    param (
        [string][Parameter(Mandatory=$True, Position=0)]$ComputerName,
        [switch]$Deep
    )
    $ComputerName = $ComputerName.ToUpper() #Because OCD
    switch (Test-Online -ComputerName $ComputerName){
        0{
            try{
                Write-Host "Copying Installation Files to $ComputerName" -ForegroundColor Yellow
                new-item -path "\\$ComputerName\C$\Client" -itemtype Directory -Force | Out-Null
                Copy-Item "\\ecss6921\client\" "\\$ComputerName\C$\" -Recurse -Force
                write-host "Kicking Off Installation. If a previous installation exists it will be removed."
                $Session = New-PSSession -ComputerName $ComputerName

                Invoke-Command -Session $Session -ScriptBlock {Start-Process -FilePath 'C:\Client\ccmsetup.exe' -ArgumentList "/uninstall"}
                write-host "Waiting 60 sec for Uninstall."
                sleep 60
                [bool]$sucessful = $false
                do{
                    write-host "Checking to see if Uninstall was Sucessful"
                    $LogTail = Get-Content \\$ComputerName\C$\windows\ccmsetup\logs\ccmsetup.log -tail 1
                    try{
                        Write-Host $($logtail.Substring(7,$logtail.Length-7).split(']')|select -First 1) #Debugging
                    }catch{}
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
                <#Mallet Edition#>
                <#Old Install File Clean Up#>
                sleep 20
                Try{
                    #This will destroy the directory
                    Remove-Item \\$ComputerName\C$\windows\ccm -Force -Recurse -ErrorAction Stop 
                }Catch{
                    Write-Warning "C:\windows\CCM Files Still in use. SCCM uninstall may not have completed."         
                }
                #CCMSetup Directory Removal 
                Try{
                    #This will destroy the directory
                    Remove-Item "\\$ComputerName\C$\windows\CCMSetup" -Force -Recurse -ErrorAction Stop 
                }Catch{
                    Write-Warning "C:\Windows\CCMSetup Files Still in use. SCCM uninstall may not have completed."        
                }
                try{
                    Stop-Service -Name BITS
                    sleep 10
                    Remove-Item "\\$ComputerName\C$\Windows\ccmcache" -Force -Recurse -ErrorAction Stop
                    Start-Service -Name BITS
                }catch{
                    Write-Warning "Error Removing ccmcache"
                }
                
                if($Deep){
                    #Deep Clean Requsted. Setting to Level 4
                    invoke-command -Session $Session -ScriptBlock{
                        Stop-Service -Name BITS
                        taskkill /im ccmsetup.exe /f
                        ipconfig /flushdns
                        Remove-Item "C:\windows\system32\grouppolicy\machine\registry.pol"
                        cmd /C del "%ALLUSERSPROFILE%\Application Data\Microsoft\Network\Downloader\*.old" 
                        cmd /C ren "%ALLUSERSPROFILE%\Application Data\Microsoft\Network\Downloader\qmgr0.dat" qmgr0.dat.old
                        cmd /C ren "%ALLUSERSPROFILE%\Application Data\Microsoft\Network\Downloader\qmgr1.dat" qmgr1.dat.old
                        
                        
                        
                        #gpupdate.exe /force #This line has been commented this is causing gpupdate to be run twice.
                        #gpupdate runs in thge invoke command below.
                        #Start-Service -Name BITS
                        Invoke-Command -ScriptBlock{ #Remove Registry.pol
                            if((test-path C:\windows\System32\grouppolicy\machine\Registry.pol) -ne $false){
                                ri C:\windows\System32\grouppolicy\machine\Registry.pol
                            }
                            gpupdate.exe /force
                        }
                    }
                    Deep-Clean -ComputerName $ComputerName -Depth 4
                    write-host "Deep Clean finished. Waiting 1 min before beginning install" -ForegroundColor Yellow
                    sleep 60
                }

                #previous install was either removed or no never existed, install fresh copy
                Write-Host "Beginning New Installation"
                #create bat file on remote system
        #        New-Item -ItemType File -Value "C:\Client\ccmsetup.exe /forceinstall" -Path \\$ComputerName\C$\Client\install.bat -Force | Out-Null
        #        psexec \\$ComputerName C:\Client\install.bat #Call Bat File
                Invoke-Command -Session $Session -ScriptBlock{
                    Start-Process -FilePath C:\Client\ccmsetup.exe -ArgumentList "/forceinstall"
                }
                #Write-Host "LastExitCode "$LASTEXITCODE #Debugging
                write-host "Giving the Installer 2 Mins to work."
                sleep 120
                do{
                    $LogTail = Get-Content \\$ComputerName\C$\windows\ccmsetup\logs\ccmsetup.log -tail 1
                    try{
                        Write-Host $($logtail.Substring(7,$logtail.Length-7).split(']')|select -First 1) #Debugging
                    }catch{}
                    $sucessful = [bool](($LogTail -like "*exiting with return code *") -or ($LogTail -like "*error code*") -or ($LogTail -match "Next retry in"))#This could be written better. Started out as a single elseif but then just kept growing with more conditions
                    if(!$sucessful){
                        write-host "Install still in progress - waiting 30 sec. before next check" -ForegroundColor Yellow
                        sleep 30
                    }elseif ($LogTail -like "*exiting with return code 0*"){
                        write-host "Install Successful. No Reboot Required" -ForegroundColor Green
                        "$(Get-Date) - $ComputerName - Push-SCCM Script Completed Successfully by $(whoami)" | Out-file '\\nent95kbazvs003\MCFPAC\3DMLG\CLB-3\Longboard 2018\H&S Company\S-6\3. Data Section\Scripts\Logs\SCCM.log' -Append -Force
                    }elseif ($LogTail -like "*exiting with return code 7*"){
                        write-host "Install Successful. Reboot Required" -ForegroundColor Yellow
                        do{
                            $Restart = Read-Host "Reboot Now? (y/n)"
                        }while($restart -notlike 'y' -and $restart -notlike 'n')
                        if ($restart -like 'y'){
                            Restart-Computer -ComputerName $ComputerName -Force
                            Write-Host "Restart command sent to $ComputerName" -ForegroundColor Green
                        }
                        "$(Get-Date) - $ComputerName - Push-SCCM Script Completed Successfully by $(whoami)" | Out-file '\\nent95kbazvs003\MCFPAC\3DMLG\CLB-3\Longboard 2018\H&S Company\S-6\3. Data Section\Scripts\Logs\SCCM.log' -Append -Force
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
                "$(Get-Date) - $ComputerName - Push SCCM Script failed. Error: $_ - $(whoami)" | Out-file '\\nent95kbazvs003\MCFPAC\3DMLG\CLB-3\Longboard 2018\H&S Company\S-6\3. Data Section\Scripts\Logs\SCCM.log' -Append -Force
                if($_ -like "Install Failed"){
                    Write-Warning "The Installation Failed. Here is the last line of the Log: `n$LogTail"
                }else{
                    Write-Warning "Failed: $_"
                }
            }
        }
    }
    #Invoke-WmiMethod -Namespace root\ccm -Class sms_client -Name setassignedsite -ArgumentList "MC3" -ComputerName $ComputerName | Out-Null #Set Site to MC3
    sleep 4
    Set-SCCMSite $ComputerName
    Trigger-ClientCycles $ComputerName
    remove-item "\\$ComputerName\C$\Client" -Recurse -Force -ErrorAction SilentlyContinue #Housekeeping
    Remove-PSSession -Session $Session
    Get-Process -Id $PID | Invoke-FlashWindow
}

function Deep-Clean{
    <#
	.Synopsis
	A tool for checking or repairing the WMI infrustructure on a remote computer.

	.DESCRIPTION
    Available in 4 levels:
    Check, Repair, Delete, and Delete & Re-register
    Check - Query WMI on its own health - I've never seen WMI actually tell you its unheathly...
    Repair - Instuct WMI to reset itself
    Delete - Deletes the WMI repository and takes no further action. The Repository will eventually realize this and rebuild itself.
    Rebuild - Deletes the WMI repository and reregisters all MOF files to attempt to manually rebuild the repository	
    The depth may be included by switch or the script will ask for it on run.

	.PARAMETER ComputerName
	The computer on which to check/repair the WMI Repositroy

	.PARAMETER Depth
	Specify the depth - useful if including in scripts.

	.EXAMPLE
	Deep-Clean WLQUAN00264456N

    Description:
    Begins the Deep-Clean on the remote computer.

    .EXAMPLE
    Deep-Clean WLQUAN00264456N -Depth 3

	Description:
	Conducts a deletion of the WMI Repository without any further prompts.
	#>
    param(
        [string][Parameter(Mandatory=$True, Position=0)]$ComputerName,
        [int]$Depth = 0
    )
    $ComputerName = $ComputerName.ToUpper() #Because OCD
    Write-Warning "Use this function with extreme caution. It can break things to the point of requireing re-image."
    #declare variables
    $Consistent = $null
    $PSRemoting = $null


    function check-wmiPSR{
        #write-host $ComputerName #Debugging
        $Results = Invoke-Command -Session $Session -ScriptBlock {winmgmt /verifyrepository}
        If($Results -like "WMI repository is consistent"){
            $Consistent = $True
        }else{
            $Consistent = $False
        }
        write-host $Results
        if ((!$Consistent) -and ($Depth -like "1")){ #Don't want to offer to salvage if we're already resetting
            do{
                $Salvage = Read-Host "Would you like to attempt to salvage the repository? (y/n)"
            }while($Salvage -notlike 'y' -and $Salvage -notlike 'n')
            if ($Salvage -like 'y'){
                Invoke-Command -Session $Session  -ScriptBlock {winmgmt /salvagerepository} | Out-Null
                Write-host "Repository Salvaged"
            }
        }
    }
    function check-wmiPSX{
        psexec \\$ComputerName winmgmt /verifyrepository
    }
    function reset-wmiPSR{
        Invoke-Command -Session $Session -ScriptBlock{
            Stop-Service -Name Winmgmt -Force
            sleep 5
            winmgmt /resetrepository
            sleep 5
            Start-Service -Name Winmgmt
        }
        Write-Host "WMI Repository on $ComputerName has been reset. Please wait aprox. 20 min. as it rebuilds itself"
    }

    function reset-wmiPSX{
        #Stop WINMGMT
        try{
            (Get-Service -ComputerName $ComputerName -Name Winmgmt).Stop()
            write-host "Stopped WMI Service on $ComputerName"
        }catch{
            Write-Warning "Failed to stop service. Can not Continue `n$_"
            Break
        }
        #Run the command using PSExec
        sleep 5
        PsExec.exe \\$ComputerName winmgmt /resetrepository
        sleep 5
        #Restart the service (its probably already running)
        try{
            $WMIService = Get-Service -ComputerName $ComputerName -Name Winmgmt
            If ($WMIService.Status -notlike "Running"){
                $WMIService.Start()
                Write-Host "WMI Service Started on $ComputerName" -ForegroundColor Green
            }else{
                Write-Host "WMI Service was already running on $ComputerName" -ForegroundColor Green
            }
        }catch{
            Write-Warning "Failed to start the service.`n$_"
        }
        Write-Host "WMI Repository on $ComputerName has been reset. Please wait aprox. 20 min. as it rebuilds itself"
    }

    function rebuild-wmiPSR{
        Invoke-Command -Session $Session -ScriptBlock{
            Stop-Service -Name Winmgmt -Force
            sleep 5
            $loop = $false
            do{
            if((Get-service -Name Winmgmt | Select -ExpandProperty Status) -eq "Stopped"){
                Remove-Item C:\Windows\System32\wbem\Repository -Recurse -Force
                $loop = $false
            }else{
                write-warning "Service isn't stopped. Waiting 10 Sec."
                sleep 10
                $loop = $true
            }
            }while($loop)
            write-host "Repository deleted"
            sleep 3
            Start-Service -Name Winmgmt
        }
        if($Depth -like "3"){write-host "WMI Repository of $ComputerName has been removed. Please allow aprox 25 min. as it rebuilds itself" -ForegroundColor Green}
    }
    function rebuild-wmiPSX{
        #Stop WINMGMT
        try{
            (Get-Service -ComputerName $ComputerName -Name Winmgmt).Stop()
            write-host "Stopped WMI Service on $ComputerName"
        }catch{
            Write-Warning "Failed to stop service. Can not Continue `n$_"
            Break
        }
        Sleep 5
        try{
            Remove-Item \\$ComputerName\C$\Windows\System32\wbem\Repository -Recurse -Force
        }catch{
            Write-Warning "Failed to blow the repositry away. Exiting"
            Break
        }
        Sleep 3
        try{
            $WMIService = Get-Service -ComputerName $ComputerName -Name Winmgmt
            If ($WMIService.Status -notlike "Running"){
                $WMIService.Start()
                Write-Host "WMI Service Started on $ComputerName" -ForegroundColor Green
            }else{
                Write-Host "WMI Service was already running on $ComputerName" -ForegroundColor Green
            }
        }catch{
            Write-Warning "Failed to start the service.`n$_"
        }
        if($Depth -like "3"){write-host "WMI Repository of $ComputerName has been removed. Please allow aprox 25 min. as it rebuilds itself" -ForegroundColor Green}
    }

    function OMG-wmiPSR{
        rebuild-wmiPSR
        if (!(test-path "\\$ComputerName\C$\Software")){
            New-Item -ItemType Directory "\\$ComputerName\C$\Software"
        }
        Copy-Item '\\nent95kbazvs003\MCFPAC\3DMLG\CLB-3\Longboard 2018\H&S Company\S-6\3. Data Section\Scripts\registration.bat' "\\$Computername\C$\Software" -Force
        Invoke-Command -Session $Session -ScriptBlock{& C:\Software\registration.bat} 
        write-host "`n`nThe WMI Repository on $ComputerName has been removed and all DLLs were un-registered and then re-registered. A restart has been scheduled on the remote machine and if a user was logged on, the user has been notified." -ForegroundColor Green
    }
    function OMG-wmiPSX{
        rebuild-wmiPSX
        if (!(test-path "\\$ComputerName\C$\Software")){
            New-Item -ItemType Directory "\\$ComputerName\C$\Software"
        }
        Copy-Item '\\nent95kbazvs003\MCFPAC\3DMLG\CLB-3\Longboard 2018\H&S Company\S-6\3. Data Section\Scripts\registration.bat' "\\$Computername\C$\Software" -Force
        PsExec.exe \\$ComputerName C:\Software\registration.bat
        write-host "`n`nThe WMI Repository on $ComputerName has been removed and all DLLs were un-registered and then re-registered. A restart has been scheduled on the remote machine and if a user was logged on, the user has been notified." -ForegroundColor Green
    }
    #Begin Action Here <----------------------------------------------------------------------------
    Switch (Test-Online -ComputerName $ComputerName){
        0{
            try{
                $Session = New-PSSession -ComputerName $ComputerName -ErrorAction Stop
                #write-host "Remoting enabled" #Debugging
                [bool]$PSRemoting = $True
            }catch{
                [bool]$PSRemoting = $False
                #write-host "Remoting not enabled`n$_`n`nExiting" #Debugging
                #break
            }
            if(($Depth -lt 1) -or ($Depth -gt 4) -or ($Depth -eq $Null)){
                do{
                    Write-host "Depth Options:`n1) Check the Repository`n2) Reset the repository`n3) Blow Away Repository`n4) Blow Away and Re-register DLLs"
                    $Depth = Read-Host "Depth"
                }while(($Depth -lt 1) -or ($Depth -gt 4))
            }
            switch($Depth){
                1{
                    if ($PSRemoting){
                        check-wmiPSR
                    }else{
                        check-wmiPSX
                    }
                }
                2{
                    if ($PSRemoting){
                        check-wmiPSR
                        reset-wmiPSR
                    }else{
                        check-wmiPSX
                        reset-wmiPSX
                    }
                }
                3{
                    if ($PSRemoting){
                        check-wmiPSR
                        rebuild-wmiPSR
                    }else{
                        check-wmiPSX
                        reset-wmiPSX
                    }
                }
                4{
                    if ($PSRemoting){
                        check-wmiPSR
                        OMG-wmiPSR
                    }else{
                        check-wmiPSX
                        OMG-wmiPSX
                    }
                }
            }
            "$(Get-Date) - WARNING - $ComputerName - Deep-Clean Script Depth=$Depth Completed Successfully by $(whoami)" | Out-file '\\nent95kbazvs003\MCFPAC\3DMLG\CLB-3\Longboard 2018\H&S Company\S-6\3. Data Section\Scripts\Logs\SCCM.log' -Append -Force
        }
    }
    try{Remove-PSSession -Session $Session -ErrorAction Stop}catch{} #Housekeeping
}

function QC-Many{
    enter-info
    $Computers = $Global:Results
    foreach ($Computer in $Computers){
        $Computer = $Computer.trim()
        QC $Computer
    }
}

Function Get-Uptime {
 	<#
	.Synopsis
	Querys a remote computer for how long it has been on.

	.DESCRIPTION
	Querys a remote computer for how long it has been on.

	.PARAMETER ComputerName
	The computer to get the uptime of.

	.EXAMPLE
	get-UpTime WLQUAN00264A01N

	Description:
	Retrieve the uptime of the remote computer.
	#>
    [CmdletBinding()] 
    param ( 
        [Parameter(Mandatory=$false, 
                        Position=0, 
                        ValueFromPipeline=$true, 
                        ValueFromPipelineByPropertyName=$true)] 
        [Alias("Name")] 
        [string[]]$ComputerName=$env:COMPUTERNAME, 
        $Credential = [System.Management.Automation.PSCredential]::Empty 
        ) 
 
    begin{} 
 
    #Need to verify that the hostname is valid in DNS 
    process { 
        foreach ($Computer in $ComputerName) { 
            try { 
                $hostdns = [System.Net.DNS]::GetHostEntry($Computer) 
                $OS = Get-WmiObject win32_operatingsystem -ComputerName $Computer -ErrorAction Stop -Credential $Credential 
                $BootTime = $OS.ConvertToDateTime($OS.LastBootUpTime) 
                $Uptime = $OS.ConvertToDateTime($OS.LocalDateTime) - $boottime 
                $propHash = [ordered]@{ 
                    ComputerName = $Computer 
                    BootTime     = $BootTime 
                    Uptime       = $Uptime 
                    } 
                $objComputerUptime = New-Object PSOBject -Property $propHash 
                $objComputerUptime 
                }  
            catch [Exception] { 
                Write-Output "$computer $($_.Exception.Message)" 
                #return 
                } 
        } 
    } 
    end{} 
}#End Function Get-Uptime

function Generate-Names{
    Param ([int]$StartNumber,
    [int]$NumberToMake,
    [string]$UIC = "00264",
    [string]$Type = "L")
    new-item -ItemType file -Path C:\Users\Public\Documents\NewCompNames.txt -Force
    for($i=0;$i -lt $NumberToMake;$i++){
        "W"+($Type.ToUpper())+"QUAN"+"$UIC"+($StartNumber.ToString("000"))+"S" | Out-File C:\Users\Public\Documents\NewCompNames.txt -Append
        $StartNumber++
    }
    notepad C:\Users\Public\Documents\NewCompNames.txt
}


Function Invoke-FlashWindow {
    <#
        .SYSNOPSIS
            Flashes a window that has been hidden or minimized to the taskbar

        .DESCRIPTION
            Flashes a window that has been hidden or minimized to the taskbar

        .PARAMETER MainWindowHandle
            Handle of the window that will be set to flash

        .PARAMETER FlashRate
            The rate at which the window is to be flashed, in milliseconds.

            Default value is: 0 (Default cursor blink rate)

        .PARAMETER FlashCount
            The number of times to flash the window.

            Default value is: 2147483647

        .NOTES
            Name: Invoke-FlashWindow
            Author: Boe Prox
            Created: 26 AUG 2013
            Version History
                1.0 -- 26 AUG 2013 -- Boe Prox
                    -Initial Creation

        .LINK
            http://pinvoke.net/default.aspx/user32/FlashWindowEx.html
            http://msdn.microsoft.com/en-us/library/windows/desktop/ms679347(v=vs.85).aspx

        .EXAMPLE
            Start-Sleep -Seconds 5; Get-Process -Id $PID | Invoke-FlashWindow
            #Minimize or take focus off of console
 
            Description
            -----------
            PowerShell console taskbar window will begin flashing. This will only work if the focus is taken
            off of the console, or it is minimized.

        .EXAMPLE
            Invoke-FlashWindow -MainWindowHandle 565298 -FlashRate 150 -FlashCount 10

            Description
            -----------
            Flashes the window of handle 565298 for a total of 10 cycles while blinking every 150 milliseconds.
    #>
    [cmdletbinding()]
    Param (
        [parameter(ValueFromPipeline=$True,ValueFromPipeLineByPropertyName=$True)]
        [intptr]$MainWindowHandle,
        [parameter()]
        [int]$FlashRate = 0,
        [parameter()]
        [int]$FlashCount = ([int]::MaxValue)
    )
    Begin {        
        Try {
            $null = [Window]
        } Catch {
            Add-Type -TypeDefinition @"
            using System;
            using System.Collections.Generic;
            using System.Text;
            using System.Runtime.InteropServices;

            public class Window
            {
                [StructLayout(LayoutKind.Sequential)]
                public struct FLASHWINFO
                {
                    public UInt32 cbSize;
                    public IntPtr hwnd;
                    public UInt32 dwFlags;
                    public UInt32 uCount;
                    public UInt32 dwTimeout;
                }

                //Stop flashing. The system restores the window to its original state. 
                const UInt32 FLASHW_STOP = 0;
                //Flash the window caption. 
                const UInt32 FLASHW_CAPTION = 1;
                //Flash the taskbar button. 
                const UInt32 FLASHW_TRAY = 2;
                //Flash both the window caption and taskbar button.
                //This is equivalent to setting the FLASHW_CAPTION | FLASHW_TRAY flags. 
                const UInt32 FLASHW_ALL = 3;
                //Flash continuously, until the FLASHW_STOP flag is set. 
                const UInt32 FLASHW_TIMER = 4;
                //Flash continuously until the window comes to the foreground. 
                const UInt32 FLASHW_TIMERNOFG = 12; 


                [DllImport("user32.dll")]
                [return: MarshalAs(UnmanagedType.Bool)]
                static extern bool FlashWindowEx(ref FLASHWINFO pwfi);

                public static bool FlashWindow(IntPtr handle, UInt32 timeout, UInt32 count)
                {
                    IntPtr hWnd = handle;
                    FLASHWINFO fInfo = new FLASHWINFO();

                    fInfo.cbSize = Convert.ToUInt32(Marshal.SizeOf(fInfo));
                    fInfo.hwnd = hWnd;
                    fInfo.dwFlags = FLASHW_ALL | FLASHW_TIMERNOFG;
                    fInfo.uCount = count;
                    fInfo.dwTimeout = timeout;

                    return FlashWindowEx(ref fInfo);
                }
            }
"@
        }
    }
    Process {
        ForEach ($handle in $MainWindowHandle) {
            Write-Verbose ("Flashing window: {0}" -f $handle)
            $null = [Window]::FlashWindow($handle,$FlashRate,$FlashCount)
        }
    }
}#End FlashWindow

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

function enter-info
{

    $objForm1 = New-Object system.Windows.Forms.Form
    $objForm1.Text = "Bulk Entry"
    $objForm1.Size = New-Object System.Drawing.Size(300,630)
    $objForm1.StartPosition = "CenterScreen"
    $objForm1.Topmost = $True
    $objForm1.FormBorderStyle = 'FixedToolWindow'

    $textbox1label = New-Object System.Windows.Forms.Label
    $textbox1label.Location = New-Object System.Drawing.Size(10,10) 
    $textbox1label.AutoSize = $true
    $textbox1label.Text = "Names:"
    $textbox1label.Font = New-Object System.Drawing.Font("Microsoft Sans Serif",11,[System.Drawing.FontStyle]::BOLD)

    $textbox1Message = New-Object System.Windows.Forms.Label
    $textbox1Message.Location = New-Object System.Drawing.Size(10,35) 
    $textbox1Message.AutoSize = $true
    $textbox1Message.Text = "Copy the Computer Names for the function below. Ensure that no trailing new line is left at the last line."
    $textbox1Message.MaximumSize = new-Object System.Drawing.Size(250, 0)

    $objTextBox1 = New-Object System.Windows.Forms.TextBox 
    $objTextBox1.Multiline = $True;
    $objTextBox1.Location = New-Object System.Drawing.Size(10,105) 
    $objTextBox1.Size = New-Object System.Drawing.Size(273,450)
    $objTextBox1.Scrollbars = "Vertical"
    
    $AcceptButton = New-Object System.Windows.Forms.Button
    $AcceptButton.Location = New-Object System.Drawing.Size(200,570)
    $AcceptButton.Size = New-Object System.Drawing.Size(80,23)
    $AcceptButton.Text = "Continue"
    $AcceptButton.DialogResult=[System.Windows.Forms.DialogResult]::OK
    
    $AbortButton = New-Object System.Windows.Forms.Button
    $AbortButton.Location = New-Object System.Drawing.Size(120,570)
    $AbortButton.Size = New-Object System.Drawing.Size(80,23)
    $AbortButton.Text = "Abort"
    
    $AbortButton.Add_Click({
        $objForm1.Close(); 
        $objForm1.Dispose()
        $textbox1label.Dispose();
        $textbox1Message.Dispose();
        $objTextBox1.Dispose();
        $AcceptButton.Dispose();
        $AbortButton.Dispose();
        $global:currentcompcount= 0
    })
    $AcceptButton.Add_Click({convert-inputtolist;
        $objForm1.Close(); 
        $objForm1.Dispose()
        $textbox1label.Dispose();
        $textbox1Message.Dispose();
        $objTextBox1.Dispose();
        $AcceptButton.Dispose();
        $AbortButton.Dispose();
        $global:currentcompcount= 0
        
    })

    $objForm1.Controls.Add($objTextBox1) 
    $objForm1.Controls.Add($AcceptButton)
    $objForm1.Controls.Add($AbortButton)
    $objForm1.Controls.Add($textbox1label)
    $objForm1.Controls.Add($textbox1Message) 
    $objForm1.ShowDialog()

}

Function convert-inputtolist
{
$global:textboxresults = @()
$global:results = $objTextBox1.text -split '[\n]'
}

Function Reset-SoftwareDistribution{
<#
    .SYNOPSIS
    Renames the Software Distribution Folder.
    .DESCRIPTION
    Renames the Software Distribution Folder to .old in order to mitigate Error Code 
    .EXAMPLE
    Reset-SoftwareDisribution -ComputerName WLQUAN00264123N

    Renames the Software Distribution folder on WLQUAN00264123N.
    .EXAMPLE
    Reset-SoftwareDisribution -ComputerName WLQUAN00264123N,WLQUAN00264124N,WLQUAN002640B6N

    Renames the Software Distribution folder on all of the listed computers.
    .PARAMETER ComputerName
    The computer name or names on which to rename the folder.
#>
param(

    [String[]][Parameter(Mandatory=$True, Position=0)]$ComputerName
    
         

)
    
    Invoke-command -ComputerName $ComputerName -ScriptBlock {
    
        Stop-Service -ServiceName wuauserv
        Stop-Service -ServiceName BITS
        Stop-Service -ServiceName CCMEXEC
        Remove-Item C:\windows\SoftwareDistribution.old -force -recurse -erroraction SilentlyContinue
        Rename-Item C:\windows\SoftwareDistribution SoftwareDistribution.old
    
        Start-Service -ServiceName wuauserv
        Start-Service -ServiceName BITS
        Start-Service -ServiceName CCMEXEC

    }
}