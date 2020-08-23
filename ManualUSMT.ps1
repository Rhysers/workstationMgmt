function download-Files{
    param (
    $CompName,
    $Creds
    )
    $toInvoke = $false
    try{
        write-host "Checking if PS Remoting is already on"
        $Global:Session = New-PSSession -ComputerName $Compname -ErrorAction Stop
        $toInvoke = $True
    }catch{
        try{
            write-host "Turning on PSRemoting"
            psexec -h \\$Compname cmd /c powershell Enable-PSRemoting -force -skipnetworkprofilecheck
            If ($LASTEXITCODE -eq 0){
                #PSExec succeeded in turning PSRemoting on. Try PSRemoting Again
                $Global:Session = New-PSSession -ComputerName $Compname -ErrorAction Stop
                    #Error action here will cause a failure to thow us into the catch statment which will
                    #fail back to a Manual Copy
                $toInvoke = $True
            }else{
                #PSExec Failed to enable PSRemoting. Failback to Manual Copy
                throw "Failed to Enable PSRemoting"
            }
        }Catch{
            try{
                #Do it the old way.
                Write-Host "PSRemoting Failed. Copying Items over Manually" -ForegroundColor Yellow
                Copy-Item -Path "\\quan0702\USMT\Tools\Manual USMT" -Recurse -Destination \\$CompName\c$ -Force -ErrorAction Stop
                Write-host "Finished Copying Items" -ForegroundColor Green
                return $true
            }catch{
                #Old way failed too. Return the exception to the calling function
                return $_
            }
        }
    }
    if ($toInvoke){
        Invoke-Command -Session $Global:Session -ScriptBlock{
            try{
                write-host "Creating PSDrive" -ForegroundColor Yellow
                New-PSDrive -Name QUAN0702 -PSProvider FileSystem -Root \\QUAN0702\USMT\TOOLS -Credential $args[0] -ErrorAction Stop
                Write-Host "Copying files down from share drive..." -ForegroundColor Yellow
                Copy-Item "QUAN0702:\Manual USMT" C:\ -Recurse -Force
                Write-Host "done" -ForegroundColor DarkGreen
            }catch{
                write-warning $_
                return $_
            }
        } -ArgumentList $Creds,$true
    
        #Remove-PSSession $Session -ErrorAction SilentlyContinue
        #it worked. Return $True
        #write-host "WTF?"
        return $True
    }
}

    function Start-Restore{
    $Global:Session = $null
    
    $Creds = Get-Credential -Message "Enter the password for the account" -UserName rhys.j.ferris@mcdsus.mcds.usmc.mil
    $AccountStatus = get-aduser -Identity ($Creds.UserName.Split('@') | Select -First 1) -Properties Lockedout,SmartCardLogonRequired,DisplayName
    if($AccountStatus.LockedOut -match "True"){
        Write-Warning "$($AccountStatus.displayname) is locked out."
        return 1
    }
    if($AccountStatus.SmartcardLogonRequired -match "True"){
        Write-Warning "SmartCard Logon is enforced for $($AccountStatus.displayname)"
        return 1
    }
    if($AccountStatus.Enabled -match "False"){
        Write-Warning "$($AccountStatus.displayname) is disabled"
        return 1
    }
    $ComputerName = Read-Host "Computer Name"
    if((test-online -computerName $ComputerName) -eq 0){
        $SerialLocal = Get-WmiObject -computername $ComputerName -class Win32_BIOS | Select -ExpandProperty SerialNumber
        $Results = download-Files -CompName $ComputerName -Creds $Creds
        If($Results){
            new-item -ItemType File -Path "\\$ComputerName\C$\manual USMT\ManualRestore.ps1" -Force
            'Param($SerialNumber)
            write-host $SerialNumber
            [string]$USMTPath = "\\QUAN0702\USMT\$SerialNumber"
            $USMTFolder = (gi "C:\Manual USMT\ManualRestore.ps1").DirectoryName
            Set-Location $USMTFolder
            $loadstate = ".\amd64\loadstate.exe"
            $date = (get-date)
            Start-Process -WindowStyle Hidden $loadstate "\\QUAN0702\USMT\$SerialNumber /v:13 /l:$USMTPath\Logs\SMSTSLog\LoadState.log /progress:$USMTPath\Logs\SMSTSLog\LoadStateProgress.log /i:.\amd64\migdocs.xml /i:.\amd64\migapp.xml /i:.\amd64\MigMCEDS.xml /config:.\amd64\config.xml"
            get-process -name loadstate' | Out-File "\\$ComputerName\C$\manual USMT\ManualRestore.ps1"
            $SerialNumber = Read-Host "Serial Number to restore from? (Serial of the Machine: $SerialLocal)"
            psexec -s -accepteula \\$ComputerName cmd /c powershell -executionpolicy bypass -file "C:\manual USMT\ManualRestore.ps1" -serialNumber $SerialNumber
        }else{
            Throw $_
        }
        start powershell -ArgumentList "-noprofile","-file $($env:USERPROFILE)\Documents\WindowsPowerShell\USMTMonitoringWindow.ps1",$SerialLocal,"Load"
    }
}

function Start-Backup{
	<#
	.Synopsis
	Kicks off a USMT Backup on the remote computer.

	.DESCRIPTION
    Starts a USMT Backup on a remote computer. Places the backup on \\QUAN0702\USMT.
    This function requires a CLO Exempt account able to access the share drive.	

	.PARAMETER ComputerName
	The computer to which connectivity will be checked

	.PARAMETER Property
	Additional values to be loaded from the registry. Can contain a string or an array of string that will be attempted to retrieve from the registry for each program entry

	.EXAMPLE
	Start-Backup
	#>
    $Global:Session = $null
    $Creds = Get-Credential -Message "Enter the password for the account" -UserName rhys.j.ferris@mcdsus.mcds.usmc.mil
    $AccountStatus = get-aduser -Identity ($Creds.UserName.Split('@') | Select -First 1) -Properties Lockedout,SmartCardLogonRequired,DisplayName
    if($AccountStatus.LockedOut -match "True"){
        Write-Warning "$($AccountStatus.displayname) is locked out."
        return 1
    }
    if($AccountStatus.SmartcardLogonRequired -match "True"){
        Write-Warning "SmartCard Logon is enforced for $($AccountStatus.displayname)"
        return 1
    }
    if($AccountStatus.Enabled -match "False"){
        Write-Warning "$($AccountStatus.displayname) is disabled"
        return 1
    }
    $ComputerName = Read-Host "Computer Name"
    if((test-online -computerName $ComputerName) -eq 0){
        $SerialLocal = Get-WmiObject -computername $ComputerName -class Win32_BIOS | Select -ExpandProperty SerialNumber
        $Results = download-Files -CompName $ComputerName -Creds $Creds
        
        #FreeHand Here
        If($Results){
            #new-item -ItemType File -Path "\\$ComputerName\C$\USMT\ManualRestore.ps1" -Force
            '$SerialNumber = (gwmi -Class win32_bios).serialNumber
            write-host $SerialNumber
            [string]$USMTPath = "\\QUAN0702\USMT\$SerialNumber"
            $USMTFolder = (gi "C:\Manual USMT\ManualRestore.ps1").DirectoryName
            Set-Location $USMTFolder
            $scanstate = ".\amd64\scanstate.exe"
            $date = (get-date)
            Start-Process -WindowStyle Hidden $Scanstate "\\QUAN0702\USMT\$SerialNumber /o /localonly /ue:$ENV:COMPUTERNAME\* /uel:180 /efs:copyraw /v:5 /l:$USMTPath\Logs\SMSTSLog\Scanstate.log /progress:$USMTPath\Logs\SMSTSLog\ScanStateProgress.log /i:.\amd64\migdocs.xml /i:.\amd64\migapp.xml /i:.\amd64\MigMCEDS.xml /config:.\amd64\config.xml"' | Out-File "\\$ComputerName\C$\Manual USMT\ManualUSMT.ps1"

            psexec -s -accepteula \\$ComputerName cmd /c powershell -executionpolicy bypass -file "C:\Manual USMT\ManualUSMT.ps1"
        }else{
            Throw $_
        }
        start powershell -ArgumentList "-noprofile","-file $($env:USERPROFILE)\Documents\WindowsPowerShell\USMTMonitoringWindow.ps1",$SerialLocal,"Scan"
    }
}

'param ($serialnumber,$State)
[string]$USMTPath = "\\QUAN0702\USMT\$SerialNumber"
if($State -like "Scan"){
    $Action = "Backup"
}else{
    $Action = "Restore"
}
$host.ui.RawUI.WindowTitle = "$serialnumber - $Action"
for($i=0;$i -lt 4;$i++){
switch($State){
    Scan{
        $LastLog = Get-Content -Path $USMTPath\Logs\SMSTSLog\scanstateprogress.log -Tail 1 -ErrorAction SilentlyContinue
    }Load{
        $LastLog = Get-Content -Path $USMTPath\Logs\SMSTSLog\loadstateprogress.log -Tail 1 -ErrorAction SilentlyContinue
    }
    
}
#write-host $USMTPath
sleep 30
Write-Host $Serialnumber - $LastLog
}
do{
switch($State){
    Scan{
        $LastLog = Get-Content -Path $USMTPath\Logs\SMSTSLog\scanstateprogress.log -Tail 1 -ErrorAction SilentlyContinue
    }Load{
        $LastLog = Get-Content -Path $USMTPath\Logs\SMSTSLog\loadstateprogress.log -Tail 1 -ErrorAction SilentlyContinue
    }
}sleep 30
Write-Host $Serialnumber - $LastLog
}while(($LastLog -notmatch "Successful run") -or ($LastLog -eq $null))
write-host "$SerialNumber Completed!" -ForegroundColor Green
Write-Host "Press Enter to Close"
read-host' | Out-File -FilePath "$($env:USERPROFILE)\Documents\WindowsPowerShell\USMTMonitoringWindow.ps1" -Force