try{
    Copy-Item '\\nent95kbazvs003\MCFPAC\3DMLG\CLB-3\Longboard 2018\H&S Company\S-6\3. Data Section\Scripts\WMIT-lib.ps1' "$($env:USERPROFILE)\Documents\WindowsPowerShell\Library.ps1" -force
    Unblock-File "$($env:USERPROFILE)\Documents\WindowsPowerShell\Library.ps1" -Confirm:$False
    Import-Module "$($env:USERPROFILE)\Documents\WindowsPowerShell\Library.ps1"
    if (!(test-path C:\Windows\System32\PsExec.exe)){
        Copy-Item '\\nent95kbazvs003\MCFPAC\3DMLG\CLB-3\Longboard 2018\H&S Company\S-6\3. Data Section\Scripts\PsExec.exe' "$($env:USERPROFILE)\Documents\PsExec.exe" -Force -ErrorAction Stop
    }
    $Env:Path += ";$($env:USERPROFILE)\Documents"
    Copy-Item '\\nent95kbazvs003\MCFPAC\3DMLG\CLB-3\Longboard 2018\H&S Company\S-6\3. Data Section\Scripts\ManualUSMT.ps1' "$($env:USERPROFILE)\Documents\WindowsPowerShell\ManualUSMT.ps1" -force
    Unblock-File "$($env:USERPROFILE)\Documents\WindowsPowerShell\ManualUSMT.ps1" -Confirm:$False
    Import-Module "$($env:USERPROFILE)\Documents\WindowsPowerShell\ManualUSMT.ps1"
}catch{
    Write-Warning "Initial Setup Failed. Error: $_
    You probably aren't running in an elevated state"
    break
}
try{
$pshost = Get-Host              # Get the PowerShell Host.
$pswindow = $pshost.UI.RawUI    # Get the PowerShell Host's UI.

$newsize = $pswindow.BufferSize # Get the UI's current Buffer Size.
$newsize.width = 136            # Set the new buffer's width to 150 columns.
$pswindow.buffersize = $newsize # Set the new Buffer Size as active.

$newsize = $pswindow.windowsize # Get the UI's current Window Size.
$newsize.width = 136            # Set the new Window Width to 150 columns.
#$newsize.height = 56
$pswindow.windowsize = $newsize # Set the new Window Size as active.

$User = whoami
$User = ($User.split("\") | Select -last 1).ToUpper()
$host.ui.RawUI.WindowTitle = "$User - PowerShell"
}catch{}
Write-Host "=-=-=-=-=-=Welcome to SSgt Ferris's Workstation Administrator PowerShell Profile=-=-=-=-=-=" -ForegroundColor Green -BackgroundColor Black


Write-Host "*---------Updated 10/30/2018 @ 1122------------*
*Functions Changed:                            *
*1) Updated Push-Flash to 32.0.0.142           *
*2) Updated Push-Java to 8U201                 *" -ForegroundColor Green -BackgroundColor Blue
Help-Me