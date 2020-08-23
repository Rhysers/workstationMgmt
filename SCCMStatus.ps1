#VERSION 6.1


<#

New adition 8/6/2019
This uses Workflow to speed up the PING and access checking on remote machines.

#>

WorkFlow Get-ConnectionStatus{
Param(


    [String[]]$ComputerList,
    [Switch]$TestAccess


)
   
    
    Foreach -parallel ($Computer in $ComputerList){

        InlineScript{
            $Access = $null
            $Current = $null
            $OutputObj = New-Object -TypeName psobject

            $Current = $USING:Computer
            
            Add-Member -InputObject $OutputObj -MemberType NoteProperty -Name ComputerName -Value $Current -Force

            
            try{
                
                $Connection = Test-Connection -ComputerName $Current -Count 1 -ErrorAction Stop                
                Add-Member -InputObject $OutputObj -MemberType NoteProperty -Name Status -Value "Connected" -Force

                

                If($Using:TestAccess.IsPresent){
                    
                        $Access = Test-Path "\\$Current\c$" -ErrorAction Stop                    
                        Add-Member -InputObject $OutputObj -MemberType NoteProperty -Name Access -Value $Access -Force
                    
                        
                    
                    }
                


            }
            Catch{
                
                
                Add-Member -InputObject $OutputObj -MemberType NoteProperty -Name Status -Value "Disconnected"  -Force  
                
                If($Using:TestAccess.IsPresent){                
                    
                    Add-Member -InputObject $OutputObj -MemberType NoteProperty -Name Access -Value $false
                }
      
            
            }
            
            $OutputObj
        }       
        
        
    }
    
    



}




#does it resolve to an IP address?
Function Get-DNSRecord
{
Param(

    $ComputerList = "127.0.0.1"
    
    )

   

    #Create the Blank array which will ultimately become the output object

    $objResult = @()
    
    # $ping = new-object System.Net.NetworkInformation.Ping
    Foreach ($Computer in $ComputerList){


         #Build Output Object Template

        $OutputObj = [PScustomObject]@{
            
                ComputerName = $null
        
                DNSComputer = $null 

                DNSIPaddress = $null
                
            }
     
       
        #Reset OutputObject Foreach loop.
        
        
        $OutputObj.ComputerName = $Computer

        $Lookup = $null
        
        $Lookup = Resolve-DnsName $Computer -Type all -ErrorAction SilentlyContinue

        Switch ($lookup.QueryType){
        
            "A"{

                If ($Lookup.name -notlike "*in-addr.arpa"){

                    $OutputObj.DNSIPaddress = $Lookup.IPAddress
                    $OutputObj.DNSComputer = $Lookup.name

                }
                else{
                
                    $OutputObj.DNSIPaddress = $null
                    $OutputObj.DNSComputer = $null
                    

                }

                
                }
            "PTR"{

                $OutputObj.DNSIPaddress = $Computer
                $OutputObj.DNSComputer = $Lookup.namehost
            
                }
           
        }
        

        <#
        Try{
            
            $OutputObj.DNSComputer = (([system.net.dns]::GetHostByAddress($Computer)).hostname).replace(".mcdsus.mcds.usmc.mil","")
            #If the line above errors the line below will not run
            $OutputObj.DNSIPaddress = $Computer
        }

        Catch
        {
            
            try{
                
                #([system.net.dns]::GetHostByName($Computer)) | select *
                $OutputObj.DNSIPaddress = (([system.net.dns]::GetHostByName($Computer)).AddressList)[0].IPAddressToString
                $OutputObj.DNSIPComputer = $Computer
            }
            Catch{
            
            #No action required    
            
            }
               
        }

        
        #>
        $OutputObj

    }

        
}

<#

***Remove 12/17/2018****

#Can I access this machine. Test access to C$ drive on machine
Function Test-MachineAccess{

param(

    $ComputerList

)
    $OutputObj = New-Object psobject

    $OutputObj | Add-Member -MemberType NoteProperty -Name ComputerName -Value $null

    $OutputObj | Add-Member -MemberType NoteProperty -Name Access -Value $null
     

    #Create the Blank array which will ultimately become the output object

    $objResult = @()

    Foreach ($Computer in $ComputerList){
        
        $OutputObj.Access = $False
        try{
            $OutputObj.Access = Test-Path "\\$Computer\c$" -ErrorAction Stop
        }
        Catch{
        
            $OutputObj.Access = $False   

        }
        
        $OutputObj

        }
    



}

#>


#Gets status of CCMStatus and returns
Function Get-CCMExecStatus{

param(

    $ComputerList = $env:COMPUTERNAME


)
        #Building Output Template
    $OutputObj = New-Object psobject

    #$OutputObj | Add-Member -MemberType NoteProperty -Name ComputerName -Value $null

    $OutputObj | Add-Member -MemberType NoteProperty -Name DNSComputerName -Value $null
         
    $OutputObj | Add-Member -MemberType NoteProperty -Name DNSIPAddress -Value $null

    $OutputObj | Add-Member -MemberType NoteProperty -Name LastBoot -Value $null

    $OutputObj | Add-Member -MemberType NoteProperty -Name User -Value $null

    $OutputObj | Add-Member -MemberType NoteProperty -Name LogonStatus -Value $null

    $OutputObj | Add-Member -MemberType NoteProperty -Name DateLocked -Value $null

    $OutputObj | Add-Member -MemberType NoteProperty -Name Status -Value $null

    $OutputObj | Add-Member -MemberType NoteProperty -Name Access -Value $null

    $OutputObj | Add-Member -MemberType NoteProperty -Name CCMExec -Value $null

    $OutputObj | Add-Member -MemberType NoteProperty -Name CCMExecReply -Value $null

    $OutputObj | Add-Member -MemberType NoteProperty -Name CmRcService -Value $null

    #$OutputObj | Add-Member -MemberType NoteProperty -Name CCMCacheExists -Value $null

    $OutputObj | Add-Member -MemberType NoteProperty -Name MITSC -Value $null
         
    $OutputObj | Add-Member -MemberType NoteProperty -Name SiteCode -Value $null

    $OutputObj | Add-Member -MemberType NoteProperty -Name PendingUpdates -Value $null
    

    #Create the Blank array which will ultimately become the output object

    $objResult = @()


    $Connection = Get-ConnectionStatus -ComputerList $ComputerList -TestAccess 
    

    Foreach ($Computer in $Connection){

        $OutputObj.Status = $Computer.Status

        #reset Values
        
               
        $OutputObj.DNSComputerName = $Computer.ComputerName
        
        
        $OutputObj.Access  = $Computer.Access
        $OutputObj.LastBoot = $Null
        $OutputObj.CCMExec = $false
        $OutputObj.CCMExecReply  = $Null
        $OutputObj.CmRcService  = $Null
        #$OutputObj.CCMCacheExists = $Null
        $OutputObj.MITSC = $Null
        $OutputObj.User = $Null
        $OutputObj.SiteCode = $Null
        $OutputObj.User = $Null
        $OutputObj.LogonStatus = $Null
        $OutputObj.DateLocked = $Null
        $OutputObj.PendingUpdates = 0

        
        $ComputerListDNSInfo = $NULL
        $ComputerListDNSInfo = Get-DNSRecord -ComputerList $Computer.ComputerName

        $OutputObj.DNSIPAddress = $ComputerListDNSInfo.DNSIPAddress

        If($ComputerListDNSInfo.DNSComputer){
            #Notaction needed   
        }

        Else{
            $OutputObj.DNSComputerName = $ComputerListDNSInfo.ComputerName
        }
        

        
        $ADLocation = (Get-ADLocation -Computer $OutputObj.DNSComputerName).MITSC
        $OutputObj.MITSC = $ADLocation

        

        

        if ($ComputerListDNSInfo) {
            
            #$OutputObj.Ping = (Test-Ping -ComputerList $Computer).ping
            if($OutputObj.Status -eq "Connected"){

                #Get DNS Info
                

                <#Test Access
                $OutputObj.Access = (Test-MachineAccess -ComputerList $Computer).access#>
                
                


                if($OutputObj.Access){

                    Try{
                    
                        $CurrentSession = New-PSSession -ComputerName $Computer.ComputerName -ErrorAction Stop
                    
                    }
                    Catch{
                        $OutputObj.Status = "AccessError"        
                    }




                    $LogonStatus = $null
                    $LogonStatus = Get-RemoteLogonStatus -computer $OutputObj.DNSComputerName -Session $CurrentSession

                    $OutputObj.User = $LogonStatus.User
                    $OutputObj.LogonStatus = $LogonStatus.Status
                    $OutputObj.DateLocked = $LogonStatus.LockDate

                    try{
                        $OutputObj.LastBoot = Get-LastBoot -Session $CurrentSession
                    }

                    Catch{
                        #no change
                    }


                    try{
                        #Get Service Status
                        $OutputObj.CCMExec = (Get-Service -Name CcmExec -ComputerName $Computer.ComputerName -ErrorAction Stop).Status

                        try{
                            
                            #Attempt to send a command to SCCM on remote machine.
                            $OutputObj.CCMExecReply  = (Invoke-CMClient -ComputerName $Computer.ComputerName -ErrorAction Stop).Result
                            
                            #$OutputObj.CCMCacheExists = Test-Path "\\$Computer\c$\Windows"
                            $OutputObj.SiteCode = (Set-SCCMSite -ComputerList $Computer.ComputerName).SiteCode

                            #Count How many updates pending or ready to push.
                            $OutputObj.PendingUpdates = (([Array](Get-UpdateList $Computer.ComputerName)).UpdateName).Count
                            
                            
                            #If there is not site code attempt get computer name and try again.
                            if (!($OutputObj.SiteCode)){
                                
                                $OutputObj.SiteCode = (Set-SCCMSite -ComputerList (Get-DNSRecord $Computer.ComputerName).DNSComputer).SiteCode                                           
                                
                            }
                            
                        }
                        catch{

                            $OutputObj.CCMExecReply  = $false
                            
                        }

                        
            
                    }#end try
                    Catch{
                        $OutputObj.CCMExec = 'MISSING'
                        $OutputObj.CmRcService = "MISSING"    
                    }#end catch        
                    
                    #Get Service Status if CCMExec exists. Do not need to test if service is missing.
                    if($OutputObj.CCMExec){
                        try{
                            $OutputObj.CmRcService = (Get-Service -Name CmRcService -ComputerName $Computer.ComputerName -ErrorAction Stop).Status 
                        } 
                        Catch{
                            $OutputObj.CmRcService = "MISSING"
                        }
                    }  
                
                }#end if Access
                else{
                    
                    $OutputObj.CCMExec = 'No Access'
                
                }
            }#end IF Ping
            else{
        
                $OutputObj.CCMExec = 'Offline'
        
            }
        
        }#end IF DNSRecord 
        Else{
        
            $OutputObj.CCMExec = 'Offline'
        
        }
                
        $OutputObj
    }#end foreach

}



<#

Function Test-Ping
{
Param(

    $ComputerList = "127.0.0.1"
    
    )
    

        #Building Output Template
    $OutputObj = New-Object -TypeName psobject

    $OutputObj | Add-Member -MemberType NoteProperty -Name Computer -Value $null

    $OutputObj | Add-Member -MemberType NoteProperty -Name Ping -Value $null

   
     

    #Create the Blank array which will ultimately become the output object

    $objResult = @()
    
    Foreach ($Computer in $ComputerList){
       
        
        
    
        Try
        {
            $Connection = Test-Connection -ComputerName $Computer -Count 2 -ErrorAction Stop
            $online = $true
        }

        Catch
        {
            $Online = $False
        }

        $OutputObj.Computer =  $Computer
        $OutputObj.Ping =  $Online
        $OutputObj

    }

        
}
#>

Function trigger-AvailableSupInstall
{
    Param(
        [Parameter(Mandatory=$True, Position=1)] $ComputerName,
        [String][Parameter(Mandatory=$False, Position=2)] $SupName = "ALL"

    )


    $AppEvalState0 = "0"
    $AppEvalState1 = "1"



    If ($SupName -Like "All" -or $SupName -like "all")
    {
        Foreach ($Computer in $ComputerName)
        {
        $MyObj = New-Object -TypeName psobject
        try{
            $Application = (Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_SoftwareUpdate -ComputerName $Computer -ErrorAction Stop) # | 
                # Where-Object { $_.EvaluationState -like "*$($AppEvalState0)*" -or $_.EvaluationState -like "*$($AppEvalState1)*"})

            Invoke-WmiMethod -Class CCM_SoftwareUpdatesManager -Name InstallUpdates -ArgumentList (,$Application) -Namespace root\ccm\clientsdk -ComputerName $Computer -ErrorAction Stop  | Out-Null
            $Status = "Command Sent."
        }
        catch{
    
        
            $Status = "Failed"
        }

        Add-Member -InputObject $MyObj -MemberType NoteProperty -Name Machine -Value $Computer
        Add-Member -InputObject $MyObj -MemberType NoteProperty -Name Status -Value $Status
        $MyObj 
        }

    }
    Else

{
    Foreach ($Computer in $Computername)
    {
 $Application = (Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_SoftwareUpdate -ComputerName $Computer | Where-Object { $_.EvaluationState -like "*$($AppEvalState)*" -and $_.Name -like "*$($SupName)*"})
 Invoke-WmiMethod -Class CCM_SoftwareUpdatesManager -Name InstallUpdates -ArgumentList (,$Application) -Namespace root\ccm\clientsdk -ComputerName $Computer 

}

}
}
 


Function Invoke-CMClient{
<#
    .SYNOPSIS
       Invoke commands remotely on an SCCM Client for a system or systems.
    
    
    .DESCRIPTION
       This function allows you to remotely trigger some of the more common actions that you would find on the local
       Configuration Manager console.
    
    
    .PARAMETER -ComputerName 
       Specifies the target computer for the management operation. Enter a fully qualified domain name, a NetBIOS name, or an IP address. When the remote computer
       is in a different domain than the local computer, the fully qualified domain name is required.

       This command defaults to localhost.

    .PARAMETER -Action 
       Specifies the action to be taken on the SCCM Client.  The available actions are as follows:
                HardwareInv - Runs a Hardware Inventory Cycle on the target machine.
                SoftwareInv - Runs a Software Inventory Cycle on the target machine.
                UpdateScan - Runs a Software Updates Scan Cycle on the target machine.
                MachinePol - Runs a Machine Policy Retrieval and Evaluation Cycle on the target machine.
                UserPolicy - Runs a User Policy Retrieval and Evaluation Cycle on the target machine.
                FileCollect - Runs a File Collection Cycle on the target machine.

    .INPUTS
       You can pipe a computer name to Invoke-CMClient


    .EXAMPLE
       Invoke-CMClientAction -ComputerName server01 -Action HardwareInv

       The above command will invoke the Configuration Manager Client's Hardware Inventory Cycle on the targeted computer.  The return will look like the following:

       
        __GENUS          : 1
        __CLASS          : __PARAMETERS
        __SUPERCLASS     :
        __DYNASTY        : __PARAMETERS
        __RELPATH        : __PARAMETERS
        __PROPERTY_COUNT : 1
        __DERIVATION     : {}
        __SERVER         : server01
        __NAMESPACE      : ROOT\ccm
        __PATH           : \\server01\ROOT\ccm:__PARAMETERS
        ReturnValue      :
        PSComputerName   : server01

    .NOTES

       Created by Will Anderson. 

http://lastwordinnerd.com/category/posts/powershell-scripting/

       This script is provided AS IS without warranty of any kind.
    #>

    PARAM(
            [Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
            [string[]]$ComputerName = $env:COMPUTERNAME

            
            )#Close Param


   
    

    FOREACH ($Computer in $ComputerName){

        $OutputObj = New-Object psobject

        $OutputObj | Add-Member -MemberType NoteProperty -Name ComputerName -Value $null

        $OutputObj | Add-Member -MemberType NoteProperty -Name Result -Value $null
     

        #Create the Blank array which will ultimately become the output object

        $objResult = @()
        
        
            try{ 
                   
                Invoke-WmiMethod -ComputerName $Computer -Namespace root\ccm -Class sms_client -Name TriggerSchedule -ArgumentList '{00000000-0000-0000-0000-000000000121}' | Out-Null
                Invoke-WmiMethod -ComputerName $Computer -Namespace root\ccm -Class sms_client -Name TriggerSchedule -ArgumentList '{00000000-0000-0000-0000-000000000021}' | Out-Null
                Invoke-WmiMethod -ComputerName $Computer -Namespace root\ccm -Class sms_client -Name TriggerSchedule -ArgumentList '{00000000-0000-0000-0000-000000000022}' | Out-Null
                Invoke-WmiMethod -ComputerName $Computer -Namespace root\ccm -Class sms_client -Name TriggerSchedule -ArgumentList '{00000000-0000-0000-0000-000000000113}' | Out-Null
                Invoke-WmiMethod -ComputerName $Computer -Namespace root\ccm -Class sms_client -Name TriggerSchedule -ArgumentList '{00000000-0000-0000-0000-000000000108}' | Out-Null
                
                $OutputObj.ComputerName = $Computer
                $OutputObj.Result = $True
                
                }
            Catch{
            
                $OutputObj.ComputerName = $True
                $OutputObj.Result = $False   
            
            }
            $OutputObj                           
        }#End FOREACH Statement
}
   
            



# this is to set the SiteCode for Sccm
Function Set-SCCMSite{

param(

    $ComputerList
    

)    
    
    $ScriptBlock = {
        
        $OutputObj = New-Object psobject

        $OutputObj | Add-Member -MemberType NoteProperty -Name ComputerName -Value $null

        $OutputObj | Add-Member -MemberType NoteProperty -Name SiteCode -Value $null
     

        #Create the Blank array which will ultimately become the output object

        $objResult = @()
        
        
        
        & c:\windows\system32\sc.exe start ccmexec | out-null
        $sms = New-Object -ComObject Microsoft.SMS.Client 
        $sms.SetAssignedSite('MC3')
        #start-sleep -s 1     
        $OutputObj.SiteCode = $sms.GetAssignedSite()
        $OutputObj.ComputerName = $env:COMPUTERNAME
        $OutputObj

    }#Script Block
             
    Invoke-Command -ErrorAction SilentlyContinue  -ComputerName $ComputerList -ScriptBlock $ScriptBlock | Select ComputerName, SiteCode
    

}#Set-SCCMSite

Function Start-SCCMAppInstall{

    Param(
    
        $ComputerList,
        $PackageName
    
    
    
    )

    ForEach($Computer in $ComputerList){
        $i = $NULL
        
        try{
            $i = (Get-WmiObject -Class CCM_Application -Namespace "root\ccm\clientsdk" -ComputerName $Computer -ErrorAction Stop) | 
                ?{($_.Name -like "*$PackageName*") -and ($_.InstallState -like "NotInstalled")}
            $I


            }
        Catch{
            $computer + " " + $GetError[0].Exception + " Check SCCM" 
            continue
        
        }
        
        
        if ($i){
       
            Invoke-WmiMethod -class CCM_ProgramManager -Namespace root\ccm\clientsdk -Name ExecutePrograms -argumentlist $i -ComputerName $Computer -ErrorAction Stop | out-null
            "$Computer Pushed"


        }
        Else{
        
            "$Computer Did not find Package"    
        
        }

    }


}

Function Get-ADLocation{

param(


    [String]$Computer

)
    #Build Output Object
    $OutputObj = New-Object -TypeName psobject

    $OutputObj | Add-Member -MemberType NoteProperty -Name Computer -Value $null

    $OutputObj | Add-Member -MemberType NoteProperty -Name ADLocation -Value $null

    $OutputObj | Add-Member -MemberType NoteProperty -Name MITSC -Value $null
     

    #Create the Blank array which will ultimately become the output object

    $objResult = @()

    $OutputObj.Computer = $Computer

    Try{
        $Computer = $Computer.Replace('.mcdsus.mcds.usmc.mil','')
        $OutputObj.ADLocation = (Get-ADcomputer $Computer -Properties CanonicalName -ErrorAction Stop).CanonicalName
    
    }
    Catch{
        try{
        $Computer = ([system.net.dns]::GetHostByAddress($Computer)).hostname
        $Computer = $Computer.Replace('.mcdsus.mcds.usmc.mil','')


        $OutputObj.ADLocation = (Get-ADcomputer $Computer -Properties CanonicalName -ErrorAction Stop).CanonicalName
        
        }
        Catch{
       
           $OutputObj.ADLocation = "No AD Record"     
       
        }            
    
    }
    $OutputObj.MITSC = ($OutputObj.ADLocation).split("/")[2]
    $OutputObj.Computer = $Computer
    $OutputObj  


}

Function Get-RemoteLogonStatus  { 
Param(

    $computer = 'localhost',
    [System.Management.Automation.Runspaces.PSSession]$Session = $null

    )

    

    <#Build Output Object
    $OutputObj = New-Object -TypeName psobject

    $OutputObj | Add-Member -MemberType NoteProperty -Name Computer -Value $computer

    $OutputObj | Add-Member -MemberType NoteProperty -Name User -Value $null

    $OutputObj | Add-Member -MemberType NoteProperty -Name Status -Value $null

    $OutputObj | Add-Member -MemberType NoteProperty -Name LockDate -Value $null
     

    #Create the Blank array which will ultimately become the output object

    $objResult = @() #>

    $MyScriptBlock={

        $OutputObj = [PScustomObject]@{    
                

            Computer = $env:COMPUTERNAME

            User = $null

            Status = $null

            LockDate = $null

                
            }


        try { 
            $user = $null
        
            $user = gwmi -Class win32_computersystem -ComputerName $env:COMPUTERNAME -ErrorAction Stop | select -ExpandProperty username -ErrorAction Stop 
       
            $OutputObj.user = $user
            }
 
        catch { 

            $user = $null

            } 
        If ($user -ne $null){
            
                $OutputObj.Status = $User
                
                
                $LogonUI = $Null

                try{
                $LogonUI =  Get-CimInstance -Class win32_process -ErrorAction Stop -ComputerName $env:COMPUTERNAME  | ?{$_.name -like "logonUI*"} | 
                        select Caption, @{n='LockDate'; e={$_.CreationDate}} -ErrorAction Stop

                }

                Catch{
                
                    
                
                }

                If($LogonUI){

                    $OutputObj.LockDate = $LogonUI.LockDate

                    $OutputObj.Status = "Locked"
             
                    
                }
                Else{
                    
                    $OutputObj.Status = "Active"

                }

            
        }
        else{
        
            $OutputObj.Status = $Null    
        }
  

        
    
         
        return $OutputObj
    }

    If($Session.ComputerName){
        Invoke-Command -Session $Session -ScriptBlock $MyScriptBlock    
    }
    Else{
        Invoke-Command -ComputerName $computer -ScriptBlock $MyScriptBlock 
    }

} 


Function Get-UpdateList{

param(

    $ComputerList,
    [Switch]$AvailableOnly,
    $Session = $null
)
    
    $OutputObj = [PScustomObject]@{
            
                ComputerName = $Null
        
                State = $Null

                ErrorCode = $Null

                MaxExecutionTime = $null

                ArticleID = $Null

                UpdateName = $Null

                


                
            }
 

    
    
    $MyScriptBlock = {
           $OutputObj = [PScustomObject]@{
            
                ComputerName = $Null
        
                State = $Null

                ErrorCode = $Null

                MaxExecutionTime = $null

                ArticleID = $Null

                UpdateName = $Null

                


                
            }

    
        [Array]$UpdateList = @()
        
              
        [Array]$UpdateList = Get-wmiobject -ComputerName $Env:COMPUTERNAME -Namespace "root\ccm\clientSDK" -Class CCM_SoftwareUpdate -ErrorAction SilentlyContinue | 
                    select *
            
            $UpdateList | ForEach-Object{
                $OutputObj.ComputerName = $Env:COMPUTERNAME
        
            
                $OutputObj.State = $_.EvaluationState
                $OutputObj.ErrorCode = $_.ErrorCode
                $OutputObj.MaxExecutionTime = $_.MaxExecutionTime
                $OutputObj.ArticleID = $_.ArticleID
                $OutputObj.UpdateName = $_.Name
                $OutputObj
                }

        }


        
        If($Session){
            $UpdateList = Invoke-Command -Session $Session -ScriptBlock $MyScriptBlock
            $UpdateList | ForEach-Object {
                    
                    $OutputObj = $_
                    $OutputObj.State = (Get-EvalState $_.State).State
                    

                    $OutputObj
                }
        }
        
        else{
            
            $Connection = Get-ConnectionStatus $ComputerList

            $Disconnected = $Connection | ?{$_.Status -like "Disconnected"}
            <#Output Disconnected machines#>
            
            $Disconnected | ForEach-Object {
    
            
                $OutputObj.computername = $_.computername
                $OutputObj.State = "Disconnected"
                $OutputObj
    
            }
            <#Output Disconnected machines#>

            $Connected = $Connection | ?{$_.Status -like "connected"}

           
            
            $ConnectedSession = New-PSSession $Connected.ComputerName -ErrorAction SilentlyContinue

            If($ConnectedSession){
                $MyTempList = Invoke-Command -Session $ConnectedSession -ScriptBlock $MyScriptBlock -ea SilentlyContinue

                $MyTempList | ForEach-Object {
                    
                    $MyTempObj = $_
                    $MyTempObj.State = (Get-EvalState $_.State).State
                    

                    $MyTempObj
                }

                
            }
            

        }

    
        
            
        
    

} 



Function Get-EvalState {

param(

    $Code
    

)
    $OutputObj = [PScustomObject]@{
            
                ciValue = $Computer
        
                Code = $Code

                State = $_.name
                
            }
    
    If ($Code -ne $null){
        
        $SCCMCodeList ="0	ciJobStateNone	None
        1	ciJobStateAvailable	Available
        2	ciJobStateSubmitted	Submitted
        3	ciJobStateDetecting	Detecting
        4	ciJobStatePreDownload	PreDownload
        5	ciJobStateDownloading	Downloading
        6	ciJobStateWaitInstall	WaitInstall
        7	ciJobStateInstalling	Installing
        8	ciJobStatePendingSoftReboot	PendingSoftReboot
        9	ciJobStatePendingHardReboot	PendingHardReboot
        10	ciJobStateWaitReboot	WaitReboot
        11	ciJobStateVerifying	Verifying
        12	ciJobStateInstallComplete	InstallComplete
        13	ciJobStateError	Error
        14	ciJobStateWaitServiceWindow	WaitServiceWindow
        15	ciJobStateWaitUserLogon	WaitUserLogon
        16	ciJobStateWaitUserLogoff	WaitUserLogoff
        17	ciJobStateWaitJobUserLogon	WaitJobUserLogon
        18	ciJobStateWaitUserReconnect	WaitUserReconnect
        19	ciJobStatePendingUserLogoff	PendingUserLogoff
        20	ciJobStatePendingUpdate	PendingUpdate
        21	ciJobStateWaitingRetry	WaitingRetry
        22	ciJobStateWaitPresModeOff	WaitPresModeOff
        23	ciJobStateWaitForOrchestration	WaitForOrchestration"


        #$SCCMCodeList
        
        $SCCMCodeList = $SCCMCodeList.split("`n")
        $List = $SCCMCodeList[$code] | %{$_.split("`t").trim()}
        

        $OutputObj.code = $List[0]
        $OutputObj.ciValue = $List[1]
        $OutputObj.State = $List[2]
        $OutputObj

    }
    
    
}


<#Get Last time a machine Rebooted#>

Function Get-LastBoot{
    param(
        $ComputerList,
        $Session
    
    )


    $MyScriptBlock = {
    
        (Get-CimInstance -ComputerName $OutputObj.DNSComputerName -ClassName win32_OperatingSystem -ErrorAction Stop -OperationTimeoutSec 10).LastBootUpTime    
    
    
    }

    If ($Session){
    
        Invoke-Command -Session $Session -ScriptBlock $MyScriptBlock
    
    }
    Else{
    
        Invoke-Command -ComputerName $ComputerList -ScriptBlock $MyScriptBlock    
        
    
    }



}

Function Get-SCCMStatus{

    Param(
        $ComputerList
    
    
    )

    $Connected =$null
    $ConnectionStatus  = $null
    $Disconnected = $null
    $CleanList = $null
    #Cleaning up the list and removing blank lines.
    $CleanList = Clean-List $ComputerList
    

    Write-Host "Validating Machine List."
    $CleanList = Clean-List $ComputerList
    Write-Host "Getting Connection status of ALL machines."
    $ConnectionStatus = Get-ConnectionStatus $CleanList
    
    Write-Host "Removing disconnected machine from list."
    $Connected = $ConnectionStatus | Where{$_.Status -eq "Connected"}
        
    Write-Host "Listing all disconnected machines."
    $Disconnected = $ConnectionStatus | Where{$_.Status -eq "Disconnected"}
    #doing it this way so no passing blank records
    $Disconnected | %{Set-ObjectOutput -InputObject $_}


    if($Connected){
        Get-MachineStatusInfo -PSComputerName $Connected.ComputerName -ErrorAction SilentlyContinue -PSConnectionRetryCount 0 | %{Set-ObjectOutput -InputObject $_}
        }
    #Set-ObjectOutput -InputObject $InputObj
    
    
} #End Function Get-SCCMStatus
    




Function Clean-List{

    Param(
    
        $List
    
    )

    If ($List.gettype() -is [array]){
    

        $List = $List | %{$_.trim()}

        $List =$List | ?{$_}
    
    }

    If ($List.gettype().name -eq "String"){
        
        $List = $List.split("`n")

        $List = $List | %{$_.trim()}

        $List =$List | ?{$_}
    
    }

    $list 
}


<#Get all Info about sccm with one WorkFlow#>

Workflow Get-MachineStatusInfo{

InlineScript{
        

        $OutputObj = [PScustomObject]@{    
                

            ComputerName = $env:COMPUTERNAME
               
            IPAddess = $null

            WinVersion = $null
                        
            LastBoot = $null

            User = $null

            Status = $null

            LockDate = $null

            CCMExec = $null
            
            CCMExecReply = $null

            CmRcService = $null

            SiteCode =$null

            PendingUpdates = $null
            
            MITSC = $null

            MAC = $null

            SerialNumber = $null


                
            }
            #This is where I am collecting the Serial Number

            Try{
            
                $SN = (Get-CimInstance WIN32_BIOS | Select SerialNumber).SerialNumber
                

            }Catch{
            
                $SN = "Failed"    
            
            }
            $OutputObj.SerialNumber = $SN



            #Getting Count of Microsoft Updates for OS, Office and SQL. Does not include 3rd part
            Try{
                
                #I am forcing an Array here because 1 Object does not respond to .Count
                #Forcing the Array gets a count of 1. It would return 0 and/or if was an array with 1 patch 
                [Array]$UpdateList = Get-ciminstance -Namespace "root\ccm\clientSDK" -ClassName CCM_SoftwareUpdate -Ea SilentlyContinue | 
                    select *
                $OutputObj.PendingUpdates = $updatelist.count
            
            }

            Catch{
            
                $OutputObj.PendingUpdates = 0
            
            }

            #Attempting to get the IP Address on the machine.

            Try{
                $OutputObj.IPAddess = (Test-Connection $env:COMPUTERNAME -count 1 | select Ipv4Address).Ipv4Address.IPAddressToString
            }
            Catch{
            
                $OutputObj.IPAddess = "0.0.0.0"
            
            }

            Try{
                
                $Adapter = (Get-NetAdapter -Physical | ?{($_.status -like "Up")})
                                             
                $OutputObj.MAC = $Adapter.MacAddress
            }
            Catch{
            
                $OutputObj.IPAddess = "0.0.0.0"    
            
            }

            try{
            
                $sms = New-Object -ComObject Microsoft.SMS.Client
                $OutputObj.SiteCode = $sms.AutoDiscoverSite()                   
                $OutputObj.SiteCode = $sms.GetAssignedSite()
            
            
            
            
            
            }
            Catch{

                $OutputObj.SiteCode = "Failed"    
            
            
            
            
            }
            


            try{ 
                   
                
		        Invoke-WmiMethod  -Namespace root\ccm -Class sms_client -Name TriggerSchedule -ArgumentList '{00000000-0000-0000-0000-000000000121}' -ea stop | Out-Null
                Invoke-WmiMethod  -Namespace root\ccm -Class sms_client -Name TriggerSchedule -ArgumentList '{00000000-0000-0000-0000-000000000021}' -ea stop | Out-Null
                Invoke-WmiMethod  -Namespace root\ccm -Class sms_client -Name TriggerSchedule -ArgumentList '{00000000-0000-0000-0000-000000000022}' -ea stop | Out-Null
                Invoke-WmiMethod  -Namespace root\ccm -Class sms_client -Name TriggerSchedule -ArgumentList '{00000000-0000-0000-0000-000000000113}' -ea stop | Out-Null
                Invoke-WmiMethod  -Namespace root\ccm -Class sms_client -Name TriggerSchedule -ArgumentList '{00000000-0000-0000-0000-000000000108}' -ea stop | Out-Null
                
                
                $OutputObj.CCMExecReply = $True
                
                }
            Catch{
            
                
                $OutputObj.CCMExecReply = $False   
            
            }



            <#get service info#>



            Try{
                $OutputObj.CCMexec = (Get-CimInstance -ClassName win32_Service -Filter 'name like "ccmexec"' -ErrorAction Stop).State
                }
            Catch{
                $OutputObj.CCMexec = "Failed"
                
            }

            Try{
                $OutputObj.CmRcService = (Get-CimInstance -ClassName win32_Service -Filter 'name like "CmRcService"' -OperationTimeoutSec 10 -ErrorAction Stop).State
                }
            Catch{
                $OutputObj.CmRcService = "Failed"
                
            }


            <#Get last Boot Time#>

            Try{
            
                $OutputObj.LastBoot = (Get-CimInstance -ClassName win32_OperatingSystem -ErrorAction Stop -OperationTimeoutSec 10).LastBootUpTime 
            
            }
            Catch{
                $OutputObj.LastBoot = "Timeout"    
            }


         <#Get the Logged on user#>

            try { 
                $user = $null
        
                $user = gwmi -Class win32_ComputerSystem  -ErrorAction Stop | select -ExpandProperty username -ErrorAction Stop 
       
                $OutputObj.user = $user
                }
 
            catch { 

                $user = $null

                } 
            If ($user -ne $null){
            
                    $OutputObj.Status = $User
                
                
                    $LogonUI = $Null

                    try{
                    $LogonUI =  Get-CimInstance -Class win32_Process -ErrorAction Stop  | ?{$_.name -like "logonUI*"} | 
                            select Caption, @{n='LockDate'; e={$_.CreationDate}} -ErrorAction Stop

                    }

                    Catch{
                
                    
                
                }

                If($LogonUI){

                    $OutputObj.LockDate = $LogonUI.LockDate

                    $OutputObj.Status = "Locked"
             
                    
                }
                Else{
                    
                    $OutputObj.Status = "Active"

                }

            
        }
        else{
        
            $OutputObj.Status = $Null    
        }
        
        try{
        
            $Names = "CurrentMajorVersionNumber", "CurrentMinorVersionNumber", "CurrentBuildNumber", "ReleaseId", "UBR" 
            $Ver = (Get-ItemProperty "Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\" -name $names -ErrorAction SilentlyContinue)
            $OutputObj.WinVersion = [String]$Ver.CurrentMajorVersionNumber + "." + [String]$ver.CurrentMinorVersionNumber +  "." +[String]$ver.CurrentBuildNumber +  "." + [String]$ver.UBR  
            
            
        }

        catch{
        
        }


        
    
         
        return $OutputObj
    }

}



Function Set-ObjectOutput{

Param(

    [psobject]$InputObject

)



$InputObject | ForEach-Object{

        $MyOutput = New-Object -TypeName PSobject -Property @{    
                

            ComputerName = $_.ComputerName
               
            IPAddess = $_.IPAddess

            WinVersion = $_.WinVersion
                        
            LastBoot = $_.LastBoot

            User = $_.User

            Status = $_.Status

            LockDate = $_.LockDate 

            CCMExec = $_.CCMExec
            
            CCMExecReply = $_.CCMExecReply

            CmRcService = $_.CmRcService

            SiteCode =$_.SiteCode

            PendingUpdates = $_.PendingUpdates

            MITSC = $Null

            MAC = $_.MAC

            SerialNumber = $_.SerialNumber

            Runtime = $null
                
            }

        Try{
            $Erro
            $Machine = ($_.ComputerName).split(".")[0]
        }
        Catch{
            $Machine = $_.ComputerName
        }

        Try{
        
            $Machine = (Get-ADComputer $Machine -Properties CanonicalName -erroraction Stop).CanonicalName
            $Machine = $machine.split("/")

            $MyOutput.MITSC = $Machine[2] 

        }
        Catch{
        
            $MyOutput.MITSC = "NoRecord"

        }

        $MyOutput.RunTime = (Get-Date -format "MM/dd/yyyy HH:mm" )
        
        
        $MyOutput | select ComputerName,IPAddess,WinVersion,LastBoot,User,Status,LockDate,CCMExec,CCMExecReply,CmRcService,SiteCode,MITSC,PendingUpdates,MAC,SerialNumber, Runtime


    
    }

}
