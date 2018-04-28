Function Get-ProcCreateEvents($Interval)
{
    #Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 2000 | ?{$_.id -eq "1"}
    
    $Events = Get-WinEvent  -LogName "Microsoft-Windows-Sysmon/Operational" -FilterXPath "*[System[EventID=1]]"  | Where-Object {($_.timecreated -ge  $Interval)}

    foreach ($item in $Events)
    {
        
        #$item | select * | fl
        $message = $item.message.split("`n") | ForEach-Object{$_.trimstart()} | ForEach-Object{$_.trimend()} | ForEach-Object{$_ -replace ";",","}
        #$message

        $Data = New-Object System.Management.Automation.PSObject
        $Data | Add-Member NoteProperty Id ($null)
        $Data | Add-Member NoteProperty LocalTime ($null)
        $Data | Add-Member NoteProperty UtcTime ($null)
        $Data | Add-Member NoteProperty UtcEndTime ($null)
        $Data | Add-Member NoteProperty ProcessGuid ($null)
        $Data | Add-Member NoteProperty ProcessId ($null)
        $Data | Add-Member NoteProperty Image ($null)
        $Data | Add-Member NoteProperty FileVersion ($null)
        $Data | Add-Member NoteProperty Description ($null)
        $Data | Add-Member NoteProperty Product ($null)
        $Data | Add-Member NoteProperty Company ($null)
        $Data | Add-Member NoteProperty CommandLine ($null)
        $Data | Add-Member NoteProperty User ($null)
        $Data | Add-Member NoteProperty LogonGuid ($null)
        $Data | Add-Member NoteProperty LogonId ($null)
        $Data | Add-Member NoteProperty TerminalSessionId ($null)
        $Data | Add-Member NoteProperty IntegrityLevel ($null)
        $Data | Add-Member NoteProperty Hashes ($null)
        $Data | Add-Member NoteProperty ParentProcessGuid ($null)
        $Data | Add-Member NoteProperty ParentProcessId ($null)
        $Data | Add-Member NoteProperty ParentImage ($null)
        $Data | Add-Member NoteProperty ParentCommandLine ($null)
        
        $Data.Id                = $item.Id
        $Data.UtcTime           = ($message | Where-Object{$_ -like "UtcTime:*"}           | ForEach-Object{$_ -replace "UtcTime: ",""} )
        $Data.LocalTime         = Get-Date([System.DateTime]$Data.UtcTime + (new-timespan -hours 3)) -Format "dd-MM-yyyy HH:mm:ss.fff"
        $Data.ProcessGuid       = ($message | Where-Object{$_ -like "ProcessGuid:*"}       | ForEach-Object{$_ -replace "ProcessGuid: ",""} )
        $Data.ProcessId         = ($message | Where-Object{$_ -like "ProcessId:*"}         | ForEach-Object{$_ -replace "ProcessId: ",""} )
        $Data.Image             = ($message | Where-Object{$_ -like "Image:*"}             | ForEach-Object{$_ -replace "Image: ",""} )
        $Data.FileVersion       = ($message | Where-Object{$_ -like "FileVersion:*"}       | ForEach-Object{$_ -replace "FileVersion: ",""} )
        $Data.Description       = ($message | Where-Object{$_ -like "Description:*"}       | ForEach-Object{$_ -replace "Description: ",""} )
        $Data.Product           = ($message | Where-Object{$_ -like "Product:*"}           | ForEach-Object{$_ -replace "Product: ",""} )
        $Data.Company           = ($message | Where-Object{$_ -like "Company:*"}           | ForEach-Object{$_ -replace "Company: ",""} )
        $Data.CommandLine       = ($message | Where-Object{$_ -like "CommandLine:*"}       | ForEach-Object{$_ -replace "CommandLine: ",""} )
        $Data.User              = ($message | Where-Object{$_ -like "User:*"}              | ForEach-Object{$_ -replace "User: ",""} )
        $Data.LogonGuid         = ($message | Where-Object{$_ -like "LogonGuid:*"}         | ForEach-Object{$_ -replace "LogonGuid: ",""} )
        $Data.LogonId           = ($message | Where-Object{$_ -like "LogonId:*"}           | ForEach-Object{$_ -replace "LogonId: ",""} )
        $Data.TerminalSessionId = ($message | Where-Object{$_ -like "TerminalSessionId:*"} | ForEach-Object{$_ -replace "TerminalSessionId: ",""} )
        $Data.IntegrityLevel    = ($message | Where-Object{$_ -like "IntegrityLevel:*"}    | ForEach-Object{$_ -replace "IntegrityLevel: ",""} )
        $Data.Hashes            = ($message | Where-Object{$_ -like "Hashes:*"}            | ForEach-Object{$_ -replace "Hashes: ",""} )
        $Data.ParentProcessGuid = ($message | Where-Object{$_ -like "ParentProcessGuid:*"} | ForEach-Object{$_ -replace "ParentProcessGuid: ",""} )
        $Data.ParentProcessId   = ($message | Where-Object{$_ -like "ParentProcessId:*"}   | ForEach-Object{$_ -replace "ParentProcessId: ",""} )
        $Data.ParentImage       = ($message | Where-Object{$_ -like "ParentImage:*"}       | ForEach-Object{$_ -replace "ParentImage: ",""} )
        $Data.ParentCommandLine = ($message | Where-Object{$_ -like "ParentCommandLine:*"} | ForEach-Object{$_ -replace "ParentCommandLine: ",""} )


        $Global:ProcCreateEvents +=$Data
    }
}
Function Get-ProcTermEvents($Interval)
{
    #Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 2000 | ?{$_.id -eq "1"}
    $Events = Get-WinEvent  -LogName "Microsoft-Windows-Sysmon/Operational" -FilterXPath "*[System[EventID=5]]"  | Where-Object {($_.timecreated -ge  $Interval)}

    foreach ($item in $Events)
    {
        
        #$item | select * | fl
        $message = $item.message.split("`n") | ForEach-Object{$_.trimstart()} | ForEach-Object{$_.trimend()} | ForEach-Object{$_ -replace ";",","}
        #$message

        $Data = New-Object System.Management.Automation.PSObject
        $Data | Add-Member NoteProperty Id ($null)
        $Data | Add-Member NoteProperty UtcTime ($null)
        $Data | Add-Member NoteProperty ProcessGuid ($null)
        $Data | Add-Member NoteProperty ProcessId ($null)
        $Data | Add-Member NoteProperty Image ($null)
        $Data | Add-Member NoteProperty FileVersion ($null)
        $Data | Add-Member NoteProperty Description ($null)
        $Data | Add-Member NoteProperty Product ($null)
        $Data | Add-Member NoteProperty Company ($null)
        $Data | Add-Member NoteProperty CommandLine ($null)
        $Data | Add-Member NoteProperty User ($null)
        $Data | Add-Member NoteProperty LogonGuid ($null)
        $Data | Add-Member NoteProperty LogonId ($null)
        $Data | Add-Member NoteProperty TerminalSessionId ($null)
        $Data | Add-Member NoteProperty IntegrityLevel ($null)
        $Data | Add-Member NoteProperty Hashes ($null)
        $Data | Add-Member NoteProperty ParentProcessGuid ($null)
        $Data | Add-Member NoteProperty ParentProcessId ($null)
        $Data | Add-Member NoteProperty ParentImage ($null)
        $Data | Add-Member NoteProperty ParentCommandLine ($null)
        
        $Data.Id                = $item.Id
        $Data.UtcTime           = ($message | Where-Object{$_ -like "UtcTime:*"}           | ForEach-Object{$_ -replace "UtcTime: ",""} )
        $Data.ProcessGuid       = ($message | Where-Object{$_ -like "ProcessGuid:*"}       | ForEach-Object{$_ -replace "ProcessGuid: ",""} )
        $Data.ProcessId         = ($message | Where-Object{$_ -like "ProcessId:*"}         | ForEach-Object{$_ -replace "ProcessId: ",""} )
        $Data.Image             = ($message | Where-Object{$_ -like "Image:*"}             | ForEach-Object{$_ -replace "Image: ",""} )
        $Data.FileVersion       = ($message | Where-Object{$_ -like "FileVersion:*"}       | ForEach-Object{$_ -replace "FileVersion: ",""} )
        $Data.Description       = ($message | Where-Object{$_ -like "Description:*"}       | ForEach-Object{$_ -replace "Description: ",""} )
        $Data.Product           = ($message | Where-Object{$_ -like "Product:*"}           | ForEach-Object{$_ -replace "Product: ",""} )
        $Data.Company           = ($message | Where-Object{$_ -like "Company:*"}           | ForEach-Object{$_ -replace "Company: ",""} )
        $Data.CommandLine       = ($message | Where-Object{$_ -like "CommandLine:*"}       | ForEach-Object{$_ -replace "CommandLine: ",""} )
        $Data.User              = ($message | Where-Object{$_ -like "User:*"}              | ForEach-Object{$_ -replace "User: ",""} )
        $Data.LogonGuid         = ($message | Where-Object{$_ -like "LogonGuid:*"}         | ForEach-Object{$_ -replace "LogonGuid: ",""} )
        $Data.LogonId           = ($message | Where-Object{$_ -like "LogonId:*"}           | ForEach-Object{$_ -replace "LogonId: ",""} )
        $Data.TerminalSessionId = ($message | Where-Object{$_ -like "TerminalSessionId:*"} | ForEach-Object{$_ -replace "TerminalSessionId: ",""} )
        $Data.IntegrityLevel    = ($message | Where-Object{$_ -like "IntegrityLevel:*"}    | ForEach-Object{$_ -replace "IntegrityLevel: ",""} )
        $Data.Hashes            = ($message | Where-Object{$_ -like "Hashes:*"}            | ForEach-Object{$_ -replace "Hashes: ",""} )
        $Data.ParentProcessGuid = ($message | Where-Object{$_ -like "ParentProcessGuid:*"} | ForEach-Object{$_ -replace "ParentProcessGuid: ",""} )
        $Data.ParentProcessId   = ($message | Where-Object{$_ -like "ParentProcessId:*"}   | ForEach-Object{$_ -replace "ParentProcessId: ",""} )
        $Data.ParentImage       = ($message | Where-Object{$_ -like "ParentImage:*"}       | ForEach-Object{$_ -replace "ParentImage: ",""} )
        $Data.ParentCommandLine = ($message | Where-Object{$_ -like "ParentCommandLine:*"} | ForEach-Object{$_ -replace "ParentCommandLine: ",""} )


        $Global:ProcTermEvents +=$Data
    }
}
Function Get-NetEvents($Interval)
{
    #Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 2000 | ?{$_.id -eq "1"}
    
    $Events = Get-WinEvent  -LogName "Microsoft-Windows-Sysmon/Operational" -FilterXPath "*[System[EventID=3]]"  | Where-Object {($_.timecreated -ge  $Interval)}

    foreach ($item in $Events)
    {
        
        #$item | select * | fl
        $message = $item.message.split("`n") | ForEach-Object{$_.trimstart()} | ForEach-Object{$_.trimend()} | ForEach-Object{$_ -replace ";",","}
        #$message

        $Data = New-Object System.Management.Automation.PSObject
        $Data | Add-Member NoteProperty Id ($null)
        $Data | Add-Member NoteProperty UtcTime ($null)
        $Data | Add-Member NoteProperty ProcessGuid ($null)
        $Data | Add-Member NoteProperty ProcessId ($null)
        $Data | Add-Member NoteProperty Image ($null)
        $Data | Add-Member NoteProperty User ($null)
        $Data | Add-Member NoteProperty Protocol ($null)
        $Data | Add-Member NoteProperty Initiated ($null)
        $Data | Add-Member NoteProperty SourceIsIpv6 ($null)
        $Data | Add-Member NoteProperty SourceIp ($null)
        $Data | Add-Member NoteProperty SourceHostname ($null)
        $Data | Add-Member NoteProperty SourcePort ($null)
        $Data | Add-Member NoteProperty SourcePortName ($null)
        $Data | Add-Member NoteProperty DestinationIsIpv6 ($null)
        $Data | Add-Member NoteProperty DestinationIp ($null)
        $Data | Add-Member NoteProperty DestinationHostname ($null)
        $Data | Add-Member NoteProperty DestinationPort ($null)
        $Data | Add-Member NoteProperty DestinationPortName ($null)

        $Data.Id                      = $item.Id
        $Data.UtcTime                 = ($message | Where-Object{$_ -like "UtcTime:*"}             | ForEach-Object{$_ -replace "UtcTime: ",""} )
        $Data.ProcessGuid             = ($message | Where-Object{$_ -like "ProcessGuid:*"}         | ForEach-Object{$_ -replace "ProcessGuid: ",""} )
        $Data.ProcessId               = ($message | Where-Object{$_ -like "ProcessId:*"}           | ForEach-Object{$_ -replace "ProcessId: ",""} )
        $Data.Image                   = ($message | Where-Object{$_ -like "Image:*"}               | ForEach-Object{$_ -replace "Image: ",""} )
        $Data.User                    = ($message | Where-Object{$_ -like "User:*"}                | ForEach-Object{$_ -replace "User: ",""} )
        $Data.Protocol                = ($message | Where-Object{$_ -like "Protocol:*"}            | ForEach-Object{$_ -replace "Protocol: ",""} )
        $Data.Initiated               = ($message | Where-Object{$_ -like "Initiated:*"}           | ForEach-Object{$_ -replace "Initiated: ",""} )
        $Data.SourceIsIpv6            = ($message | Where-Object{$_ -like "SourceIsIpv6:*"}        | ForEach-Object{$_ -replace "SourceIsIpv6: ",""} )
        $Data.SourceIp                = ($message | Where-Object{$_ -like "SourceIp:*"}            | ForEach-Object{$_ -replace "SourceIp: ",""} )
        $Data.SourceHostname          = ($message | Where-Object{$_ -like "SourceHostname:*"}      | ForEach-Object{$_ -replace "SourceHostname:",""} )
        $Data.SourcePort              = ($message | Where-Object{$_ -like "SourcePort:*"}          | ForEach-Object{$_ -replace "SourcePort: ",""} )
        $Data.SourcePortName          = ($message | Where-Object{$_ -like "SourcePortName:*"}      | ForEach-Object{$_ -replace "SourcePortName:",""} )
        $Data.DestinationIsIpv6       = ($message | Where-Object{$_ -like "DestinationIsIpv6:*"}   | ForEach-Object{$_ -replace "DestinationIsIpv6: ",""} )
        $Data.DestinationIp           = ($message | Where-Object{$_ -like "DestinationIp:*"}       | ForEach-Object{$_ -replace "DestinationIp: ",""} )
        $Data.DestinationHostname     = ($message | Where-Object{$_ -like "DestinationHostname:*"} | ForEach-Object{$_ -replace "DestinationHostname:",""} )
        $Data.DestinationPort         = ($message | Where-Object{$_ -like "DestinationPort:*"}     | ForEach-Object{$_ -replace "DestinationPort: ",""} )
        $Data.DestinationPortName     = ($message | Where-Object{$_ -like "DestinationPortName:*"} | ForEach-Object{$_ -replace "DestinationPortName:",""} )

        $Global:NetEvents +=$Data
    }
}
Function Get-FileEvents($Interval)
{
    #Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 2000 | ?{$_.id -eq "1"}
    
    $Events = Get-WinEvent  -LogName "Microsoft-Windows-Sysmon/Operational" -FilterXPath "*[System[EventID=2]]"  | Where-Object {($_.timecreated -ge  $Interval)}

    foreach ($item in $Events)
    {
        
        #$item | select * | fl
        $message = $item.message.split("`n") | ForEach-Object{$_.trimstart()} | ForEach-Object{$_.trimend()} | ForEach-Object{$_ -replace ";",","}
        #$message

        $Data = New-Object System.Management.Automation.PSObject
        $Data | Add-Member NoteProperty Id ($null)
        $Data | Add-Member NoteProperty UtcTime ($null)
        $Data | Add-Member NoteProperty ProcessGuid ($null)
        $Data | Add-Member NoteProperty ProcessId ($null)
        $Data | Add-Member NoteProperty Image ($null)
        $Data | Add-Member NoteProperty TargetFilename ($null)
        $Data | Add-Member NoteProperty CreationUtcTime ($null)
        $Data | Add-Member NoteProperty PreviousCreationUtcTime ($null)
        $Data | Add-Member NoteProperty Hash ($null)
        
        $Data.Id                      = $item.Id
        $Data.UtcTime                 = ($message | Where-Object{$_ -like "UtcTime:*"}                 | ForEach-Object{$_ -replace "UtcTime: ",""} )
        $Data.ProcessGuid             = ($message | Where-Object{$_ -like "ProcessGuid:*"}             | ForEach-Object{$_ -replace "ProcessGuid: ",""} )
        $Data.ProcessId               = ($message | Where-Object{$_ -like "ProcessId:*"}               | ForEach-Object{$_ -replace "ProcessId: ",""} )
        $Data.Image                   = ($message | Where-Object{$_ -like "Image:*"}                   | ForEach-Object{$_ -replace "Image: ",""} )
        $Data.TargetFilename          = ($message | Where-Object{$_ -like "TargetFilename:*"}          | ForEach-Object{$_ -replace "TargetFilename: ",""} )
        $Data.CreationUtcTime         = ($message | Where-Object{$_ -like "CreationUtcTime:*"}         | ForEach-Object{$_ -replace "CreationUtcTime: ",""} )
        $Data.PreviousCreationUtcTime = ($message | Where-Object{$_ -like "PreviousCreationUtcTime:*"} | ForEach-Object{$_ -replace "PreviousCreationUtcTime: ",""} )
       
        $Global:FileEvents +=$Data
    }
    $Events = Get-WinEvent  -LogName "Microsoft-Windows-Sysmon/Operational" -FilterXPath "*[System[EventID=11]]"  | Where-Object {($_.timecreated -ge  $Interval)}

    foreach ($item in $Events)
    {
        
        #$item | select * | fl
        $message = $item.message.split("`n") | ForEach-Object{$_.trimstart()} | ForEach-Object{$_.trimend()} | ForEach-Object{$_ -replace ";",","}
        #$message

        $Data = New-Object System.Management.Automation.PSObject
        $Data | Add-Member NoteProperty Id ($null)
        $Data | Add-Member NoteProperty UtcTime ($null)
        $Data | Add-Member NoteProperty ProcessGuid ($null)
        $Data | Add-Member NoteProperty ProcessId ($null)
        $Data | Add-Member NoteProperty Image ($null)
        $Data | Add-Member NoteProperty TargetFilename ($null)
        $Data | Add-Member NoteProperty CreationUtcTime ($null)
        $Data | Add-Member NoteProperty PreviousCreationUtcTime ($null)
        $Data | Add-Member NoteProperty Hash ($null)
        
        $Data.Id                      = $item.Id
        $Data.UtcTime                 = ($message | Where-Object{$_ -like "UtcTime:*"}                 | ForEach-Object{$_ -replace "UtcTime: ",""} )
        $Data.ProcessGuid             = ($message | Where-Object{$_ -like "ProcessGuid:*"}             | ForEach-Object{$_ -replace "ProcessGuid: ",""} )
        $Data.ProcessId               = ($message | Where-Object{$_ -like "ProcessId:*"}               | ForEach-Object{$_ -replace "ProcessId: ",""} )
        $Data.Image                   = ($message | Where-Object{$_ -like "Image:*"}                   | ForEach-Object{$_ -replace "Image: ",""} )
        $Data.TargetFilename          = ($message | Where-Object{$_ -like "TargetFilename:*"}          | ForEach-Object{$_ -replace "TargetFilename: ",""} )
        $Data.CreationUtcTime         = ($message | Where-Object{$_ -like "CreationUtcTime:*"}         | ForEach-Object{$_ -replace "CreationUtcTime: ",""} )
           
        $Global:FileEvents +=$Data
    }
    
    $Events = Get-WinEvent  -LogName "Microsoft-Windows-Sysmon/Operational" -FilterXPath "*[System[EventID=15]]"  | Where-Object {($_.timecreated -ge  $Interval)}

    foreach ($item in $Events)
    {
        
        #$item | select * | fl
        $message = $item.message.split("`n") | ForEach-Object{$_.trimstart()} | ForEach-Object{$_.trimend()} | ForEach-Object{$_ -replace ";",","}
        #$message

        $Data = New-Object System.Management.Automation.PSObject
        $Data | Add-Member NoteProperty Id ($null)
        $Data | Add-Member NoteProperty UtcTime ($null)
        $Data | Add-Member NoteProperty ProcessGuid ($null)
        $Data | Add-Member NoteProperty ProcessId ($null)
        $Data | Add-Member NoteProperty Image ($null)
        $Data | Add-Member NoteProperty TargetFilename ($null)
        $Data | Add-Member NoteProperty CreationUtcTime ($null)
        $Data | Add-Member NoteProperty PreviousCreationUtcTime ($null)
        $Data | Add-Member NoteProperty Hash ($null)
        
        $Data.Id                      = $item.Id
        $Data.UtcTime                 = ($message | Where-Object{$_ -like "UtcTime:*"}                 | ForEach-Object{$_ -replace "UtcTime: ",""} )
        $Data.ProcessGuid             = ($message | Where-Object{$_ -like "ProcessGuid:*"}             | ForEach-Object{$_ -replace "ProcessGuid: ",""} )
        $Data.ProcessId               = ($message | Where-Object{$_ -like "ProcessId:*"}               | ForEach-Object{$_ -replace "ProcessId: ",""} )
        $Data.Image                   = ($message | Where-Object{$_ -like "Image:*"}                   | ForEach-Object{$_ -replace "Image: ",""} )
        $Data.TargetFilename          = ($message | Where-Object{$_ -like "TargetFilename:*"}          | ForEach-Object{$_ -replace "TargetFilename: ",""} )
        $Data.CreationUtcTime         = ($message | Where-Object{$_ -like "CreationUtcTime:*"}         | ForEach-Object{$_ -replace "CreationUtcTime: ",""} )
        $Data.Hash                    = ($message | Where-Object{$_ -like "Hash:*"}                    | ForEach-Object{$_ -replace "Hash: ",""} )

        $Global:FileEvents +=$Data
    }
}
Function Get-RegEvents($Interval)
{
    #Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 2000 | ?{$_.id -eq "1"}
    
    $Events = Get-WinEvent  -LogName "Microsoft-Windows-Sysmon/Operational" -FilterXPath "*[System[EventID=12]]"  | Where-Object {($_.timecreated -ge  $Interval)}

    foreach ($item in $Events)
    {
        
        #$item | select * | fl
        $message = $item.message.split("`n") | ForEach-Object{$_.trimstart()} | ForEach-Object{$_.trimend()} | ForEach-Object{$_ -replace ";",","}
        #$message

        $Data = New-Object System.Management.Automation.PSObject
        $Data | Add-Member NoteProperty Id ($null)
        $Data | Add-Member NoteProperty EventType ($null)
        $Data | Add-Member NoteProperty UtcTime ($null)
        $Data | Add-Member NoteProperty ProcessGuid ($null)
        $Data | Add-Member NoteProperty ProcessId ($null)
        $Data | Add-Member NoteProperty Image ($null)
        $Data | Add-Member NoteProperty TargetObject ($null)
        $Data | Add-Member NoteProperty Details ($null)
        
        
        $Data.Id                      = $item.Id
        $Data.EventType               = ($message | Where-Object{$_ -like "EventType:*"}               | ForEach-Object{$_ -replace "EventType: ",""} )  
        $Data.UtcTime                 = ($message | Where-Object{$_ -like "UtcTime:*"}                 | ForEach-Object{$_ -replace "UtcTime: ",""} )
        $Data.ProcessGuid             = ($message | Where-Object{$_ -like "ProcessGuid:*"}             | ForEach-Object{$_ -replace "ProcessGuid: ",""} )
        $Data.ProcessId               = ($message | Where-Object{$_ -like "ProcessId:*"}               | ForEach-Object{$_ -replace "ProcessId: ",""} )
        $Data.Image                   = ($message | Where-Object{$_ -like "Image:*"}                   | ForEach-Object{$_ -replace "Image: ",""} )
        $Data.TargetObject            = ($message | Where-Object{$_ -like "TargetObject:*"}            | ForEach-Object{$_ -replace "TargetObject: ",""} )
        
       
        $Global:RegEvents +=$Data
    }

    $Events = Get-WinEvent  -LogName "Microsoft-Windows-Sysmon/Operational" -FilterXPath "*[System[EventID=13]]"  | Where-Object {($_.timecreated -ge  $Interval)}

    foreach ($item in $Events)
    {
        
        #$item | select * | fl
        $message = $item.message.split("`n") | ForEach-Object{$_.trimstart()} | ForEach-Object{$_.trimend()} | ForEach-Object{$_ -replace ";",","}
        #$message

        $Data = New-Object System.Management.Automation.PSObject
        $Data | Add-Member NoteProperty Id ($null)
        $Data | Add-Member NoteProperty EventType ($null)
        $Data | Add-Member NoteProperty UtcTime ($null)
        $Data | Add-Member NoteProperty ProcessGuid ($null)
        $Data | Add-Member NoteProperty ProcessId ($null)
        $Data | Add-Member NoteProperty Image ($null)
        $Data | Add-Member NoteProperty TargetObject ($null)
        $Data | Add-Member NoteProperty Details ($null)
        
        
        
        $Data.Id                      = $item.Id
        $Data.EventType               = ($message | Where-Object{$_ -like "EventType:*"}               | ForEach-Object{$_ -replace "EventType: ",""} )  
        $Data.UtcTime                 = ($message | Where-Object{$_ -like "UtcTime:*"}                 | ForEach-Object{$_ -replace "UtcTime: ",""} )
        $Data.ProcessGuid             = ($message | Where-Object{$_ -like "ProcessGuid:*"}             | ForEach-Object{$_ -replace "ProcessGuid: ",""} )
        $Data.ProcessId               = ($message | Where-Object{$_ -like "ProcessId:*"}               | ForEach-Object{$_ -replace "ProcessId: ",""} )
        $Data.Image                   = ($message | Where-Object{$_ -like "Image:*"}                   | ForEach-Object{$_ -replace "Image: ",""} )
        $Data.TargetObject            = ($message | Where-Object{$_ -like "TargetObject:*"}            | ForEach-Object{$_ -replace "TargetObject: ",""} )
        $Data.Details                 = ($message | Where-Object{$_ -like "Details:*"}                 | ForEach-Object{$_ -replace "Details: ",""} )
       
        $Global:RegEvents +=$Data
    }
}
Function Get-DriverEvents($Interval)
{
    #Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 2000 | ?{$_.id -eq "1"}
    
    $Events = Get-WinEvent  -LogName "Microsoft-Windows-Sysmon/Operational" -FilterXPath "*[System[EventID=6]]"  | Where-Object {($_.timecreated -ge  $Interval)}

    foreach ($item in $Events)
    {
        
        #$item | select * | fl
        $message = $item.message.split("`n") | ForEach-Object{$_.trimstart()} | ForEach-Object{$_.trimend()} | ForEach-Object{$_ -replace ";",","}
        #$message

        $Data = New-Object System.Management.Automation.PSObject
        $Data | Add-Member NoteProperty Id ($null)
        $Data | Add-Member NoteProperty UtcTime ($null)
        $Data | Add-Member NoteProperty ImageLoaded ($null)
        $Data | Add-Member NoteProperty Hashes ($null)
        $Data | Add-Member NoteProperty Signed ($null)
        $Data | Add-Member NoteProperty Signature ($null)
        $Data | Add-Member NoteProperty SignatureStatus ($null)
        
        $Data.Id                = $item.Id
        $Data.UtcTime           = ($message | Where-Object{$_ -like "UtcTime:*"}           | ForEach-Object{$_ -replace "UtcTime: ",""} )
        $Data.ImageLoaded       = ($message | Where-Object{$_ -like "ImageLoaded:*"}       | ForEach-Object{$_ -replace "ImageLoaded: ",""} )
        $Data.Hashes            = ($message | Where-Object{$_ -like "Hashes:*"}            | ForEach-Object{$_ -replace "Hashes: ",""} )
        $Data.Signed            = ($message | Where-Object{$_ -like "Signed:*"}            | ForEach-Object{$_ -replace "Signed: ",""} )
        $Data.Signature         = ($message | Where-Object{$_ -like "Signature:*"}         | ForEach-Object{$_ -replace "Signature: ",""} )
        $Data.SignatureStatus   = ($message | Where-Object{$_ -like "SignatureStatus:*"}   | ForEach-Object{$_ -replace "SignatureStatus: ",""} )
      
        $Global:DriverEvents +=$Data
    }
}

Clear-Host 
$Global:Table            = @()
$Global:ProcCreateEvents = @()
$Global:ProcTermEvents   = @()
$Global:NetEvents        = @()
$Global:FileEvents       = @()
$Global:RegEvents        = @()
$Global:DriverEvents     = @()

$DataFolder = "\\Mac\Home\Downloads\events"
#$DataFolder = "d:\events"

#$Interval = (get-date) - (new-timespan -Minutes 25)
[System.DateTime]$LastSysStart = [System.DateTime]((Get-WinEvent -LogName "System"  -FilterXPath "*[System[EventID=6009]]" | Select-Object -first 1).timecreated) - (New-TimeSpan -Seconds 10)

$LastSysStart
Get-ProcCreateEvents $LastSysStart  ; "Get-ProcCreateEvents"
Get-ProcTermEvents   $LastSysStart  ; "Get-ProcTermEvents "
Get-NetEvents        $LastSysStart  ; "Get-NetEvents"
Get-FileEvents       $LastSysStart  ; "Get-FileEvents"
Get-RegEvents        $LastSysStart  ; "Get-RegEvents"
Get-DriverEvents     $LastSysStart  ; "Get-DriverEvents"
#$Global:ProcTermEvents |Select-Object Id,UtcTime,ProcessId,Image,User,ParentProcessId,ParentImage   |Format-Table -AutoSize

foreach ($termitem in $Global:ProcTermEvents)
{
    foreach ($procitem in $Global:ProcCreateEvents)
    {
        if ($termitem.ProcessGuid -eq $procitem.ProcessGuid) {$procitem.UtcEndTime = $termitem.UtcTime}
    }
}

#$Global:ProcCreateEvents |Select-Object Id,UtcTime,UtcEndTime,ProcessId,Description,Image,User          |Format-Table -AutoSize
#$Global:NetEvents        |Select-Object Id,UtcTime,ProcessGuid,ProcessId,Image,User,Protocol,Initiated  |Format-Table -AutoSize
#$Global:ProcCreateEvents |Select-Object * -First 1 
$Global:ProcCreateEvents | sort UtcTime | Export-Csv -Path  $DataFolder\Procc.csv   -Encoding UTF8 -Delimiter ";" 
$Global:NetEvents        | sort UtcTime | Export-Csv -Path  $DataFolder\Net.csv     -Encoding UTF8 -Delimiter ";"
$Global:FileEvents       | sort UtcTime | Export-Csv -Path  $DataFolder\File.csv    -Encoding UTF8 -Delimiter ";"
$Global:RegEvents        | sort UtcTime | Export-Csv -Path  $DataFolder\Reg.csv     -Encoding UTF8 -Delimiter ";"
$Global:DriverEvents     | sort UtcTime | Export-Csv -Path  $DataFolder\Driver.csv  -Encoding UTF8 -Delimiter ";"
#$Global:NetEvents |Select-Object * -First 1
write-host "Completed!"