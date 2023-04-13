# Blue Team Notes

## Requirements

- Install Sysmon (Using SwiftOnSecurity)
    - https://github.com/SwiftOnSecurity/sysmon-config 

```cmd
.\sysmon64.exe -accepteula -i .\sysmonconfig-export.xml
```

## Detection

General log hunting note/reference:
```powershell
Get-WinEvent -FilterHashTable @{LogName='Security';ID='XXXX'} | Format-List
```

### Command Execution
- Check the Windows EID for process execution
- Use Sysmon to detect process execution (focus on schedtasks.exe)
- Enable Powershell CLI logging
    - GP, Policies, Computer Configuration, Administrative Templates, Windows Components, Windows PowerShell
        - Change maximum size of the event log (20MB by default) –NOTE: Can’t find where to change size?
        - Event 4104 (4105,4106 for stop/start)
        - Audit
            - Module logging
            - Script execution
            - Script block logging
            - Turn on transcription
                - Redirect to different folder
                    - c:\tools
- Csc.exe
- WMI execution (not working)
    - `Set-ItemProperty -Path "HKLM:\Software\Microsoft\Wbem\CIMOM" -Name "Logging" -Value "1"`
    - `net start winmgmt`
    - `Get-WmiObject -Class Win32_OperatingSystem -Namespace "root\cimv2"`

### File Modification
- Sysmon ID 2: A process changed a file creation time (probably not the best approach)

- Sysmon EID 11: Probably not the best method?
- Windows Event 4656

- Enable auditing on file system
    - C:\Windows\system32\Tasks\
    - Right-click, properties, Security, Advanced, Auditing

### Process Creation
- Enable process tracking
    - Local Security policy→Local Policy→audit policy→Audit Process Tracking
- Enable Process Creation
    - Local Security policy→Advanced Audit Policy Configuration→Detailed Tracking→Audit Process Creation

- Event 4688
    - schtasks.exe
    - csc.exe

### Scheduled Job Creation
- Enable Object Access events
    - Local policy→audit policy→Object Access
    - Event ID 4968


### Windows Registry Key Creation

- Enable Auditing
    - HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\
- Enable Auditing via Local Policy
    - Local policy→Advanced Audit Policy Configuration→Object Access→Audit Registry


### Updated Scheduled Task 
- Enable event ID 4702 (Enabled by default?)
- `Get-WinEvent -FilterHashTable @{LogName='Security';ID='4702'} -MaxEvents 1 | Format-List`

### WMI Event
- Sysmon Event 19 (WmiEventFilter activity)
- Sysmon Event 20 (WmiEventConsumer activity)
- Sysmon Event 21 (Registration of WMI consumers)
- Event 5857/5858

### General Hunting

```powershell
# Task Execution
(Get-ScheduledTask).Actions | Where-Object {$_.Execute -notlike "*windir*" -and $_.Execute -notlike "*Systemroot*"} | Group-Object -property Execute | Sort-Object -Property Count

# Author 
get-scheduledtask | Group-Object -property Author | Sort-Object -Property Count

# Task Arguments
(Get-ScheduledTask).Actions | Where-Object {$_.Arguments -like "*powershell*"} | Select-Object *

# Task Path Outside Microsoft
get-scheduledtask | Where-Object {$_.TaskPath -notlike "\Microsoft*"} | Format-Table TaskName,Taskpath,State
```


## Red Team Escalation Notes

**NEW Scheduled Tasks**
1. New Scheduled Task (schtasks.exe)
    -  4688 (process creation) looking for schtasks.exe
    - 4968 (new scheduled task) 
        ```powershell
        $event4688 = get-winevent -logname Security | Where-Object {$_.id -like ‘4688’}
        $event4688 | Where-Object {$_.
        ```
        SYSMON
        ```powershell
        Get-WinEvent -logname Microsoft-Windows-Sysmon/Operational | ? {$_.id -like ‘1’} | ? {{$_.Message -like '*schtasks*'} | select *
        ```

2. PowerShell
    - 4104 (PS Script Block Logging)

3. .NET 
    - 4104 ? Maybe?

**MODIFY Scheduled Tasks**

4. Modified Scheduled Tasks, Download .script 
    - 4656 (File Modification)
    - Sysmon 11, maybe? 
    - 4702 (Modified Scheduled Task)

5. Reg /xml 
    - 4702, maybe?

**REMOTE Scheduled Task Creation**

6. impacket wmi
    - 4688 for wmiprvse.exe 

## Resources

https://github.com/Oofles/scheduled-tasks
