# Windows Events Logs
- Windows >> stores logs from different components >> system >> application >> ETW providers & services
- `Event Viewer` or `Windows Event Log API`
- *.evtx* >> log files
    - `Event ID` >> unique identifier

- `Create Custom XML Queries` >> to search for specific `SubjectLogonID` >> The idea: you can change
    it to different fields: `ProcessID`
    - [EventData[Data[@Name='SubjectLogonID']='0x3E7']]

- **Helpful Windows Event Logs:**
    - **System:**
        - `Event ID 1074` >> system shutdown/restart
        - `Event ID 6005` >> event log service was started
        - `ID 6006` >> event log service was stopped
        - `ID 7040` >> service status change >> service startup change
    - **Security:**
        - `ID 1102` >> audit log was cleared
        - `ID 1116, 1118, 1119, 1120,` >> antivirus malware detection, remediation informations
        - `ID 4624` >> successful login
        - `ID 4625` >> failed login
        - `ID 4648` >> logon attempt using explicit credentials
        - `ID 4672` >> special privileges assigned to a New Logon
        - `ID 4698` >> scheduled task is created
        - `ID 4700, 4701, 4702` >> scheduled task is enabled / disabled / updated

## Practical Challenges:
    1. I analyzed the event with **ID 4624**, that took place `on 8/3/2022 at 10:23:25`. I conducted a investigation and provide the name of the executable responsible for the modification of the auditing settings. >>>
    **Solved:** >> Using `Event Viewer` >> `Filter` Option for the Event ID and manual analysis the certain logs

    2. I built an custom `XML query` to determine if the previously mentioned executable modified the auditing settings of C:\Windows\Microsoft.NET\Framework64\v4.0.30319\WPF\wpfgfx_v0400.dll. I found the time and provided as an answer HH:MM:SS
    **Solved:** >> Using `Event Viewer` >> `Filter` Option >> `XML` custom query to search for the
    specific `ObjectID`

# Analyzing Evil With Sysmon & Event Logs
- **Sysmon >> System Monitor**
    - detailed info >> `process creation`, `network connections`, `changes to file creation` etc
    - uses IDs >>  each ID corresponds to a specific type of event
        - `ID 1` >> Process Creation events
        - `ID 3` >> Network Connection events
        - `ID 7` >> Image Loaded
        - `ID 8` >> Create RemoteThread >> when a process creates a thread in another process.
        - `ID 10` >> Process Access >> when a process opens another process
        - `ID 255` >> Error

    - *Install sysmon*: `sysmon.exe -i -accepteula -h md5,sha256,imphash -l -n`
    - To use updated sysmon file >> `sysmon.exe -c sysmonconfig-export.xml`

## Detection Example 1: Detecting DLL Hijacking
    - `dll hijacking` >> when an the certain `dynamic link library` is used as modified with the
        same name to trick the applications which use dlls
    - For example >> calc.exe >> uses `WININET.dll` and you are putting another file with different
        code under the same of this dll and putting all in user-writable folder >> the application
        is starting to search for the necessary dll from the current file where it is located, voila
        customized dll is executed

- **How to Detect DLL Hijacking:**
    - Put the sysmon: use `Event Viewer`, filter for the `ID 7`
    - Keep an eye on files locations except for `system32` >> some options: AppData >> Temp folder
        >> User Folders
    - Keep an eye on the `Microsoft-signed` dlls

## Detection Example 2: Detecting Unmanaged PowerShell/C-Sharp Injection
    - `unmanaged powershell injection` >> calling powershell-based .dlls through other services or
        applications which do not raise suspicion for the detecting devices
        why it is `unmanaged` since it bypasses the `managed` way of calling powershell.exe which is
        controlled by CLR >> common language runtime

    - **Process Hacker** >> nice application pour montre des processes avec les couleurs differents

    - The core idea is that look for the certain dlls such as `clr.dll` or `clrjit.dll` which are
        used when `C# code` is ran as part of the runtime to execute the bytecode.
    - Then look what program is natively using them and keep an eye on the one which seems odd and
        normally should not use these dlls >> voila, tu as retruve le response
## Detection Example 3: Detecting Credential Dumping
    - **Mimikatz:** >> credential dumping tool
        - `privilege::debug` >> `sekurlsa::logonpasswords` >> dumps the memory >> shows credentials
        - It accesses to the ` Local Security Authority Subsystem Service (LSASS)` >> **lsass.exe**

    - **Detection:** >> `Event Viewer` >> Sysmon `ID 10`(Process Access)
    - Keep an eye what service (legitimate or not) (look at the location from what location is
        initiated) >> is accessing to the **lsass.exe**
    - Voila, you can see the some strange apps

## Practical Challenges:
    1. In the windows system, I found the `dll hijacking` attack and the SHA256 hash value of the
       corresponding .dll
       **Solved:** >> Event Viewer >> calc.exe is initiated from /Desktop >> which is not normal and
       using WININET.dll library which is also not native for the calculation purposes
    2. I found the `Unmanaged PowerShell attack` in windows and provide the SHA256 hash of clrjit.dll that spoolsv.exe used
       **Solved:** >> Event Viewer >> `crl.dll` and `clrjit.dll` are loading for the spoolsv.exe
       which is abnormal >> since these dlls are also with powershell.exe >> so suspicious!
    3. I found the activity of `the Credential Dumping attack` and provided the NTLM hash of the Administrator user password which is captured.
       **Solved:** Using `Mimikatz`, and special its commands: `privilege::debug` and
       `sekurlsa::logonpasswords` >> Voila

# Event Tracing For Windows (ETW)
    - ETW >> **tracing mechanism** for events raised by both `user-mode applications` and `kernel-mode device drivers`.
        - `Providers` >> event loggers
        - `Controllers` >> controls what to log for the providers
        - `Consumers` >> subscribe to specific events of interest and receive those events for
            further processing or analysis >> `Event Viewer` or `Sysmon`
    - **How to Play with ETW?**
        - `logman` >> `logman.exe query -ets`
        - Logman is a pre-installed utility for managing Event Tracing for Windows (ETW) and Event Tracing Sessions.
        - `-ets` parameter will allow for a direct investigation of the event tracing sessions
        -
        - `logman.exe query "EventLog-System" -ets`
        - `logman.exe query providers`

        - `logman.exe query providers | findstr "Winlogon"`
        - `logman.exe query providers Microsoft-Windows-Winlogon`
    - **GUI-based alternative is Performance Monitor**

    - **Useful Providers:**
        - `Microsoft-Windows-DotNETRuntime` >> focuses on .NET runtime events >> to detect anomalies
            with .NET executions
        - `Microsoft-Windows-PowerShell` >> provider tracks PowerShell execution and command activity, making it invaluable for detecting suspicious Power              Shell usage
        - `Microsoft-Antimalware-Service` >> ETW provider can be employed to detect potential issues with the antimalware service
        - `Microsoft-Windows-DNS-Client` >> visibility into DNS client activity >> unusual DNS requests that may indicate C2 communication
        -













