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

# Tapping into ETW

## Detection Example 1. Detecting Strange Parent-Child Relationship
- Happens when processes call other unusual processes
- highly unlikely to see "calc.exe" spawning "cmd.exe"
- Tool to use >> `Process Hacker`

- **Attack Technique: Parent PID Spoofing:**
    - Tool: Powershell >> `psgetsystem project` > need to import this module `psgetsys.ps1`
    - `[MyProcess]::CreateProcessFromParent(9432,"C:\Windows\System32\cmd.exe","")`
        - Here >> PID 9432 is `spoolsv.exe` >> shows as if it's the parent process of the
                `cmd.exe`
        - Due to the parent PID spoofing technique we employed, `Sysmon Event 1` incorrectly displays spoolsv.exe as the parent of cmd.exe. However, it               was actually `powershell.exe` that created `cmd.exe`.
        -
- **How to Detect?:**
        - So here. sysmon is no more effective, we have to say goodbye to him for now.
        -
        - I used the stronger log tool which is the father of the most existing ones: ETW
        - **SilkETW:** >>  Using `Microsoft-Windows-Kernel-Process` provider, we can see more
          what's going in the lower level
        - `SilkETW.exe -t user -pn Microsoft-Windows-Kernel-Process -ot file -p C:\windows\temp\etw.json`
        -
        - By analyzing `etw.json` log file >> we see that `powershell` is the one who used
          the process ID `9432` and initiated the `cmd.exe`

## Detection Example 2: Detecting Malicious .NET Assembly Loading
- a Strategy known as `Living off the Land` (LotL) >> **You use whatever you have without
        bringing anything extra**
        - use legitimate apps & services to carry out the malicious processes

- another Strategy >> `Bring Your Own Land >> (BYOL)` >>
        - This attack tries to employ `.NET assemblies` executed `entirely in memory.`
        - involves creating `custom-built tools` using languages `like C#`, rendering them independent of the pre-existing tools on the target system.
        - **Why this attack is effective ?**
            - since >> already present .NET env in the system
            - .NET assemblies `has a nice ability` **to be loaded directly into memory**
            - This means that an `executable or DLL` does not need to be written physically to the disk - instead, `it is executed directly in memory`.
            - a wide range of libraries into the .NET framework

- **Attack Technique:  "execute-assembly" by CobaltStrike**
    - implemented in CobaltStrike
    - CobaltStrike's 'execute-assembly' command allows the user to `execute .NET assemblies directly from memory`,
    - making it an ideal tool for implementing a BYOL strategy.

    - We use now .NET assembly >> precompiled and resided on the disk >> `Seatbelt`
    - `Seatbelt` >>  is a well-known .NET assembly, often employed by adversaries who load and execute it in memory
        - To gain `situational awareness` on a `compromised system.`
        -
        - we run `.\Seatbelt.exe TokenPrivileges` command in the powershell
        - This .NET assembly will load DLLs: **clr.dll and mscoree.dll**
        -

- **How To Detect?:**
        - We will keep an eye on `.NET-related DLLs such as 'clr.dll' and 'mscoree.dll'.`
        - We can use Sysmon ID 7 >> however, it does not give **granular details about the actual content of the loaded .NET assembly.**
            - while it informs us about the DLLs being loaded
        - To deeper & better analyse >> `(ETW)` and specifically the `Microsoft-Windows-DotNETRuntime` provider.
        -
        - We run `SilkETW` >> `SilkETW.exe -t user -pn Microsoft-Windows-DotNETRuntime -uk 0x2038 -ot file -p C:\windows\temp\etw.json`
        - Then we simulate the attack again and the **analyse the etw.json logs**
        - Now, we see **wealth of information about the loaded assembly, including method names.**

## Practical Challenge:
- Task is to simulate the attack with `Seatbelt` and need to find the **ManagedInteropMethodName** from the loaded .NET assembly

**Solved:**
    - For this, I use `SilkETW` >> `SilkETW.exe -t user -pn Microsoft-Windows-DotNETRuntime -uk 0x2038 -ot file -p C:\windows\temp\etw.json`
    - This captures loaded .NET assembly with more info thanks to the provider
        `Microsoft-Windows-DotNETRuntime`
    - I manually review the `etw.json` file >> I searched for `Seatbelt` and analysed its loaded
        .NET assemblies and there I found the Method Names loaded for this
    - Voila c'est comment j'ai trouve la reponse!

# Get-WinEvent
- an ideal tool >> to work with massive amount of logs

- `Get-WinEvent -ListLog * | Select-Object LogName, RecordCount, IsClassicLog, IsEnabled, LogMode, LogType | Format-Table -AutoSize`
        - `-ListLog` >> shows all available logs

- `Get-WinEvent -ListProvider * | Format-Table -AutoSize`
        - >> shows log providers

- `Get-WinEvent -LogName 'System' -MaxEvents 50 | Select-Object TimeCreated, ID, ProviderName, LevelDisplayName, Message | Format-Table -AutoSize`
        - >> Retrieving events from the System log

- `Get-WinEvent -LogName 'Microsoft-Windows-WinRM/Operational' -MaxEvents 30 | Select-Object TimeCreated, ID, ProviderName, LevelDisplayName, Message        | Format-Table -AutoSize`
        - >> now logs from Microsoft-Windows-WinRM/Operational

- `Get-WinEvent -Path 'C:\Tools\chainsaw\EVTX-ATTACK-SAMPLES\Execution\exec_sysmon_1_lolbin_pcalua.evtx' -MaxEvents 5 | Select-Object >>> specify he`
        - >> from the files `.evtx`

- `Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=1,3} | Select-Object TimeCreated, ID, ProviderName, LevelDisplay       Name, Message | Format-Table -AutoSize`
        - >> now with **-FilterHashtable**
        - **Sysmon ID 1 and 3** >> for *dangerous or uncommon binaries* or C2 communication possible
        -
- `Get-WinEvent -FilterHashtable @{Path='C:\Tools\chainsaw\EVTX-ATTACK-SAMPLES\Execution\sysmon_mshta_sharpshooter_stageless_meterpreter.evtx'; ID           =1,3} |`
            - This is for exported files

## If we want the get event logs based on a date range (5/28/23 - 6/2/2023)
- **Commands**
    - `$startDate = (Get-Date -Year 2023 -Month 5 -Day 28).Date`
    - `$endDate   = (Get-Date -Year 2023 -Month 6 -Day 3).Date`
    - Final Command:
    - `Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=1,3; StartTime=$startDate; EndTime=$endDate} | Select-Object Tim       eCreated, ID, ProviderName, LevelDisplayName, Message | Format-Table -AutoSize`

    - *filter between the start date inclusive and the end date exclusive. That's why we specified June 3rd and not 2nd.*

- **Important:** >> **Sysmon** >> **ID 1 >> Process Create**
    - `Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=1} | Where-Object {$_.Properties[21].Value -like "*-enc*"} | For       mat-List`
        - `Where-Object {$_.Properties[21].Value -like "*-enc*"}`
        - `$_` >> refers to the current object in the pipeline, i.e., each individual event that was retrieved and passed from the previous command.
        - `.Properties[21].Value` >> *index 21* corresponds to the ParentCommandLine property of the event
        - `-like "*-enc*"` >> **-enc** string might be part of suspicious commands, for example, it's a common parameter in PowerShell commands to denote            an **encoded command which could be used to obfuscate malicious scripts.**

## Practical Challenge:
- I need utilize the `Get-WinEvent` cmdlet to traverse all event logs located within the "C:\Tools\chainsaw\EVTX-ATTACK-SAMPLES\Lateral Movement" dire      ctory and determine when the **\\*\PRINT** share was added. Enter the time of the identified event.
    -
**Solved:**
    I created a **Get-WinEvent** query >> the location has more than 20 log files
    I used `Where-Object` cmdlet and also use Message property from the logs to match the message I
    am looking for ..  and spedificied some columns I am interested in
- `Get-WinEvent  -Path 'C:\Tools\chainsaw\EVTX-ATTACK-SAMPLES\Lateral Movement' | `
      `Where-Object {$_.Message -like "*\\*\PRINT*"} | Select-Object TimeCreated, ProviderName`

- Voila >> J'ai trouve le flag!

# Skills Assessment

## Challenge #1
- *By examining the logs located in the "C:\Logs\DLLHijack" directory, determine the process responsible for executing a DLL hijacking attack. Enter t       he process name as your answer*

    **Solved:**
- Tool >> Event Viewer >> Sysmon ID 7
- I found that the `WININET.dll` is associated with the executable which is running from the
    suspicious location >> not `/windows/system32`
- Manual review the associated processes with these DLL
- Voila >> J'ai retrouve le flag.

## Challenge #2
- *By examining the logs located in the "C:\Logs\PowershellExec" directory, determine the process that executed unmanaged PowerShell code. Enter the p      rocess name as your answer*

    **Solved:**
- Tools >> Event Viewer >> Sysmon ID 1,7
- I look at the loaded DLL by powershell.exe >> among them, the necessary ones `clr.dll` and
        `clrjit.dll` >> I keep an eye on them
- Then I found that `an application` which is not supposed to use `clr.dll` or `clrjit.dll` is
        loading these variables
- Interestingly, that application is running from the suspicious location user-writable
        directory >> not >> `/windows/system32`
- Voila, c'est le flag!

## Challenge #3
- *By examining the logs located in the "C:\Logs\PowershellExec" directory, determine the process that injected into the process that executed unmanag      ed PowerShell code.*

**Solved:**
- It went a bit challenging now I need to find the process that injected or created another
        process or thread in another process.
- Tool >> Event Viewer
- I found out that >> `Sysmon ID 8`(RemoteThread) >> It's the one which gives me the correct direction >>
- I filtered the logs based on sysmon ID 8 >> then I found the process which injected into the
        another process which I found a bit earlier!
- Voila >> c'est le flag!

## Challenge #4
- *By examining the logs located in the "C:\Logs\Dump" directory, determine the process that performed an LSASS dump. Enter the process name*

**Solved:**
- It went well >> I knew that the suspicious service will connect to the `lsass.exe`
- Tool >> Event Viewer >> Filter Option
- I used the naive approach >> I filtered based on the `lsass.exe` and look for the each service
        connected to this service
- Importantly >> I keep an eye on the services which are from `not /windows/system32` >> this
        idea helps me  a lot >>
- After searching 258 logs >> I see the services from the `unusual location` accessing to our
        honey
- Voila, c'est le processus de recherche de la reponse!

## Challenge #5
- *By examining the logs located in the "C:\Logs\Dump" directory, determine if an ill-intended login took place after the LSASS dump*

**Solved:**
- I have the checked the `Event ID 4624` >> Successful Login
- Tool >> Event Viewer >> Filter Option
- I identified the time when suspicious program accessed to the lsass.exe
- Then based on this time, I see any successful logins >> I see no activites of "ill-intended"
- Voila, J'ai retrouve le drapeau!

## Challenge #6
- *By examining the logs located in the "C:\Logs\StrangePPID" directory, determine a process that was used to temporarily execute code based on a stra      nge parent-child relationship. Enter the process name*

**Solved:**
- It went a bit challenging for me
- I kinda got the feeling that I need to search for powershell.exe or cmd.exe and who executed
        them
- This feeling led me to the right direction
- Tool >> Event Viewer >> `Sysmon ID 1 and 10` >>  I understood that I need logins to tell me when
        "Process Created" and When "Process Accessed To Another Process" >> this shed a light in the
        dark room for me
- I filtered the logs based on these IDs >> manual check the few logs (since they were a few)
- I found the suspicious connection explorer.exe > in_the_middle_another_benign_application >>
        then cmd.exe >> then I found the evil.
- Voila, c'est le processus de recherche de la reponse!

