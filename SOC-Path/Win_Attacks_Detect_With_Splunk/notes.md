# Detecting Common User/Domain Recon
- Key Techniques:
    - Attacker wants to map info about AD & its structure/ relationships
    - Common Tools:
        - `whoami /all`
        - `wmic computersystem get domain`
        - `net user /domain`
        - `net group "Domain Admins" /domain`
        - `arp -a`
        - `nltest /domain_trusts`

    - Garde un oeil sur les commandes pour ler alerts: au-dessus

## User/Domain Reconnaissance Using BloodHound/SharpHound
- Background Info:
    - `SharpHound.exe` is a collector for BloodHound
    - suspicious command: `.\Sharphound3.exe -c all`

- Detection:
    - **BloodHound collector executes numerous LDAP queries for DC to get info**
        - `Event 1644` >> an option to monitor but not that helpful

    - **With SilkETW** >> `Microsoft-Windows-LDAP-Client` provider of **ETW**
    - Use this and plus, `YARA` rules

    - **The list of LDAP filters frequently used by Reconnaissance Tools.**
        ```code
        Recon Tool                     >>           Filter

    enum ad user comments (Metasploit) >> (&(&(objectCategory=person)(objectClass=user))(|(description=*pass*)(comment=*pass*)))
    enum ad computers (Metasploit)     >> (&(objectCategory=computer)(operatingSystem=*server*))
    enum ad groups (Metasploit)        >> (&(objectClass=group))
    enum ad managedby_groups (MetSp)   >> (&(objectClass=group)(managedBy=*)),
                                          (&(objectClass=group)(managedBy=*)(groupType:1.2.840.113556.1.4.803:=2147483648))

    Get-NetComputer (PowerView)        >> (&(sAMAccountType=805306369)(dnshostname=*))
    Get-NetUser - Users (Powerview)    >> (&(samAccountType=805306368)(samAccountName=*))
    Get-NetUser - SPNs (Powerview)     >> (&(samAccountType=805306368)(servicePrincipalName=*))
    Get-DFSshareV2 (Powerview)         >> (&(objectClass=msDFS-Linkv2))
    Get-NetOU (PowerView)              >> (&(objectCategory =organizationalUnit)(name=*))

    Get-DomainSearcher (Empire)        >> (samAccountType=805306368)
    ```

    - To find these events, I can use those filters to trigger the incidents:

## Detecting User/Domain Recon With Splunk
- Scenario:
    - I got a timeframe: `earliest=1690447949 latest=1690450687`
    - Tool: `Splunk`

- Command:
    ```splunk
    index=main source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1 earliest=1690447949 latest=1690450687

    | search process_name IN (arp.exe,chcp.com,ipconfig.exe,net.exe,net1.exe,nltest.exe,ping.exe,systeminfo.exe,whoami.exe)
      OR (process_name IN (cmd.exe,powershell.exe)
      AND process IN (*arp*,*chcp*,*ipconfig*,*net*,*net1*,*nltest*,*ping*,*systeminfo*,*whoami*))

    | stats values(process) as process, min(_time) as _time by parent_process, parent_process_id, dest, user

    | where mvcount(process) > 3
    ```
    - `IN (..)` >> to choose anything from this
    - it checks `the process field contains certain substrings.`
    - `values()` checks unique values of `process` field
    - `min(_time)`>> captures the earliest time
    -

## Detecting Recon By Targeting BloodHound
- Command:
    ```code
        index=main earliest=1690195896 latest=1690285475 source="WinEventLog:SilkService-Log"
        | spath input=Message
        | rename XmlEventData.* as *
        | table _time, ComputerName, ProcessName, ProcessId, DistinguishedName, SearchFilter
        | sort 0 _time
        | search SearchFilter="*(samAccountType=805306368)*"
        | stats min(_time) as _time, max(_time) as maxTime, count, values(SearchFilter) as SearchFilter by ComputerName, ProcessName, ProcessId
        | where count > 10
        | convert ctime(maxTime)
    ```
    - `spath` command is used to extract fields from the `Message` field
    - `rename` to rename the field for easier access later
    - `sort 0 _time` >> sorts the `_time` from oldest to newest; `0` arg means *no limit on the number of results on the output*
    - `search` >> used to filter the results where `SearchFilter`  contains the string `*(samAccountType=805306368)*`
    - `stats` to aggregate the results `max(_time)` >> to get the latest time, `count`
    - `ctime(maxTime)` >> to convert Unix timestamp to human-readable format
    - `where count > 10` >> **only show processes that executed the LDAP search filter more than 10 times**

    - Below How `count` counts these combinations within each group (this group thing is combination given by fields >> by `stats`:
    - `Group = unique combo of ComputerName + ProcessName + ProcessId`

    ```code
        ComputerName	ProcessName	ProcessId	SearchFilter
        PC-1	powershell.exe	1234	(samAccountType=805306368)
        PC-1	powershell.exe	1234	(samAccountType=805306368)
        PC-1	powershell.exe	9999	(samAccountType=805306368)
        PC-2	svchost.exe	8888	(samAccountType=805306368)

        → The stats will group these as:

        PC-1 | powershell.exe | 1234 → count = 2

        PC-1 | powershell.exe | 9999 → count = 1

        PC-2 | svchost.exe | 8888 → count = 1
    ```

## Practical Challenges:
1. Modify and employ the Splunk search provided at the end of this section on all ingested data
   (All time) to find all process names that made LDAP queries where the filter includes the string *(samAccountType=805306368)*.
   Enter the missing process name from the following list as your answer. N/A, Rubeus, SharpHound, mmc, powershell .......

**Solved:**
    - J'ai enleve les restrictions de temps >> j'ai obtenu le drapeau:
    -
    - Voila, ca y est, c'est fini!









