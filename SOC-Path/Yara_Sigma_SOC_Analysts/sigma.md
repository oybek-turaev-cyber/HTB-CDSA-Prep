# Sigma
- Key Idea:
    - generic signature for describing detection rules
    - ideal work with SIEM & EDR
    - extension in `.yaml` format
    - idea >> compatibility >> portability
    - standardized format for analysts to create and share detection rules

    - Converter >> `sigmac` ou `uncoder.io`

    - Process >> `Sigma Rule -> Sigma Converter -> SIEM & EDR Tools`

    - **True power of Sigma lies in its convertibility**
    - *you just write a generic sigma rule then `sigmac` converter converts this rule to specific tool*
        - such as: `translate it for ElasticSearch, QRadar, Splunk, and many more`

- Rule Example:
  ```sigma
    title: Potential LethalHTA Technique Execution
    id: ed5d72a6-f8f4-479d-ba79-02f6a80d7471
    status: test
    description: Detects potential LethalHTA technique where "mshta.exe" is spawned by an "svchost.exe" process
    references:
        - https://codewhitesec.blogspot.com/2018/07/lethalhta.html
    author: Markus Neis
    date: 2018/06/07
    tags:
        - attack.defense_evasion
        - attack.t1218.005
    logsource:
        category: process_creation
        product: windows
    detection:
        selection:
            ParentImage|endswith: '\svchost.exe'
            Image|endswith: '\mshta.exe'
        condition: selection
    falsepositives:
        - Unknown
    level: high
 ```
    - `Detection:` >> two parts >> selection with Search Identifiers & condition


    - **Search Identifiers:**
        1. Lists (different options) >> the example in the below
        2. Maps (Key-Value Pair) >> the example in the above
    ```sigma
    detection:
        selection:
            Image|endswith:
              - 'cmd.exe'
              - 'powershell.exe'
            ParentImage|endswith:
              - 'winword.exe'
              - 'excel.exe'
              - 'notepad.exe'
    condition: selection
    falsepositives:
        - Unknown
    level: high
    ```
    - **Value Modifiers:**
        - to change the behavior of *Search Identifiers*
        - `contains` == `*val*`
        - `all` == Links all elements of a list with a logical "AND" (instead of the default "OR") >> `CommandLine|contains|all`
        - `startswith` == `val*` >> `ParentImage|startswith`
        - `endswith` == `*val` >>  `Image|endswith`
        - `re:`-> to say regex >> `CommandLine|re: '\[String\]\s*\$VerbosePreference`

    - **Condition Examples:**
        - logical AND / OR >> `keywords1 or keywords2`
        - 1/all of them >> `all of them`
        - `all of selection*`
        - `all of filter_*`
        - negation 'not' >> `keywords and not filters`
        - group >> selection1 and (keywords1 or keywords2)

## Developing Sigma Rules
- Example 1: LSASS Credential Dumping
    - goal here is to use `Sysmon ID 10` to identify `process_access`
    - fields: `TargetImage` and `GrantedAccess`
        - `GrantedAccess == 0x1010`  means >> combination of `PROCESS_VM_READ (0x0010) and PROCESS_QUERY_INFORMATION (0x0400) permissions`
        - `0x1010` >> both read & query
        - `0x0410` >> to read LSASS memory


    - Refer to `./win_access_process.yml` for Sigma Rule


    - **Conversion: Sigma Rule To Powershell command:**
        - command: `python sigmac -t powershell 'C:\Rules\proc_access_win_lsass_access.yml'`
        - magic happens >> `sigmac` returns this:
        - need to change to provide certain captured logs if exist
        ```sigma
        Get-WinEvent -Path C:\Events\YARASigma\lab_events.evtx |
        where {($_.ID -eq "10" -and $_.message -match "TargetImage.*.*\\lsass.exe" -and $_.message -match "GrantedAccess.*.*0x1010") }
        | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
        ```
        - Enhanced version: `./win_access_enhanced.yaml`

- Example 2: Multiple Failed Logins From Single Source (Based on Event 4776)
    - `4776` >> signals  credential validation occurs using NTLM authentication.
    - shows only `the computer name (Source Workstation) ` Not `Destionation`
    - Refer to this `./muliple_fails.yaml`

    - Key Part of the rule:
    ```rule
    detection:
        selection2:
            EventID: 4776
            TargetUserName: '*'
            Workstation: '*'
        condition: selection2 | count(TargetUserName) by Workstation > 3
    falsepositives:
        - Terminal servers
        - Jump servers
        - Other multiuser systems like Citrix server farms
        - Workstations with frequently changing users
    level: medium
    ```
    - **falsepositives:** not parsed by sigmac >> just to guide analysts

- Practical Challenge:
    1. Using sigmac translate the "C:\Tools\chainsaw\sigma\rules\windows\builtin\windefend\win_defender_threat.yml"
       Sigma rule into the equivalent PowerShell command. Then, execute the PowerShell command against
       "C:\Events\YARASigma\lab_events_4.evtx" and enter the malicious driver as your answer. Answer format: _.sys

    **Solved:**
    - J'ai utilise le converter `sigmac` et j'ai obtenu ca:
    ``` code
        Get-WinEvent -Path C:\path_to_file | where {($_.ID -eq "1006" -or $_.ID -eq "1116" -or $_.ID -eq "1015" -or $_.ID -eq "1117") }
        | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
    ```

    - Apres, j'ai trouve le .dll suspect
    - Voila, ca y est, c'est fini

## Hunting Evil with Sigma (Chainsaw Edition)
- Key Point:
    - When no SIEM >> go to `Chainsaw` or `Zircolite`
    - Goal: >> **use Sigma rules to scan not just one, but multiple EVTX files concurrently**
    - Chainsaw >> tool designed to swiftly pinpoint security threats within Windows Event Logs.

- Example 1: Hunting for Multiple Failed Logins From Single Source With Sigma
    - What you need:
        1. sigma rule file `.yaml`
        2. data file `.evtx`
        3. sigma config file how to search for in logs, specific what needed

    - Command:
    ```
    .\chainsaw_x86_64-pc-windows-msvc.exe hunt C:\Events\YARASigma\lab_events_2.evtx
    -s C:\Rules\sigma\win_security_susp_failed_logons_single_source2.yml
    --mapping .\mappings\sigma-event-logs-all.yml
    ```
    - `hunt` command by chainsaw
    - `-s` here to specify sigma file
    - `--mapping` config file

- Example 2: Hunting for Abnormal PowerShell Command Line Size With Sigma (Based on Event ID 4688)
    - Refer to `./sigma_powershell.yaml` for full rule

    - Key Part:
    ```code
    detection:
    selection:
        EventID: 4688
        NewProcessName|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
            - '\cmd.exe'
    selection_powershell:
        CommandLine|contains:
            - 'powershell.exe'
            - 'pwsh.exe'
    selection_length:
        CommandLine|re: '.{1000,}'
    condition: selection and selection_powershell and selection_length
    ```
    - Chainsaw Command:
    ```
    .\chainsaw_x86_64-pc-windows-msvc.exe hunt C:\Events\YARASigma\lab_events_3.evtx
    -s C:\Rules\sigma\proc_creation_win_powershell_abnormal_commandline_size.yml
    --mapping .\mappings\sigma-event-logs-all.yml
    ```

- Practical Challenge:
    1. Use Chainsaw with the "C:\Tools\posh_ps_win_defender_exclusions_added.yml"
       Sigma rule to hunt for suspicious Defender exclusions inside "C:\Events\YARASigma\lab_events_5.evtx".
       Enter the excluded directory as your answer.

    **Solved:**
    - J'ai utilise cette commande:
    ```
    .\chainsaw_x86_64-pc-windows-msvc.exe hunt C:\Events\YARASigma\lab_events_5.evtx
    -s C:\Tools\chainsaw\sigma\rules\windows\powershell\powershell_script\posh_ps_win_defender_exclusions_added.yml
    --mapping .\mappings\sigma-event-logs-all-new.yml
    ```

    - Voila, apres, j'ai obtenu "ScriptBlockText: Set-MpPreference -ExclusionPath c:\******\*****"
    - Ca y est, c'est fini


## Hunting Evil with Sigma (Splunk Edition)
- Goal:
     - to create sigma rule
     - use `sigmac` to convert it to Splunk command

- Example 1: Hunting for MiniDump Function Abuse to Dump LSASS's Memory (comsvcs.dll via rundll32)
    - Command:
        - ` python sigmac -t splunk C:\Tools\proc_dll.yml -c .\config\splunk-windows.yml`
        - `-c ` >> tells specific for which Splunk

    - Splunk:
        - `(TargetImage="*\\lsass.exe" SourceImage="C:\\Windows\\System32\\rundll32.exe" CallTrace="*comsvcs.dll*")`

- Example 2: Hunting for Notepad Spawning Suspicious Child Process
    - Command:
        - `python sigmac -t splunk C:\Rules\notepad_susp_child.yml -c .\config\splunk-windows.yml`

    - Splunk:
        ```code
    (ParentImage="*\\notepad.exe" (Image="*\\powershell.exe" OR Image="*\\pwsh.exe"
    OR Image="*\\cmd.exe" OR Image="*\\mshta.exe" OR Image="*\\cscript.exe" OR Image="*\\wscript.exe"
    OR Image="*\\taskkill.exe" OR Image="*\\regsvr32.exe" OR Image="*\\rundll32.exe" OR Image="*\\calc.exe"))
    ```
- Practical Challenge:
    1. Using sigmac translate the "C:\Rules\win_app_dropping_archive.yml" Sigma rule into the equivalent Splunk search.
        Then, navigate to site, and submit the Splunk search sigmac provided.
        Enter the TargetFilename value of the returned event as your answer.

    **Solved:**
    - J'ai utlise cette commande:
    - Splunk Command:
    ```code
    ((Image="*\\winword.exe" OR Image="*\\excel.exe" OR Image="*\\powerpnt.exe" OR Image="*\\msaccess.exe"
    OR Image="*\\mspub.exe" OR Image="*\\eqnedt32.exe" OR Image="*\\visio.exe" OR Image="*\\wordpad.exe"
    OR Image="*\\wordview.exe" OR Image="*\\certutil.exe" OR Image="*\\certoc.exe" OR Image="*\\CertReq.exe"
    OR Image="*\\Desktopimgdownldr.exe" OR Image="*\\esentutl.exe" OR Image="*\\finger.exe" OR Image="*\\notepad.exe"
    OR Image="*\\AcroRd32.exe" OR Image="*\\RdrCEF.exe" OR Image="*\\mshta.exe" OR Image="*\\hh.exe"
    OR Image="*\\sharphound.exe") (TargetFilename="*.zip" OR TargetFilename="*.rar" OR TargetFilename="*.7z"
    OR TargetFilename="*.diagcab" OR TargetFilename="*.appx"))
    ```






