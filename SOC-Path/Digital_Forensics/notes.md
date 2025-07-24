# Intro
- Key Info:
    - Electronic Evidence >> Preservation of Evidence >> Forensic Process
    - Process:
        - Create Image >> Document System' State >> Identify & Preserve  >> Analyze Evidence >> Timeline >> IoCs >> Report


- Benefits: For SOC People:
    - post-mortem of incidents
    - rapid analysis of affected devices
    - legal cases
    - proactive threat hunting
    - IR strategies

# Windows Forensics
- **NTFS**

    - file system since 1993
    - successor of FAT

- **Key Forensics Artifacts by NTFS:**

    - `File Metadata` >>

    - `MFT Entries` >> Master File Table >> metadata for all files and directories on a volume

    - `File Slack and Unallocated Space` >> unused portion of a cluster

    - `File Signatures`

    - `USN Journal` >> Update Sequence Number >> record changes made to files and directories

    - `LNK Files` >> shortcut files >> insights into recently accessed files or executed programs.

    - `Prefetch Files` >> used to improve startup performance
        - indicate which programs have been run on the system and when they were last executed

    - `Registry Hives` >> Malicious activities or unauthorized changes can leave traces in the registry

    - `Shellbags` >> registry entries >> store folder view settings, such as window positions and sorting preferences
        - navigation patterns and potentially identify accessed folders.

    - `Thumbnail Cache` >> *reveal files that were recently viewed, even if the original files have been deleted.*

    - `Alternate Data Streams (ADS)` >>  additional streams of data associated with files

    - `Volume Shadow Copies` >> system backup key info

- **Execution Artifacts:**

    - traces left by apps/programs executed in Win
    - `Prefetch Files` >> Windows has prefetch folder >> *reveal a history of executed programs and the order in which they were run.*
        - `C:\Windows\Prefetch`

    - `Shimcache` >> helps identify recently executed programs and their associated files.
        - `Registry: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache`

    - `Amcache` >> database >> *info of installed applications and executables >> identify potentially suspicious or unauthorized software.*
        - `C:\Windows\AppCompat\Programs\Amcache.hve (Binary Registry Hive)`

    - `UserAssist` >> registry key >> info about programs executed by users
        - `Registry: HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist`

    - `RunMRU Lists` >> Most Recently Used, In Registry >> recently executed programs by locations of `Run` and `RunOnce` keys
        - `Registry: HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`

    - `Jump Lists` >> *recently accessed files, folders, and tasks associated with specific applications*
        - `User-specific folders (e.g., %AppData%\Microsoft\Windows\Recent)`

    - `Recent Items` >>  Recently accessed files
        - `User-specific folders (e.g., %AppData%\Microsoft\Windows\Recent)`

    - Windows Event Logs >>
        - `C:\Windows\System32\winevt\Logs`

- **Windows Persistence Artifacts:**

    - Key Targets by Attackers:
        - registry keys
        - startup processes
        - scheduled tasks / services

    - Registry:
        - `crucial database`, storing `critical system settings` for the Windows OS
        - `configurations` for devices, security, services,
        - the `storage of user account security configurations` in the `Security Accounts Manager (SAM)`
        - it's essential to **routinely inspect Registry autorun keys.**

    - **Possible Autorun Keys for Persistence:**
        - **Run/RunOnce Keys:**
        ```code
            HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run

            HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce

            HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run

            HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce

            HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\
        ```
        - **Keys used by WinLogon Process:**
        ```code
            HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon

            HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell
        ```
        - **Startup Keys:**
        ```code
            HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders

            HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders

            HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders

            HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User
        ```
    - Schtasks:
        - location >> `C:\Windows\System32\Tasks`
        - each >> saved as an `XML file`
        - check each file's content to see trigger / timing

    - Services:
        - their job >> run background tasks without user interaction.
        - **Malicious actors often tamper with or craft rogue services to ensure persistence**
        - Garde un oeil sur la location: `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services.`
        - Examples:
            - `Windows Update Service` >> installs system updates automatically
            - `Windows Defender Antivirus Service` – Provides real-time protection.
            - `Print Spooler` – Manages print jobs.
            - `DHCP Client` – Gets IP address from DHCP server.
            - `Windows Time` – Syncs system clock.
            - `Remote Desktop Services` – Enables remote desktop connections.
            - `Superfetch (SysMain)` – Speeds up app launching.
            - `Background Intelligent Transfer Service (BITS)` – Transfers files in the background.
            - `Windows Event Log` – Records system, security, and app logs.

- **Web Browser Forensics**
    - `Browser History >> Bookmarsk >> Download History >> Autofill Data >> Search History`

    - `Cookies` >> *Small data files stored by websites on a user's device*
        - contains info: **session details, preferences, and authentication tokens**

    - `Cache` >> Cached copies of web pages, images, and other content
        - *can reveal websites accessed even if the history is cleared.*

    - `Web Storage` >> local storage data used by websites

- **SRUM**
    - System Resource Usage Monitor
    - *Tracks resource utilization and application usage patterns*
    - The database file `sru.db` in `C:\Windows\System32\sru`

    - Key Forensic Artifacts:
        - `Application Profiling` >> all info of executed programs/ apps in system with *executable names, file paths, timestamps*
        - `Resource Consumption` >> for each app >> identifying unusual patterns of resource consumption
        - `Timeline Reconstruction` >> can create timelines of application and process execution
        - `User and System Context` >> user identifiers >> specific user activities >>
        - `Malware Analysis & IR`


# Evidence Acquisition
- Three Key Process:
    - Forensic Imaging
    - Extracting Host-Based Evidence & Rapid Triage
    - Extracting Network Evidence

## Forensic Imaging
- Key Idea
    - bit-by-bit copy of exact data

- Tools:
    - `FTK Imager:` >> imager > view & analyze the content of data without altering
    - `AFF4 Imager` >> can image based on creation time, segment volumes, enabled compression as well
    - `DD, DCFLDD` >> command-line utilities >>
    - `Virtualization Tools` >> evidence can be taken *by temporary halting the system and transferring the directory that houses it*
        - also `snapshot` capability

    - `Arsenal Imager Mounter` >> To mount the obtained images

- Example 1: FTK Imager:
    - With `FTK`, the process is straightforward

- Example 2: Mounting a Disk Image with `Arsenal Image Mounter`:
    - open with admin rights
    - options to open the image: `read-only` or `read-write`
    - `read-only` is go-to option par defaut
    - once mounted, it appears as `D:\`

## Extracting Host-Based Evidence
- Volatile Data
    - Volatile memory >> key thing to obtain
    - `FTK` >> also to capture memory

    - Memory Acquisition Tools:
        - `WinPmem` >> open-source >> par defaut Windows
        - `DumpIt` >> Win & Lin >> in Win concatenates 32-bit & 64-bit memory into a single output file
        - `MemDump` >> capture the contents of RAM >> good in forensics enqueter >> simply & easy to use
        - `Belkafost RAM Capturer` >> Win >> captures even if >> active anti-debugging or anti-dumping protection
        - `LiME (Linux Memory Extractor)` >> evading many common anti-forensic measures >> Loadable Kernel Module >LKM
            - this LKM >> allows the acquisition of volatile memory

    - Example 1: With `WinPmem`:
        - `winpmem_mini_x64_rc2.exe memdump.raw` with admin rights

    - Example 2: Acquiring `VM Memory`:
        - Open the running VM's options
        - Suspend the running VM (*Suspend Guest*)
        - Locate the `.vmem` file inside the `VM's directory.`

- Non-Volatile Data
    - Registry >> Logs
    - System-related artifacts (Prefetch, Amcache)
    - Application-specific Artifacts

## Rapid Triage
- Idea:
    - It's the process of collecting data from `compromised systems`
    - Goal >> take high-value data >> streamlining `indexing & analysis`

- Tool >> `KAPE`:
    - For **rapid artifact parsing and extraction** >> `KAPE`
    - We can use it against the `Live System` or `Mounted Image` or `F-Response` >> as well to retrieve key forensic data
    - Windows-based
    - GUI-version & command-line
    - not open-source >> but its file collection logic encoded in YAML is available `KapeFiles Project` GitHub

    - Components:
        - `Targets` >> defines what to collect (files, folders, registry keys).
            - `specific artifacts` we aim to extract from an image or system
            - Extension `.tkape`
        - **Compount Targets:**
            - amalgamation of multiple targets
            - Example: `KapeTriage` or `!SANS_TRIAGE`
            -
        - `Modules` >> defines how to process what was collected (e.g., run a script, parse logs).
        -
        - **Target gathers → Module processes.**

    - Idea:
        - Choose the `specific Targets`

- Remote Artifact Collection:
    - Case:
        - **You want to perform artifact collection remotely and en masse:**
    - Solution:
        - **EDR** and `Velociraptor` tool

    - EDR >> enables remote acquisition & analysis of evidence: recently executed binaries & added files
            - instead of single network >> it gives full control over the network
            - plus >> you can specify what you want to `gather`

    - Velociraptor >> est l'outil fort pour:
        - Gathering host-based information using `Velociraptor Query Language (VQL)` queries
        - It has `Hunts` to obtain different artifacts
        - **Frequently-used artifact:** >> `Windows.KapeFiles.Targets`
            - Specify the Collection inside its config: `!SANS_TRIAGE`
        - After this, you can download the results
        -
        - **For remote memory dump collection using Velociraptor:**
            - Choose the artifact: `Windows.Memory.Acquisition`

## Extracting Network Evidence
- Process
    - Wireshark & TcpDump
    - IDS/IPS
    - Traffic Flow data >> often sourced from tools like `NetFlow` or `sFlow`
        - they give broader / high-level view of network behaviour not details for each packet
    - Firewalls

## Practical Challenge:
1. Visit the URL "https://127.0.0.1:8889/app/index.html#/search/all" and log in using the credentials:***/***.
    After logging in, click on the circular symbol adjacent to "Client ID".
    Subsequently, select the displayed "Client ID" and click on "Collected".
    Initiate a new collection and gather artifacts labeled as "Windows.KapeFiles.Targets"
    using the _SANS_Triage configuration.
    Lastly, examine the collected artifacts and enter the name of the scheduled task that begins with 'A' and concludes with 'g' as your answer.

    **Solved:**
    - D'abbord, il vous faut choisir le Client ID actif: c'est de couleur verte
    - Apres, il faut suivre sur les instructions
    - J'ai utilise cette commande Powershell: `Get-ScheduledTask | Where-Object{$_.TaskName -like "A*g"}`
    - C'est important que tu dois faire ca dans la machine cible
    - Voila, ca y est, j'ai obtenu le drapeu

# Memory Forensics
- Crucial Data in RAM:

    1. Network connections
    2. File handles and open Files
    3. Open registry keys
    4. Running processes on the system
    5. Loaded modules
    6. Loaded device drivers
    7. Command history and console sessions
    8. Kernel data structures
    9. User and credential information
    10. Malware artifacts
    11. System configuration
    12. Process memory regions

- Systematic Approach:
    - Process Identification and Verification:
        - Identify all active processes
        - Determine their origin within the operating system.
        - Cross-reference with known legitimate processes.
        - Highlight any discrepancies or suspicious naming conventions.

    - Deep Dive into Process Components:
        - Examine DLLs linked to the suspicious process
        - Check for unauthorized or malicious DLLs.
        - Investigate any signs of DLL injection or hijacking.

    - Network Activity Analysis:
        - Review active and passive network connections in the system's memory.
        - Identify and document external IP addresses and associated domains.
        - Determine the nature and purpose of the communication
            - Validate the process' legitimacy
            - Assess if the process typically requires network communication.
            - Trace back to the parent process.
            - Evaluate its behavior and necessity.

    - Code Injection Detection:
        -  process hollowing
        -  utilize unmapped memory sections.
            - Use memory analysis tools to detect anomalies or signs of these techniques.
            - Identify any processes that seem to occupy unusual memory spaces or exhibit unexpected behaviors.

    - Rootkit Discovery:
        - embed deep within the OS
        - Scan for signs of rootkit activity or deep OS alterations.
        - Identify any processes or drivers operating at unusually high privileges
            - or exhibiting stealth behaviors.

    - Extraction of Suspicious Elements:
        - These elements >> processes >> drivers >> executables
            - Dumping the suspicious components from memory.
            - Storing them securely for subsequent examination using specialized forensic tools.

- Key Tool:
    - Volatility Framework
        - based on `Volatility Python script`
        - lots of plugins >> `pslist; cmdline; netscan; malfind; handles; svcscan; dlllist; hivelist`

    - Identify Profile:
        - imageinfo >> `vol.py -f dumped_file.vmem imageinfo`
    - Running Processes:
        - pslist >> `vol.py -f dumped_file.vmem pslist`

    - Network Artifacts:
        - netscan
        - connscan
    - Identify Injected Code >> `malfind` this plugin

    - Identify Handles >>
        - In OS, a process cannot access to resources directly
        - it accesses them through `handles` >> OS controls this
        - With specific process:
            - `vol.py -f Win7-2515534d.vmem --profile=Win7SP1x64 handles -p 1512 --object-type=Key`
            - `vol.py -f Win7-2515534d.vmem --profile=Win7SP1x64 handles -p 1512 --object-type=File`
            - `vol.py -f Win7-2515534d.vmem --profile=Win7SP1x64 handles -p 1512 --object-type=Process`

    - Identify Wind Services:
        - `svcscan`

    - Identify Loaded Dlls and Hivelist:
        - `dlllist`
        - `hivelist`

## Rootkit Analysis with Volatility v2
- Intro:
    - `EPROCESS` >> a  data structure in the Windows kernel that `represents a process`
        - so that each running process has corresponding `EPROCESS` block in kernel memory
        - important to see `parent-child` connections with this in memory

    - `FLINK and BLINK` >>
        - inside `EPROCESS` >> we have **ActiveProcessLinks as the doubly-linked list**
        - then this doubly-linked list has `next pointer & previous pointer` which are
        - `flink and blink` fields
        - `flink` >> points to the `_next_ EPROCESS` in this structure
        - `blink` >> points to the `_previous_ EPROCESS` in the list
        -
        - Example: let's say a process `Powershell.exe` it has `EPROCESS` and this includes `flink &
            blink` >> meaning that we can see the connections tighted

- Identifying Rootkit Signs:
    - `Direct Kernel Object Manipulation (DKOM)` >>  technique used by rootkits
    - It changes the lower kernel level data of the process so that detection devices cannot detect

    - How:
        - If monitor tool depends on `EPROCESS` structure then it could be changed
        - rootkit manipulates the EPROCESS structure directly in kernel memory
        - **altering the EPROCESS structure or unlinking a process from lists,**
        - as a result >> monitoring tool cannot see hidden process in the active list of processes:

    - DKOM Workflow: `First Process > (Hidden Process) >> Next Process`
    - Here the idea is that >> the `flink` of the first process points to the `next process` not `the hidden process`
    - correspondingly, `blink` is  also modified to avoid `hidden process`
    - Voila, how the rootkit achieves this

    - `psscan` >> scans memory pools associated with `EPROCESS` structure so that
    - It can detect hidden processes or unlinked processes >> `rootkits`

## Memory Analysis Using Strings
- Cases:
    - Identify IPv4 Addresses:
        - `strings Win7-2515534d.vmem | grep -E "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b"`

    - Identify Email Addresses:
        - `strings Win7-2515534d.vmem | grep -oE "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,4}\b"`

    - Identifying Command Prompt or PowerShell Artifacts:
        - `strings Win7-2515534d.vmem | grep -E "(cmd|powershell|bash)[^\s]+"`

## Practical Challenge:
1.  Examine the file "/home/htb-student/MemoryDumps/Win7-2515534d.vmem" with Volatility.
    Enter the parent process name for @WanaDecryptor (Pid 1060) as your answer. Answer format: _.exe

    **Solved:**
    - Pour trouver parent-child relationships, j'ai utilise ce plugin `pstree`
    - Ma commande: `vol.py -f Win7-2515534d.vmem --profile=Win7SP1x64 pstree | grep -C 5 '@WanaDecryptor'`
    - Avec `grep`, c'est facile comme ca!
    - Voila, ca y est, j'ai obtenu le drapeau

2. Examine the file "/home/htb-student/MemoryDumps/Win7-2515534d.vmem" with Volatility.
   tasksche.exe (Pid 1792) has multiple file handles open. Enter the name of the suspicious-looking file that ends with
   .WNCRYT as your answer.

   **Solved:**
   - Je connais que je dois utiliser `handles` plugin avec type pour fichier
   - Et voila ma commande pour ca: `vol.py -f Win7-2515534d.vmem --profile=Win7SP1x64 handles -p 1792 --object-type=File | grep -E '*.WNCRYT'`
   - Voila, ca y est >> J'ai obtenu le resultat!

3. Examine the file "/home/htb-student/MemoryDumps/Win7-2515534d.vmem" with Volatility.
   Enter the Pid of the process that loaded zlib1.dll as your answer.

    **Solved:**
    - Pour trouver ca >> tu dois connaitre comment utiliser `dlllist` efficacement
    - D'accord, j'ai analyse le output de `dlllist` par la main
    - Et j'ai compris que ce plugin montre process et ses dlls
    - Voila, ma commande pour ca: `vol.py -f Win7-2515534d.vmem --profile=Win7SP1x64 dlllist | grep -B 35 'zlib1.dll'`
    - Avec `grep` ca marche parfaitement >> `-B` pour montrer les lignes avant cela
    - Voici, ca y est , j'ai trouve le drapeau

# Disk Forensics
- Concept
    - it's the analysis of disk image >> so disk image examination & analysis

- Tool:
    - `Autopsy` >> open-source
        - timeline assessments
        - keyword hunts
        - web & email artifact retrievals
        - recover `deleted files`
- Usage:
    - Open the disk image as new case
    - start the analysis

# Rapid Triage Examination & Analysis Tools
- Idea
    - Now, the necessary image is taken
    - Time to investigate
    - Our Output Data from KAPE

- Tool
    - `Eric Zimmerman` >>  full pack of tools
    - Goal >> is to feel each tool >> to see what it can do

## MAC(b) Times in NTFS
- TimeStamps:
    - MAC(b) >> timestamps of the file / objects
    - `Modified > Accesses > Changed > Birth Times`

    - Rules:
        - Operations: `File Create`, `File Modify`, `File Copy`, `File Access`
        - These are times when MAC(b) info are changed
        - More Detail Like this: Here No when not update >> other letters to show modification
            - `File Create` > M > A > B
            - `File Modify` > M > No > No
            - `File Copy` > No > A > B
            - `File Access` > No > Yes > No

    - All these timestamps >> `$MTF` > `Master File Tree`
    - Inside this `$MFT`, these timestamps are housed in two attributes:
        - `$STANDARD_INFORMATION`
        - `$FILE_NAME`
    - What we see in `Windows File Explorer` Taken from `$STANDARD_INFORMATION` attribute

## TimeStomping Investigation
- Technique Info:
    - `T1070.006` MITRE
    - Goal is to alter timestamps to obfuscate sequence of file activities
    - Tools used for this attack >> `CobaltStrik` , `Empire`

- Enquete:
    - Open the extracted file `$MFT` by the `MFT Explorer` Tool from `Zimmerman` Toolset
    - There you see the `timestamps` info by the attribute `$STANDARD_INFORMATION`
        - Take the `hex digit` value of this for cross-verification
        - Check it with `MFTECmd.exe` from `Zimmerman Toolset`
            - `.\MFTECmd.exe -f 'C:\kape_output\D\$MFT' --de 0x16169`
            - Here if you check the attribute `$FILE_NAME` >> it shows the **different timestamps** which is original one
            - Why it is not reflected >> since to change `$FILE_NAME`, regular users lack permissions

## MFT File
- Key Info:
    - Master File Tree >> responsible for *organizing & cataloging files/directories* on NTFS volume
    - Granular record of file info
    - **Even Metadata of Deleted Files is saved in MFT**
        - Records for `deleted files` are flagged as  `free` and ready for reuse
    - Tool: `MFT Explorer` by `Zimmerman Toolset`

- MFT Structure
    Such Layers:
    ```code
    1. File Record Header
    2. Attribute $10 > $STANDARD_INFORMATION
    3. Attribute $30 > $FILE_NAME
    4. Attribute $80 > $DATA (File Data Resident or Non-Resident)
    5. Additional Attributes

    Overal Size is 1024 bytes info
    ```

    Definition of Each Attribute:
        1. `File Record Header` >> contains info: signature, sequence number,
        2. `$STANDARD_INFORMATION` >> timestamps, security identifiers, file attributes
        3. `$FILE_NAME` >> length, namespace, and Unicode characters.
        4. `$DATA` >> Resident > when stored within the MFT record
                 >> Non-Resident > when stored in external clusters ( on disk)

    Case:
        - We can use `ID` of each record attribute for further enquete with `MFTECmd.exe`
            - `.\MFTECmd.exe -f 'C:\Users\johndoe\Desktop\forensic_data\kape_output\D\$MFT' --de 27142`
            - `27142` >> ID of `File Recorder Header` attribute

    Case:
        - We can investigate `$MFT` raw data using the tool `Active@ Disk Editor` GitHub
        - It shows entries of $MFT with Hex Values
        - We can see `Non-Resident` & `Resident` Flags info
        - Plus it is visible by `MFTECmd.exe` as well

- Zone.Identifier
    - Location:
        - Zone Identifier is a stream and is part of ADS
        - ADS (Alternate Data Streams) are part of NTFS file system
        - NTFS stores each stream (including ADS) as attributes in the file’s MFT entry

    - Features:
        - file metadata attribute
        - part of  Windows Attachment Execution Service (AES)
        - shows from where a file was sourced
        - from the internet or other potentially untrusted origins.

    - Case:
        - When a file is fetched from the internet, Windows assigns `ZoneId`
        - `ZoneId = 3` tells it's from Internet
        -
        - To see: `Get-Item * -Stream Zone.Identifier -ErrorAction SilentlyContinue`
        - To see the content of Zone Identifier >> `Get-Content * -Stream Zone.Identifier -ErrorAction SilentlyContinue`

    - Additional:
        - `Mark of the Web (MotW)` >> security mechanisms
        - if a file has `MotW` presence, then this file is carefully treated
        - By using this `MotW` >> forensics people can identify the download method of the file

- Extracting ZoneId Info:
    - First need to get parsed `$MFT` into `CSV`format using `MFTECmd.exe`
        - `.\MFTECmd.exe -f 'C:\Users\kape_output\D\$MFT' --csv C:\file_path_to\ --csvf file_name.csv`
    - Then, Ingest parsed `CSV` info to `Timeline Explorer`
    - Voila, bonne analyse


## Timeline Explorer
- Tool:
    - `Timeline Explorer` Tool by `Zimmerman Toolset`
    - provide a chronological view of system events and activities
    - Need to usually `convert data into CSV then feed it into` **Timeline Explorer**

## USN Journal
- Info:
    - Update Sequence Number (USN) >> key part of NTFS
    - Change Journal to record any modifications to files/dirs
    - Location: `$J` >> System Folder or File

- Analyzing the USN Journal Using MFTECmd:
    - Tool: `MFTECmd.exe` by `Zimmerman Toolset`
        - Tool's primary goal is MFT but okay for USN as well

    - Process:
        1. Need to parse `$J` into CSV format using `MFTECmd.exe`
            - `.\MFTECmd.exe -f 'C:\Users\D\$Extend\$J' --csv C:\file_to_save_dir\ --csvf name_of_file.csv`
            - `--csv` >> to set the location for the output file
            - `--csvf` >> to set the name of the file
        2. Put this `CSV` formatted file into `Timeline Explorer`

## Windows Event Logs Parsing Using EvtxECmd
- Tool:
    - `EvtxECmd` is by `Zimmerman Toolset` to parse `.evtx` Windows log files into ` JSON, XML, or CSV.`
    - `.\EvtxECmd.exe --sync` >> to update EvtxECmd for maps
    - **Maps of EvtxECmd** >> *maps help normalize and simplify the output.*
        - They are `templates/rules` that tell the tool:
            - Which EventIDs to extract
            - Which fields to parse
            - How to format the output

- Command:
    - `.\EvtxECmd.exe -f "C:\Microsoft-Windows-Sysmon%4Operational.evtx" --csv "C:\file_pathe" --csvf file_name.csv`

    - Put the CSV file into `Timeline Explorer`

## Investigating Windows Event Logs with EQL
- Tool:
    - `Endgame's Event Query Language (EQL)`
    - query language to extract info

- Process:
    - `pip install eql`
    - There are Powershell essential functions tailored for parsing Sysmon events from Windows Event Logs
        - `import-module .\scrape-events.ps1`

    - Need to parse first into `JSON` using the function `Get-EventProps`
    - `Get-WinEvent -Path C:\Sysmon.evtx -Oldest | Get-EventProps | ConvertTo-Json | Out-File -Encoding ASCII -FilePath C:\kape.json`
    - Now, this `JSON` file is ready for EQL Queries
    - `eql query -f C:\kape.json "EventId=1 and (Image='*net.exe' and (wildcard(CommandLine, '* user*', '*localgroup *', '*group *')))" | jq`
    - `jq` for better formatting

## Windows Registry
- Locations:
    - `<KAPE_output_folder>\Windows\System32\config`
    - `users's profile >> NTUSER.DAT`
    - `UsrClass.dat`

- Tools:
    - `RegistryExplorer` is by `Zimmerman Toolset`
    - Example: Load `SYSTEM` or `SOFTWARE` hives into the tool `RegistryExplorer` GUI
        - Capabilities:
            - hive analysis
            - search capabilities
            - filtering options
            - timestamp viewing
            - bookmarking

    - `RegRipper` >> command-line, to extract from Registry
        - `.\rip.exe -h`
        - It has key plugins -> `.\rip.exe -l -c > rip_plugins.csv`
            - You see the list of plugins >> leur descriptions
        - These each plugin has assigned location in Registry >> and they execute against the specified locations
        -
        - Example: *let's execute the compname command on the SYSTEM hive*
            - `.\rip.exe -r "C:\kape_output\D\Windows\System32\config\SYSTEM" -p compname`
                - this command `compname` >> takes ComputerName & Hostnames from System hive
            - Timezone >> `.\rip.exe -r "C:\kape_output\D\Windows\System32\config\SYSTEM" -p timezone`
            - Network Info >> `.\rip.exe -r "C:\kape_output\D\Windows\System32\config\SYSTEM" -p nic2` or `ips`
            - Installer Execution >> `.\rip.exe -r "C:\kape_output\D\Windows\System32\config\SYSTEM" -p installer`
            - Recently Accessed Folders/Docs >> `.\rip.exe -r "C:\kape_output\D\Windows\System32\config\SYSTEM" -p recentdocs`
            - Autostart - Run Key Entries >> `.\rip.exe -r "C:\kape_output\D\Windows\System32\config\SYSTEM" -p run`
                - shows how many keys are at the `RUN` locations >> wow

## Program Execution Artifacts
- Idea:
    - execution artifacts >> traces left by run programs/apps

- Well-Know Execution Artifacts:
    - `Prefetch`
    - `Shimcache`
    - `Amcache`
    - `BAM >> Background Activity Moderator`

- Investigation of Prefetch:

    - Prefetch >> feature to load metadata of each executing/installed programs
    - extension: `.pf` >> the name of executable and its Hex value >> `DISCORD.EXE-7191FAD6.pf`

    - Tool: `PECmd` is by `Zimmerman Toolset` for Prefetch Investigation
        - `.\PECmd.exe -h`
        -
        - `.\PECmd.exe -f C:\kape_output\D\Windows\prefetch\DISCORD.EXE-7191FAD6.pf`

    - What Info it shows:
        - first & last execution timestamps
        - how many times the app is executed
        - app name  / its path
        - size / hash values
        - directories / files referenced >> voila, ca y est

    - **Keep an eye on Suspicious Locations: for referenced files**

    - Convert Fetch Files to CSV
        - `.\PECmd.exe -d C:\kape_output\D\Windows\prefetch --csv C:\where_to_save_directory`
        - This creates `csv` files inside this directory:
        - Feed these `csv` files into `Timeline Explorer`

- Investigation of Shimcache:

    - `Shimcache` also known as `AppCompatCache` >> (Application Compatibility Cache)
        - identify application compatibility issues
        - this database is in Registry
        - **records information about executed applications**

    - What helpful for Forensics:
        - `Full file paths` >> `Timestamps` >> `Last modified time`, `last uptaded time`

    - **AppCompatCache Location**:
        - `HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\ControlSet001\Control\Session Manager\AppCompatCache`

    - Process:
        - Load `SYSTEM` hive into `RegistryExplorer`
        - Then go to `bookmarks` and select `AppCompatCache` and see `application execution`

- Investigation of Amcache:

    - registry file >> store evidence related to program execution
    - it has info for each executed program: *deleted_time, first_installation, execution_path*

    - Process & Tools:
        - Load directly: `Amcache.hve` into `RegistryExplorer` tool
        - Also, use `AmcacheParser` tool by `Zimmerman Toolset` to convert to `CSV` then play it in `Terminal Explorer`
            - `.\AmcacheParser.exe -f "C:\kape_output\D\Windows\AppCompat\Programs\AmCache.hve" --csv C:\amcache-analysis`

- Investigation of BAM:

    - Background Activity Monitor >> *tracks and logs the execution of certain types of background or scheduled tasks*
    - Main job >> *responsible for controlling the activity of background applications*
    - We can see program execution in its BAM hive: its key:
        - `HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\bam\State\UserSettings\{USER-SID}`

    - Tool:
        - Use `RegistryExplorer` >> locate to `SYSTEM` hive >> `bam` dir
        - Also use `RegRipper` with `bam` plugin

## Analyzing Captured API Call Data (.apmx64)
- Key Idea:
    - **.apmx64 files are generated by API Monitor, which records API call data.**
    - *API Monitor is a software that captures and displays API calls*
    - primary function is debugging and monitoring

- Process:
    - Load: `\APMX64\discord.apmx64`  into `API Monitor` tool
    - **Clicking on the monitored processes to the left will display the recorded API call data**

## Registry Persistence via Run Keys

- In API Monitor tool, open `discord.apmx64` >> look for these functions to know any suspicious `run keys` are asked:
    - `RegOpenKeyExA` function
    - registry API function `RegSetValueExA.`
    - Learn each API functions args also pour comprendre tout
        - **A critical takeaway from this API call is the lpData parameter:**

## Process Injection:
- In API Monitor tool, after loading API calls of the certain program or executable

    - To find the process injection cases:
        - Search for `CreateProcessA` function instances
        - Learn the structure of **syntax of the Windows API function, CreateProcessA.**
        - Other functions to show: `OpenProcess`, `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`

    - Idea: `CreateProcessA`'s arg >> `dwCreationFlags` this flag set to `CREATE_SUSPENDED`
        - To win sometime and meantime the parent process injects malicious code then
        - Presses the button through the function `ResumeThread`

## Review PowerShell Activity
- Key Things:
    - `Unusual Commands`
    - `Script Execution`
    - `Privilege Escalation`
    - `Registry Manipulation`
    - `Use of Uncommon Modules`
    - `Scheduled Tasks`
    - `Repeated or Unusual Patterns`
    - `Execution of Unsigned Scripts`

## Practical Challenge
1. During our examination of the USN Journal within Timeline Explorer, we observed "uninstall.exe".
   The attacker subsequently renamed this file. Use Zone.Identifier information to determine its new name and enter it as your answer.

    **Solved:**
    - Pour trouver la reponse, j'ai utilise ce methode:
    - Avant, j'ai fait parse de $MFT au CSV format par `MFTECmd.exe`
        - D'abbord, j'ai utilise l'outil `MFTECmd.exe` pour converter $MFT au CSV fichier
        - Apres, J'ai mis le fichier dans le `Timeline Explorer`
        - J'ai compris que, l'information de `ZoneId` n'est pas modifie meme le nom est modifie
        - J'ai cherche `uninstall.exe` et apres J'ai analyse chaque resultat
        - Surtout, j'ai cherche la partie de `ZoneId` et voila, j'ai trouve que
        - ZoneId est la meme mais le nom du programme est different
        - D'eilleur, j'ai vu que `uninstall.exe` est le viex nom et le nouvel nom est enregistre: `08:30:06`
    - Voila, ca y est; j'ai  obtenu le drapeau

2. Review the file at "C:\Microsoft-Windows-Sysmon%4Operational.evtx" using Timeline Explorer.
   It documents the creation of two scheduled tasks. Enter the name of the scheduled task that begins
   with "M" and concludes with "r" as your answer.

   **Solved:**
   - J'ai utilise l'outil: `EvtxECmd.exe` pour faire parse du format .evtx au CSV
   - Apres, j'ai cherche le mot "sch" dans le `Timeline Explorer`
   - J'ai trouve deux resultats et le deuxime m'a donne le drapeau
   - Plus precisement, `TN` Task Name est ce que tu dois regarder
   - Voila, ca y est, j'ai fini!

3. Examine the contents of the file located at "C:\discord.apmx64" using API Monitor.
   "discord.exe" performed process injection against another process as well.
    Identify its name and enter it as your answer.

    **Solved:**
    - Pour ca, j'ai utilise l'outil `API Monitor x64`
    - D'abbord, j'ai compris que je dois chercher l'information avec `CreateProcessA`
    - Donc, j'ai utilise `Find` option et j'ai cherche `CreateProcess`
    - Pour la promiere fois, j'ai trouve `comp.exe` dont je le savais deja
    - Pour la deuxime, j'ai trouve `cmd***.exe` aussi
    - Voila, ca y est, c'est fini!


# Practical Digital Forensics Scenario
- Allez-y

## Memory Analysis with Volatility v3

- We got dumped memory file >> `PhysicalMemory.raw`

- Identifying the Memory Dump's Profile:
    - `windows.info` plugin
    - `python vol.py -q -f ..\memdump\PhysicalMemory.raw windows.info`

- Identifying Injected Code:
    - Using plugin `malfind`
    - `python vol.py -q -f ..\memdump\PhysicalMemory.raw windows.malfind`
    -
    - **Key Point:**
        - this plugin shows memory parts >> injected code also
        - if you see `PAGE_EXECUTE_READWRITE` for the given process >> **ability to both execute and write to that memory region**
        - It's **Red Flag** >> since usually processes need `READ` also code execution happens in
            different part of the memory `execution`

- Identifying Running Processes:
    - `windows.pslist` plugin or `windows.pstree` for Tree View with parent-child relationships
    - `python vol.py -q -f ..\memdump\PhysicalMemory.raw windows.pslist`

- Identifying Process Command Lines:
    - `windows.cmdline` plugin
    - `python vol.py -q -f ..\memdump\PhysicalMemory.raw windows.cmdline`

- Dumping Process Memory & Leveraging YARA:
    - if the certain process is suspicious, possible to extract its own data
    - `windows.memmap` >> plugin
    - `python vol.py -q -f ..\memdump\PhysicalMemory.raw windows.memmap --pid 3648 --dump`
    -
    - Running YARA Rules using Powershell:
        ```code
            - $rules = Get-ChildItem C:\Users\johndoe\Desktop\yara-4.3.2-2150-win64\rules | Select-Object -Property Name
            - foreach ($rule in $rules) {C:\yara-4.3.2-2150-win64\yara64.exe
              C:\yara-4.3.2-2150-win64\rules\$($rule.Name) C:\Users\johndoe\Desktop\pid.3648.dmp}
        ```

- Identifying Loaded DLLs:
    - `windows.dlllist` can be specified for the specific process
    - `python vol.py -q -f ..\memdump\PhysicalMemory.raw windows.dlllist --pid 3648`

- Identifying Handles:
    - `windows.handles -p 3933`

- Identifying Network Artifacts:
    - `windows.netstat` or `windows.netscan` (comprehensive)
    - `python vol.py -q -f ..\memdump\PhysicalMemory.raw windows.netstat`

## Disk Image/Rapid Triage Data Examination & Analysis

- Search for Keywords
    - Run `Autopsy`
    - Search the suspicious info >> `Extract files`
    - For example, we need `payload.dll` to extract this for further investigation we use `Autopsy`
    - `Extract Files` >> `right-click`

- Identifying Web Download Information & Extracting Files with Autopsy:
    - we use `ADS` Alternate Data Streams >> `.Zone.Identifier information` which show **file's internet origin**

- Extracting Cobalt Strike Beacon Configuration
    - Steps:
        - We know that CobaltStrike C2 config is used
        - To identify this: we use `CobaltStrikeParser script` GitHub Repo
            - `python parse_beacon_config.py E:\payload.dll`
            - It parses & shows >> **C2 servers Sleep time User agent Keys, pipes, etc.**

- Identifying Persistence with Autoruns:

    - Tool: `Autoruns`
        - Open the `johndoe_autoruns.arn` file
        - By default, it shows some useful info: inconsistencies
        - Look at some suspicious programs >> take the hash of them >> check them with `VirusTotal`

    - `Scheduled Tasks` tab of the `Autoruns` tool
        - Look for the Registry Keys >> some programs at auto runs

- Analyzing MFT Data with Autopsy:
    - Sometimes, program timestamps are modified >> check them with `MFT` info

- Analyzing SRUM Data with Autopsy:
    - Well, we found earlier >> *malicious executable had an open handle directed at the Desktop folder*
        - Inside the `Desktop` folder >> we see the file `users.db`
        - probably, the attacker wanted to take info from the system
    - To verify this:
        - Go to `Data Arifacts` >> `Run Programs` >> `SRUDB.dat.`
        - You see that `430526981 bytes` may **have been exfiltrated.**

- Analyzing Rapid Triage Data - Windows Event Logs (Chainsaw):
    - Why Chainsaw:?
        - Goal is to use `Sigma Rules` by community for log events
        - Massive analysis to find any alerts

    - Run this command:
        - `chainsaw_msvc.exe hunt "..\winevt\Logs" -s sigma/ --mapping mappings/sigma-event-logs-all.yml -r rules/ --csv --output output_csv`

    - We got multiple `CSV` files in the directory `output_csv`

    - `account_tampering.csv` >> shows that new `Admin` was created
        - **We can also identify new user creation through Autopsy as follows.**
        - `OS Accounts`

- Analyzing Rapid Triage Data - Prefetch Files (PECmd):
    - we are into system's execution history
    - `PECmd.exe -d "C:\kapefiles\\Windows\Prefetch" -q --csv C:\Users\johndoe\Desktop --csvf suspect_prefetch.csv`

- Analyzing Rapid Triage Data - USN Journal (usn.py):
     - Goal >> **we can identify all files that were either created or deleted during the incident.**

     -  Command: We will utilise `USN Parser script`
     ```code
     python C:\files\USN-Journal-Parser-master\usnparser\usn.py -f C:\Users\johndoe\$UsnJrnl%3A$J -o C:\Users\johndoe\Desktop\usn_output.csv -c
    ```

-  **Suspicious activities took place approximately between 2023-08-10 09:00:00 and 2023-08-10 0:00:00.**
    - **To view the CSV using PowerShell in alignment with our timeline:**
    ```code
        $time1 = [DateTime]::ParseExact("2023-08-10 09:00:00.000000", "yyyy-MM-dd HH:mm:ss.ffffff", $null)
        $time2 = [DateTime]::ParseExact("2023-08-10 10:00:00.000000", "yyyy-MM-dd HH:mm:ss.ffffff", $null)

        Import-Csv -Path C:\Users\johndoe\Desktop\usn_output.csv |
        Where-Object { $_.'FileName' -match '\.exe$|\.txt$|\.msi$|\.bat$|\.ps1$|\.iso$|\.lnk$' } |
        Where-Object { $_.timestamp -as [DateTime] -ge $time1 -and $_.timestamp -as [DateTime] -lt $time2 }
    ```
    - Analyse The Output >> look for deleted or created files

    - We found the `flag.txt` was deleted

- Analyzing Rapid Triage Data - MFT/pagefile.sys (MFTECmd/Autopsy):
    - Now goal is to see how `flag.txt ` was and what info it had:

    - We need `MFT` table
        - **running MFTEcmd to parse the $MFT file, followed by searching for flag.txt**
        - Convert to CSV:
            - `MFTECmd.exe -f C:\files\mft_data --csv C:\Users\johndoe\Desktop\ --csvf mft_csv.csv`
        - Then use Powershell to investiage CSV for `flag.txt`:
            - `Select-String -Path  C:\Users\johndoe\Desktop\mft_csv.csv -Pattern "flag.txt"`
        - Based on the info: we found the location: ` (\Users\johndoe\Desktop\reports).`
        -
        - Go To `mft` file with `MFT Explorer` tool
        - Locate to the location: ` (\Users\johndoe\Desktop\reports).`
        - Here you see that `flat.txt` is marked with `Is_deleted`
            - **Key Point Here:**
                - When files from NTFS system volume, are deleted >> their MFT entries are marked as free & may be reused
                - But, until it is overwritten, **the data is saved on the disk**
                - Even, it's overwritten:
                    - **portions of its content were preserved** in `pagefile.sys`
                    - this file `pagefile.sys` >> supplements RAM >>
                        - When RAM is full >> it puts some info in `pagefile`
                - Then, with this partial content, possible to investigate the disk
                - and *retrieve the flag from pagefile.sys* with `Autopsy`

- Constructing an Execution Timeline:
    - possible to **map out the attacker's actions chronologically.** by `Autopsy`
    - Go to `Timeline` Tab
        - Limit event types to:
            - Web Activity: All
            - Other: All
        - Set Display Times in: GMT / UTC
            - Start: Aug 10, 2023 9:13:00 AM
            - End: Aug 10, 2023 9:30:00 AM
    - This shows us **detailing the actions undertaken by the malicious actor.**

## Practical Challenge:
1. Extract and scrutinize the memory content of the suspicious PowerShell process which corresponds to PID 6744.
   Determine which tool from the PowerSploit repository (accessible at https://github.com/PowerShellMafia/PowerSploit)
   has been utilized within the process, and enter its name as your answer.

   **Solved:**
    - Pour identifier ce process, j'ai utilise cette commande: `python vol.py -f file.raw windows.pslist | Select-String 6744`
    - J'ai trouve que le process est `conhost.exe`
    - Apres, j'ai ete besoin de ses commandes: donc je dois utiliser le plugin `cmdline` pour `6744`
        - `python vol.py -f file.raw windows.cmdline --pid 6744`
    - Voila, j'ai trouve une commande tres mefiant de Powershell:
    - Le `shellcode` est fait obfuscated avec `base64` mais les contents aussi sont fait obfuscated
    - J'ai analyse le logic de code et J'ai compris que l'outil est `P********`
    - Et voila, ca y est, c'est fini!

2.  Investigate the USN Journal located at "C:\$Extend\$UsnJrnl%3A$J" to determine how "advanced_ip_scanner.exe" was introduced
    to the compromised system. Enter the name of the associated process as your answer.

    **Solved:**
    - D'abbord, je dois faire conversion pour CSV:
        - `python .\usn.py -f 'C:\Users\$Extend\$UsnJrnl%3A$J' -o C:\Users\johndoe\Desktop\usn_output.csv -c`
    - Apres, j'ai utiliser `Timeline Explorer` avec CVS fichier
    - J'ai cherche `advanced_ip_scanner.exe` >> J'ai trouve le temps que `09:20:04` executed d'emplacement `advanced.zip` a `09:20:26`
    ```code
        6744    chrome.exe      2023-08-10 09:11:41.000000
        7512    rundll32.exe    2023-08-10 09:15:14.000000
        632     powershell.exe  2023-08-10 09:21:16.000000

    - Apres, j'ai essaye avec les quelques options: La reponse est parmi tous les trois options;
    - Ca y est! Voila



