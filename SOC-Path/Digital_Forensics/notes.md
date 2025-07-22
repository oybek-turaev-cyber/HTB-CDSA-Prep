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














