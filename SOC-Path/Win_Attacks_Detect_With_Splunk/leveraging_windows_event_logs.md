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

# Detecting Password Spraying Attack
- Scenario:
    - certain number of passwords to many accounts
    - to avoid account locks

    - Tool: `Spray` in Kali

- Detection Techniques:
    - Primarily >> `EventID 4625` >>
    - Others:
    ```code
        4768 and ErrorCode 0x6 - Kerberos Invalid Users
        4768 and ErrorCode 0x12 - Kerberos Disabled Users

        4776 and ErrorCode 0xC000006A - NTLM Invalid Users
        4776 and ErrorCode 0xC0000064 - NTLM Wrong Password

        4648 - Authenticate Using Explicit Credentials

        4771 - Kerberos Pre-Authentication Failed
    ```

- Detection with Splunk:
    - Command:
        ```code
            index=main earliest=1690280680 latest=1690289489 source="WinEventLog:Security"
            | bin span=15m _time
            | stats values(user) as users, dc(user) as dc_count by src, Source_Network_Address, dest, EventCode, Failure_Reason
        ```

    - It is working within time limit
    - `bin span=15m _time` >> it's grouping events within 15m time buckets >> kinda putting alerts
        happened 15 mins intervals >> groups by this feature
    - Then `stats` creates specific `groups or combinations`  based on source, source IP address, destination and
        eventcode and failure message.
    - For each this combination >> it calculates unique values of `user` field by function `values()` and
        - `dc()` function counts the unique number of `user` field for `each group or combination`

- Practical Challenge:
    1. Employ the Splunk search provided at the end of this section on all ingested data (All time) and
       enter the targeted user on SQLSERVER.corp.local as your answer.

    **Solved:**
    - J'ai utilise cette commande au-dessus et j'ai debarasse les restrictions de temps
    - J'ai obtenu le drapeau et Voila, ca y est, c'est fini!

# Detecting Responder-like Attacks
- LLMNR / NBT-NS / mDNS Poisoning:
    - `LLMNR` >> Link-Local Multicast Name Resolution: `UDP 5335`
    - `NBT-NS` >> NetBIOS Name Service: `UDP 137`

    - Usage:
        - Used to resolve hostnames to IPs on local networks when FQDN(DNS) fails
        - They have some inefficiencies >> so that attackers use them

    - Tool:
        - `Responder` >> **To execute LLMNR, NBT-NS, or mDNS poisoning.**

    - Scenario:
        - **They will be used when the Main DNS fails ? Then when DNS fails? When it could not find
            the requested hostname then LLMNR / NBT-NS / mDNS come to action**
        - Steps:
            - Victim send mistyped hostname `filesharea` query to DNS
            - DNS cannot resolve this >> then one of the 3 brothers come to solve: `LLMNR / NBT-NS / mDNS`
            - The attacker responds to `LLMNR / NBT-NS / mDNS` requests >> pretending to be the server of this mistyped host
            - The system is now poisoned communicating with adversary-controlled system

    - Attack Goal:
        - To obtain `NetNTLM Hashes` or  NTLM-based credentials

- Responder Detection Opportunities:
    - Two Methods:
        - Employ net monitor solutions for **unusual LLMNR and NBT-NS traffic patterns** >>
           such as *an elevated volume of name resolution requests from a single source.*
        -
        - **HoneyPot** >> Normally, requests for non-existant hosts / file shares should fail!
            - If the attacker is present in the env for `LLMNR / NBT-NS ` spoofing >>
            - The attacker is ready to accept any requests from those protocols
            - Now, as a defender >> we list non-existant hosts / file shares and run them in every host in the network
            - The expected response should fail, If not, if it succeeds >> then it's a **red flag** for us about the attacker
            - Refer to the `./LLMNR_detecter.ps1` for the Powershell Script

- Detecting Responder-like Attacks With Splunk:
    - Methods:
        1. `Sysmon ID-22` >> shows *DNS queries* to **non-existent or mistyped file shares**
            ```code
                    index=main earliest=1690290078 latest=1690291207 EventCode=22
                    | table _time, Computer, user, Image, QueryName, QueryResults
            ```
        2. `EventID 4648` >> **logs events when credentials are explicitly used to access network resources**
            - Yes, the logs can be for legit servers/resources
            - Also for **suspicious or strange/fake file shares /resources by the attacker** also
            - Our Goal is to find the suspicious cases of when credentials are explicitly used (NTLM credentials for example)
            ```code
                    index=main earliest=1690290814 latest=1690291207 EventCode IN (4648)
                    | table _time, EventCode, source, name, user, Target_Server_Name, Message
                    | sort 0 _time
            ```
                - `EventCode=4648  equal to  EventCode IN (4648)`
                - However, `IN (...)` is used for multiple options, usually not single

- Practical Challenges:
    1. Modify and employ the provided Sysmon Event 22-based Splunk search on all ingested data (All time)
    to identify all share names whose location was spoofed by 10.10.0.221.
    Enter the missing share name from the following list as your answer. myshare, myfileshar3, _

    **Solved:**
    - J'ai utilise cette commande:
        ```code
            index=main earliest=169029078 latest=1690291207 EventCode=22
            | table _time, Image, User, QueryName, QueryResults
            | where like(QueryResults, "%10.10.0.221%")
        ```
    - La partie de ce code: `where like(...)` est tres utile pour trouver tous les trois resultats
    - Voila, ca y est, c'est fini!

# Detecting Kerberoasting / AS-REProasting
- Kerberoasting:
    - Technique >> targets `service accounts`
    - Ultimate Goal >> to obtain password'hashes of the `service accounts`
        - Brute Force Password & Later obtain full control of `service accounts` for LM

    - Why Attack is Possible?
        - How Kerberos controls these process: `authentication`, `ticket distribution`?
        - Well, there is `SPN` > (Service Principal  Names) >> shortcut for specific service: SQL, HTTP, LDAP servers
        - **These SPN are database or kinda map for the Kerberos to know what service account runs what service**
        - There is a list of available SPN data >> you send the specific SPN to Kerberos for the service you want to access >>
        - Then based on SPN, Kerberos finds out who is `service account` for this service
        - **The issue is that** Anyone joined in Domain Network can ask SPN data and request SPN info from Kerberos

    - Service Access Process with Kerberos:
        - User finishes identification process to get `TGT` (usually that's given when logged in domain-joined device)
        - User sends `AS-REQ` and it gets `AS-REP`
        - So, logged in means that you have `TGT`
        - Then to access the certain service, you need `TGS`, well to ask that you need `TGT` which you got at log in
        - You identify what service you want to ask by knowing `SPN` info
        - Then send this `TGS-REQ` to Kerberos >> Here Kerberos responds with `TGS-REP`
        - Here, **Vulnerable Part** >> Kerberos includes the `hash of service account password` into `TGS`
        - Then, normal user continues to access to Service with this `TGS` >> log-on by the user is expected as a normal case
        - But, the attacker stops after it gets `TGS` ticket from Kerberos: Why?
            - Because, `TGS` has `hash` which is possible to crack using `hashcat, john` >> password of service account

    - Kerberoasting Steps:
        - Find SPNs >> Query AD via LDAP for accounts with SPNs (usually service accounts).
        - Request TGS Tickets Use tools to get service tickets (TGS) for those SPNs.
        - Extract Tickets >> Dump the TGS from memory (e.g., with Rubeus or mimikatz).
        - Crack Tickets Offline >> Use tools like Hashcat or John to brute-force the service account password from the ticket.

    - What Log Events are generated?
        - `Event ID 4768` >> Kerberos TGT Request
        - `Event ID 4769` >> Kerberos Service Ticket Request, TGS >>
            - *Generated after the client receives the TGT and requests a TGS for the MSSQL server's SPN.*
        - `4624` >> *Logged in the Security log on the MSSQL server, indicating a successful logo*

    - Detection:
        - Garde un oeil sur les `LDAP` activities to detect SPN queries
        - **Focuses on the difference between benign service access and a Kerberoasting attack.**
            - normal user continues the process with service provider to log in
            - attacker stops after `TGS` >> mefiant!
        - **Find `TGS` requests without subsequent logon event**
        - Also >> keep track of `4648` >> `explicit use of credentials`

## Detecting Kerberoasting With Splunk
- Benign TGS Requests:
    - Command:
    ```code
        index=main earliest=1690388417 latest=1690388630 EventCode=4648 OR (EventCode=4769 AND service_name=iis_svc)
        | dedup RecordNumber
        | rex field=user "(?<username>[^@]+)"
        | table _time, ComputerName, EventCode, name, username, Account_Name, Account_Domain, src_ip, service_name,
          Ticket_Options, Ticket_Encryption_Type, Target_Server_Name, Additional_Information
    ```
    - `dedup` removes duplicates based on field `RecordNumber`
    - `rex` regex extracts info from `user` field with the new field name `username`

- Detecting Kerberoasting - SPN Querying:
    - Command:
    ```code
        index=main earliest=1690448444 latest=1690454437 source="WinEventLog:SilkService-Log"
        | spath input=Message
        | rename XmlEventData.* as *
        | table _time, ComputerName, ProcessName, DistinguishedName, SearchFilter
        | search SearchFilter="*(&(samAccountType=805306368)(servicePrincipalName=*)*"
    ```
    - Here I am extracting data from `Message` field >> it has JSON/XML based data
    - first with `spath` I take its input
    - then all fields inside `Message` will be with prefix`XmlEventData.SearchFilter` ...
    - To remove this prefix I use `rename XmlEventData.* as *` >> it removes prefix from all fields  inside `Message`
    - then I use `search` for the each field such as `SearchFilter`
    - Goal here whether any request with SPN info

- Detecting Kerberoasting - TGS Requests:
    - Command:
        ```code
            index=main earliest=1690450374 latest=1690450483 EventCode=4648 OR (EventCode=4769 AND service_name=iis_svc)
            | dedup RecordNumber
            | rex field=user "(?<username>[^@]+)"
            | bin span=2m _time
            | search username!=*$
            | stats values(EventCode) as Events, values(service_name) as service_name, values(Additional_Information)
              as Additional_Information, values(Target_Server_Name) as Target_Server_Name by _time, username
            | where !match(Events,"4648")
        ```
        - `bin span=2m _time` >> groups events into 2-minute intervals based on the `_time`
        - `| where !match(Events,"4648"):` >> Filters out events that have the value `4648` in the `Events` field.

- Detecting Kerberoasting Using Transactions - TGS Requests:
    - Command:
    ```code
        index=main earliest=1690450374 latest=1690450483 EventCode=4648 OR (EventCode=4769 AND service_name=iis_svc)
        | dedup RecordNumber
        | rex field=user "(?<username>[^@]+)"
        | search username!=*$
        | transaction username keepevicted=true maxspan=5s endswith=(EventCode=4648) startswith=(EventCode=4769)
        | where closed_txn=0 AND EventCode = 4769
        | table _time, EventCode, service_name, username
    ```
    - uses `transaction` command >> why since after TGS, should happen `explicit use of credentials`
    - `transaction username keepevicted=true maxspan=5s endswith=(EventCode=4648) startswith=(EventCode=4769)`
        - Groups events into `transactions` based on `username` field
        - `keepevicted=true` >> includes events that do not meet the transaction criteria
        - `maxspan=5s` >> sets the max transaction time to 5 seconds
        - `endswith=(EventCode=4648)` and `startswith=(EventCode=4769)` specify that events should happen in this order
        - `where closed_txn=0 AND EventCode = 4769` >> *include transactions that are not closed (closed_txn=0) and have an EventCode of 4769.*

## AS-REPRoasting
- Technique:
    - target user accounts which are with `without pre-authentication enabled` or `unconstrained delegation`
    - so that no authentication needed to access
    - usually *pre-authentication is a security feature requiring users to prove their identity before the TGT is issued.*

- Attack Steps:
    - Identify Target User Accounts: `Ruebus`
    - Request `AS-REQ` Service Tickets:
    - Offline Brute-Force Attack: >> *The attacker captures the encrypted TGTs and employs offline brute-force techniques*

- Kerberos Authentication Vulnerabilities:
    - usually, When a user tries to `access a network resource` or `service`, the client sends an authentication request `AS-REQ` to the KDC.
    - if `pre-authentication` is enabled it includes: `pA-ENC-TIMESTAMP` >> possible to see in `Wireshark` Under Kerberos
        - **The KDC attempts to decrypt this timestamp using the user password hash and, if successful, issues a TGT to the user.**
    -
    - When `pre-authentication` is disabled >> then no `timestamp` to decrypt by KDC >> it just issues `TGT` without knowing the user password.
    - It means that attacker >> without being asked the password >> can get a chance to access the hash of this user's password

- AS-REPRoasting Detection Opportunities:
    - Attacker uses LDAP queries to find out user accounts with `no-pre-authentication enabled` or `unconstrained delegation`
    - So, `4768` >> TGT Request contains >> `PreAuthType` attribute >> check this

## Detecting AS-REPRoasting With Splunk
- Detecting AS-REPRoasting - Querying Accounts With Pre-Auth Disabled:
    - Command:
        ```code
            index=main earliest=1690392745 latest=1690393283 source="WinEventLog:SilkService-Log"
            | spath input=Message
            | rename XmlEventData.* as *
            | table _time, ComputerName, ProcessName, DistinguishedName, SearchFilter
            | search SearchFilter="*(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304)*"
        ```
    - `SearchFilter="*(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304)*"`
    - this part is key part to detect accounts with `Pre-Auth Disabled`
    - **This is what `Ruebus` is looking for >> then that's what I should keep an eye on it**

- Detecting AS-REPRoasting - TGT Requests For Accounts With Pre-Auth Disabled:
    - Command:
        ```code
            index=main earliest=1690392745 latest=1690393283 source="WinEventLog:Security" EventCode=4768 Pre_Authentication_Type=0
            | rex field=src_ip "(\:\:ffff\:)?(?<src_ip>[0-9\.]+)"
            | table _time, src_ip, user, Pre_Authentication_Type, Ticket_Options, Ticket_Encryption_Type
        ```
    - `Pre_Authentication_Type = 0` >> c'est joli!
## Practical Challenges:
1. Modify and employ the Splunk search provided at the "Detecting Kerberoasting - SPN Querying" part of this section on all ingested data (All time).
   Enter the name of the user who initiated the process that executed an LDAP query containing the
   "*(&(samAccountType=805306368)(servicePrincipalName=*)*" string at 2023-07-26 16:42:44 as your answer. Answer format: CORP\_

   **Solved:**
   - J'ai utilise la commande au-dessus et j'ai trouve le process `rundll32.exe`
   - Et j'ai trouve le `ComputerName`, `Host` mais ces informations ne sont utiles
   - Apres, j'ai trouve que >> j'ai besoin de `ProcessID: 7136` et Sysmon ID `process creation`
   - Voila, ma commande: `index=main EventCode=1 "7136"`
   - Ca y est, c'est fini!

# Detecting Pass-The-Hash
- Idea:
    - uses user's `NTLM Hash` to authenticate
    - takes it from memory with `mimikatz`

- Steps:
    - run `mimikatz.exe` > `sekurlsa::logonpasswords` to get the NTLM hash
    - attacker authenticates with this hash for the user
        - `sekurlsa::pth /Administrator /ntlm:obtained_hash /domain:corp.local`
    - with `authenticated session` now, moves freely in network: accessing resources:
        - `dir \\dc01\c$`

- Windows Access Tokens:
    - `access token` is security context of a process or a thread
        - it contains info about associated user's account identity / privileges
        - when a user is logged in, system generates a `access token`
        - `any process` user access >> takes this `access token`

- Alternate Credentials:
    - **goal here to execute certain commands / or access resources as different users**
    - It happens **without logging out or switching accounts** just in the current session
    - way to do it `runas` >> corresspondingly, `new access token` is then generated for this user
        - `runas /user:lab.internal.local\Administrator cmd.exe`
    - you can verify the new user with `whoami`

- **runas:**
    - it has  `/netonly` flag >> *the specified user information is for remote access only*
        - `runas /user:lab.internal.local\Administrator /netonly cmd.exe`

    - **Key Point:**
        - each `access token` has a `LogonSession` data info generated at user logon
        - This `LogonSession` structure contains info: `Username, Domain, and AuthenticationID (NTHash/LMHash)`
            - You log in → A LogonSession is created.
            - Any app or process you launch uses your Access Token, tied to that session.
            - That token controls who you are to the OS and when accessing remote resources.
        - This `LogonSession` is used when **the process accesses remote resources**
        -
        - **Another Point:** when `runas /netonly` is used
        - we run process locally but saying Windows to use different user credentials
        - OS uses **Same Access Token → Local behavior doesn't change.**
        - But **But: a second LogonSession is created with different network credentials.**
        - So then here, `LogonSession` is different

## Pass-the-Hash Detection Opportunities
- Goal:
    - Need to catch `runas` usage:
        - without `/netonly` flag >> `4624` and `LogonType 2` (interactive) is logged
        - with `/netonly` flag >> `4624` and `LogonType 9` (NewCredentials) is logged

## Detecting Pass-the-Hash With Splunk
- Command:
    ```code
        index=main earliest=1690450708 latest=1690451116 source="WinEventLog:Security" EventCode=4624 Logon_Type=9 Logon_Process=seclogo
        | table _time, ComputerName, EventCode, user, Network_Account_Domain, Network_Account_Name, Logon_Type, Logon_Process
    ```
    - Here `Logon_Process=seclogo`
        - `seclogo` is Logon Process Name >> Windows uses to label `Logon_Type 9`
        - `Logon_Type=9` >> which is `NewCredentials` used
        - **"seclogo" just tells you the logon was through this NewCredentials method.**

- **Here is Logic:**
    - When the hash is obtained >> user cannot easily use it to access
    - It needs to use `mimikatz` since authentication is like this for windows:
        - **Windows wants: A password, or >> A Kerberos ticket, or >>A valid authentication session already loaded in memory**
    - Then, attacker needs to change `memory` to fake credentials or to create new one
    - specifically what process the attacker access: `lsass memory`
        - `Inject the hash into memory (LSASS)`
        - `Create a fake LogonSession or modify an existing one`
        - `This tricks Windows into thinking the user is already logged in`
- Now:
    - by knowing about this >> attacker needs to access `lsass`, we track it
    - With `Sysmon 10` *Process Access*

- Better Command:
        ```code
            index=main earliest=1690450689 latest=1690451116 (source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=10
            TargetImage="C:\\Windows\\system32\\lsass.exe" SourceImage!="C:\\ProgramData\\Microsoft\\Windows Defender\\platform\\*\\MsMpEng.exe")
            OR (source="WinEventLog:Security" EventCode=4624 Logon_Type=9 Logon_Process=seclogo)
            | sort _time, RecordNumber
            | transaction host maxspan=1m endswith=(EventCode=4624) startswith=(EventCode=10)
            | stats count by _time, Computer, SourceImage, SourceProcessId, Network_Account_Domain, Network_Account_Name, Logon_Type, Logon_Process
            | fields - count
        ```

    - Here, `transaction host maxspan=1m endswith=(EventCode=4624) startswith=(EventCode=10)`
        - **Groups related events based on the host field**
        - *command is used to associate process access events targeting lsass.exe with remote logon events.*
    - `fields - count` >> removes `count` field from the results

## Practical Challenge:
1. A Pass-the-Hash attack took place during the following timeframe earliest=1690543380 latest=1690545180.
   Enter the involved ComputerName as your answer.

    **Solved:**
    - J'ai utilise la commande ci-dessus et apres j'ai obtenu le drapeau
    - Voila, ca y est!

# Detecting Pass-The-Ticket
- Idea:
    - lateral movement technique
    - abuses `TGT` or `TGS` tickets
    - Uses These Tickets to authenticate without knowing user's passwords

- Steps:
    - firstly, attacker should gain administrative  access to a system
    - secondly, it uses `rubeus` or `mimikatz` to extract valid `TGT` or `TGS` tickets from the **compromised system's memory**
        - `rubeus.exe monitor /interval:30`
    - thirdly, attacker submits the extracted ticket to the current logon session using `rubeus.exe`
        - `rubeus.exe ptt /ticket:my_ticket_plain_sattered_format`
        - check with `klist` >> you see the active `administrator session`

- Kerberos Authentication Process:
    1. User logs on >> asks `TGT` with `NTLM Hash`
    2. Receives `TGT` **encrypted with krbtgt hash**
    3. **The TGT is like a sealed letter — the user carries it but can’t open it. Only Kerberos can read it (because it holds the key = KRBTGT hash).**
    4. Requests `TGS` with obtained `TGT`
    5. Now Receives `TGS` encrypted with **hash** of `service account password`
    6. Then client connects to the server with `TGS`

- For Detection: Helpful Events:
    - `4648` >>> *Explicit Credential Logon Attempt: password, usernames are used*
    - `4624`
    - `4672` >> *Special Logon: special privileges, such as running applications as an administrator*
    - `4768` >> TGT >> `4769` >> TGS
    - `4770` >> TGS was renamed

## Pass-the-Ticket Detection Opportunities
- Possible Techniques:
    1. For the attack `Pass-The-Ticket` >> Kerberos Authentication is **partial**
        - without `TGT` >> it starts right away from `TGS`
        - so need look for `4769 and 4770` without prior `4768` *from the same system within a specific time window.*

    2. Mismatch between `Host ID` and `Service ID` from `4769` and the `actual Source and Destination IPs` **in Event ID 3**
        - Check these credentials from `4769` & `Sysmon 3`
        - *When mismatch happens >> when attacker takes the tickets from one machine >> then may use it from another machine*
        - *Admin logs into Machine A*
            - Ticket is in memory (LSASS) of Machine A
            - Attacker on Machine A dumps the ticket
            - Attacker reuses it:
            - on Machine A (silent PtT)
            - *or Machine B (causes mismatch)*

    3. Pre-Authentication Failure  `4771`:
        - `Pre-Authentication Type = 2`
            - → Means client used **Encrypted Timestamp** for login
        - `Failure Code = 0x18`
            - → Means **"Pre-auth info was invalid"** (couldn’t decrypt timestamp)
        - Why suspicious?
            - Happens when attacker **injects a fake or invalid ticket**
            - Or uses wrong password/hash to generate timestamp
            - KDC can't decrypt it → login fails
        - How to Detect:
            - Look for 4771 events with **Pre-auth type 2 + Failure 0x18**
            - Can signal **forged ticket**, **brute-force**, or **PtT gone wrong**

## Detecting Pass-the-Ticket With Splunk
- Command:
    ```code
        index=main earliest=1690392405 latest=1690451745 source="WinEventLog:Security" user!=*$ EventCode IN (4768,4769,4770)
        | rex field=user "(?<username>[^@]+)"
        | rex field=src_ip "(\:\:ffff\:)?(?<src_ip_4>[0-9\.]+)"
        | transaction username, src_ip_4 maxspan=10h keepevicted=true startswith=(EventCode=4768)
        | where closed_txn=0
        | search NOT user="*$@*"
        | table _time, ComputerName, username, src_ip_4, service_name, category
    ```

    - Here, `transaction` >> *groups events into transactions based on the username and src_ip_4 fields.*
    - `keepevicted=true` >> *ensures that open transactions without an ending event are included in the results.*
    - `where closed_txn=0` >> **filters the results to include only open transactions, which do not have an ending event.**

# Detecting Overpass-the-Hash
- Goal:
    - Attacker obtains the `NTLM Hah` then creates `TGT` using this hash
    - So, it has full Kerberos Authenticated `TGT`
    - It doesn't know the password of the user

- Attack Steps:
    - Use `mimikatz` to obtain `NTLM Hash` >> *attacker must have at least local administrator privileges on*
    - Use `Rubeus.exe` to ask `TGT` **craft a raw AS-REQ request for a specified user to request a TGT ticket**

- Detection:
    - When `Rubeus` works >> it sends `AS-REQ` request directly to DC
    - So it communicates by `TCP/UDP port 88`
    - Goal is to detect this connection from unusual process except `lsass.exe` which is legit

- Command:
    ```code
        index=main earliest=1690443407 latest=1690443544 source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
        (EventCode=3 dest_port=88 Image!=*lsass.exe) OR EventCode=1
        | eventstats values(process) as process by process_id
        | where EventCode=3
        | stats count by _time, Computer, dest_ip, dest_port, Image, process
        | fields - count
    ```

- Practical Challenge:
    1. Employ the Splunk search provided at the end of this section on all ingested data (All time) to find all involved images (Image field).
       Enter the missing image name from the following list as your answer. Rubeus.exe, _.exe

       **Solved:**
       - J'ai utilise cette commande ci-dessus et apres, j'ai trouve le drapeau
       - J'ai cherche le process sauf `lsass.exe`

# Pass-The-Hash VS Pass-The-Ticket VS Overpass-The-Hash
    ```code
        | Attack Type        | Input Used      | Protocol | Goal                      | Tools Used      |
        | ------------------ | --------------- | -------- | ------------------------- | --------------- |
        | Pass-the-Hash      | NTLM Hash       | NTLM     | Log in / run commands     | runas, mimikatz |
        | Pass-the-Ticket    | Kerberos Ticket | Kerberos | Access services           | mimikatz::ptt   |
        | Over-Pass-the-Hash | NTLM Hash → TGT | Kerberos | Forge full Kerberos login | mimikatz::pth   |
    ```

# Detecting Golden Tickets/Silver Tickets
- Goal:
    - Forges `TGT` to access AD as Domain Administrator

- Attack Steps:
    - Extract `NTLM Hash` of `KRBTGT account` using: `DCSync` OR *On DC, they can dump 'NTDS.dit' or LSASS process*
    - Armed with `KRBTGT Hash`, **attacker forges a TGT for an arbitrary user account with admin privileges** using `mimikatz`
        - `kerberos::golden ...`
    - Then in injects the obtained `TGT` in the current session using `ptt`

- Golden Ticket Detection Opportunities:
    - Problem: `TGT` obtain can be offline >> no traces of `mimikatz`

    - Key: Look How `KRBTGT Hash` can be obtained:
        - DCSync
        - NTDS.dit file access
        - LSASS memory read on DC `Sysmon 10`

## Detecting Golden Tickets With Splunk (Yet Another Ticket To Be Passed Approach):
- Command:
    ```code
        index=main earliest=1690451977 latest=1690452262 source="WinEventLog:Security" user!=*$ EventCode IN (4768,4769,4770)
        |rex field=user "(?<username>[^@]+)"
        | rex field=src_ip "(\:\:ffff\:)?(?<src_ip_4>[0-9\.]+)"
        | transaction username, src_ip_4 maxspan=10h keepevicted=true startswith=(EventCode=4768)
        | where closed_txn=0
        | search NOT user="*$@*"
        | table _time, ComputerName, username, src_ip_4, service_name, category
    ```

## Silver Ticket
- Goal:
    - IF the attacker has the `password hash` of a **target service account (e.g., SharePoint, MSSQL)**
    - He tries to forge `TGS` known as Silver Tickets
    - It can `impersonate any user`
    - Its limit is only `service single: e.g: MSSQL`

- Steps:
    - Extracts `NTLM Hash` of **service account** OR `NTLM Hash` of **computer account for CIFS access**
    - sometimes, no user log in the machine so no info in memory >> then *computer account* is also used for CIFS Access
        - `CIFS` (Common Internet File System) >> older version of `SMB` >> **file-sharing protocol, used by Windows to access network resources**
        - exmaples: `CIFS/server.domain.com` >> *Kerberos ticket for accessing file share on that server*

    - Using extracted `NTLM Hash` with `mimikatz` >> attacker creates `Silver Ticket` with `TGS` for specified service
    - Then injects forged `TGS` in the `ptt`

- Silver Ticket Detection Opportunities:
    - Sometimes, with Silver & Golden Ticket Attacks, attacker can use any user >> it can create `a new user`
    - To track this `4720` >> *A user account was created*
    - Also: `4672` (Special Logon: with admin privileges)

## Detecting Silver Tickets With Splunk
- Create `user.csv` with event id `4720`: new user was created
    ```code
        index=main latest=1690448444 EventCode=4720
        | stats min(_time) as _time, values(EventCode) as EventCode by user
        | outputlookup users.csv
    ```
- Add this list to Splunk >> `Settings -> Lookups -> Lookup table files -> New Lookup Table File.`

- Let's now compare the list above with logged-in users as follows:
    ```code
        index=main latest=1690545656 EventCode=4624
        | stats min(_time) as firstTime, values(ComputerName) as ComputerName, values(EventCode) as EventCode by user
        | eval last24h = 1690451977
        | where firstTime > last24h
       ```| eval last24h=relative_time(now(),"-24h@h") `'``
        | convert ctime(firstTime)
        | convert ctime(last24h)
        | lookup users.csv user as user OUTPUT EventCode as Events
        | where isnull(Events)
    ```
    - Ultimate goal: **Find unknown or suspicious logons from accounts not recently created**
    -
    - `eval last24h =` >> assigns it a specific timestamp value. This value represents a time threshold for filtering the results.
    - `where firstTime > last24h` >> filters the results to include only logins that occurred after the time threshold defined in last24h.
        - yeah, `firstime` happened later >> that's why bigger
    - `eval last24h=relative_time(now(),"-24h@h")` >> *redefine the last24h variable to be exactly 24 hours before the current time*
    - `lookup users.csv user as user OUTPUT EventCode as Events`
        - `lookup <lookupfile> <lookup_field> as <search_field> OUTPUT <lookup_output_field> as <output_field>`
        - *matches the user field from the search results with the user field in the CSV file*
    - `| where isnull(Events)` >> only  those where the Events field is null
        - *This indicates that the user was not found in the users.csv file. so it's created before*

- Detecting Silver Tickets With Splunk By Targeting Special Privileges Assigned To New Logon:
    - Command:
        ```code
            index=main latest=1690545656 EventCode=4672
            | stats min(_time) as firstTime, values(ComputerName) as ComputerName by Account_Name
            | eval last24h = 1690451977
            ```| eval last24h=relative_time(now(),"-24h@h") `'``
            | where firstTime > last24h
            | table firstTime, ComputerName, Account_Name
            | convert ctime(firstTime)
        ```








