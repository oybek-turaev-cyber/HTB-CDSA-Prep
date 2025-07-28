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


















