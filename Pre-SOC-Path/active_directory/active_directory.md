# AD Structure
    - `centralized management tool` to manage Windows network environments
    - a directory service: `Active Directory Domain Services`
    - since Windows 2000 Server

- **Forest**
    - AD Structure which includes one or more domains
    - Security Boundary which all objects are under administrative control
- **Domain**
    - AD Structure which includes objects: users, computers, groups
    - Has many built-in `OUs` >> `Organizational Units`: Domain Controller, Users, Computers
    - New OUs can be created as required

    - If `two forests` has  `bidirectional trust`, but it **does not apply** `for child domains`

# AD Terminology
- `attributes`  >> to define the characteristics of the object
- `schema`    >> blueprint >> to define what type of objects exist AD Database
- `domain`  >> logical group of objects such as computers, users, OUs and groups
- `forest` >> collection of AD domains
- `GUID` >> Global Unique Identifier >> 128-bit value >> assigned when new user or group is created
- `SAM` >> Security Accounts Manager >> to manage local user accounts and groups
- `DN` >> Distinguished Name >> full path to an object in AD:
   - *inflane.local/Users/Sales/Managers/Jbones*
- `RDN` >> Relative Distinguished Name >> single component of DN to identify the object from others
   - *inflane.local/Users/Sales/Managers/Jbones* >> here `Jbones` is RDN
   -
- `FSMO` Roles >> Flexible Single Master Operation:
    - `Schema Master` / `Domain Naming Master`  / `Relative ID Master`  / `Primary Domain Controller`
    - `Infrastructure Master`

- `Global Catalog` >> stores copies of ALL objects in AD forest.
- `SPN` >> Service Principal Name >> uniquely identifies a service instance
- `FQDN` >> Fully Qualified Domain Name >> a complete name for a specific computer or host
    - DCO1.INFLANE.LOCAL >> `HOSTNAME.DOMAIN NAME.TLD`
- `Tombstone` >> container object that holds the deleted AD objects
    - the tombstone object >> `stripped of most of its attributes`
- `AD Recycle Bin` >> deleted objects' attributes are preserved
- `NTDS.DIT` >> **heart of AD >> stored at Domain Controller C:\Windows\NTDS**
    - stores the `hashes of passwords` for *ALL users* in a domain
- `Leaf objects` >> do not contain other objects and found at the end of tree hierarchy
- `Security Principals` >> the objects which AD should secure
    - anything that the operating system can authenticate, including users, computer accounts, or even threads/processes
    - if an object is considered a `Security Principal` (securable object) >> then it gets **SID**
- `SID` >> Security Identifier >>  unique identifier for a `security principal` or `security group`

# AD Objects
- `Users` >> leaf objects >> SID & GUID
    - more than 800 attributes
- `Contacts` >> external users >> leaf objects
- `Computers` >> comes with account **NT AUTHORITY\SYSTEM** (similar to standard domain user)
- `Shared Folders` >> can be accessible to everyone (even without valid AD Account)
- `Groups` >> container object >> nested groups (inherit rights) >> possible issues
    - `BloodHound` >> shows the connections graphically
- `Organizational Units` >> container >> sys admins use to store similar objects for easier adminst
- `Domain` >> contain objects: users, objects which are organized into container objects:groups, OUs
- `Domain Controller` >> the brains of AD Network
    - handle authentication requests
    - verify users on the network
    - controls authorization to access the resources
- `Site` >> a `site` in AD >> *a set of computers*
    - across one or more subnets
    - connected using high speed links

- `Foreign Security Principal` >> an object created in AD:
    - to represent a security principal `that belongs` to a `trusted external forest`.

# AD Functionality
- Five Roles (Masters) for specific tasks in Domain
- Based on the Windows Server Year Series >> Domain Function Levels are labeled
- `Trust` >> forest-forest / domain-domain
    - `Cross-Link` >> between domain children

# AD Protocols
- **Kerberos**
    - robust `authentication protocol` for AD
    - `issues tickets` for users
    - avoids repetitive password entries
    - these tickets are necessary to `access to resources` in Domain.
    - **Process**
        - User logs in, his password is used to encrypt a timestamp
        - This encrypted timestamp is sent to KDC (Key Distribution Center)
        - KDC >> attempts to find the user in DC and decrypts the timestamp
        - KDC then issues TGT (Ticket Granting Ticket) >> encrypt it with secret key
        - User receives TGT >> `presents it to DC` to request TGS (Ticket Granting Service) for a
            `specific service`
        - TGS is encrypted with NTLM password hash of the service or computer account in which
            service instance is running
        - User takes TGS
        - Then User `presents TGS to the service` >> then access to service is `granted` voila!
- **DNS**
    - used in AD >> clients use to locate DC >> client to DNS with domain name
    - DNS back to client with IP of the domain or vice versa
    - `nslookup <host_name>` without FQDN
- **LDAP**
    - open-source & cross-platform
    - `language` or main protocol used to `query & manage` information in `AD`
    - provides `a way` to `access & query` various `directory services`
    - similar to we use `HTTP` with `Apache`
    - used:  look up user details, group memberships, other attributes

    - authentication messages are sent in plaintext >> should be used with `TLS`
    - Ports: `389` >> `636 over TLS`
- **MSRPC**
    - Microsoft Remote Procedure Call (RPC)
    - to allow services & components to communicate with each other across a network
    - enables one program to `execute a procedure` on *another machine* `remotely`
    - Four Name Instances:
        - `netlogon` >> domain-joined comps use MS-RPC via Netlogon service to establish a secure
          - channel `with Domain Controller` (DC) >> goal secure communication for authentication
          - requests & domain configuration details
          -
        - `samr` >> Security Account Management Remote
            - to manage user and group accounts on DC
        - `lsarpc` >>  manages the local security policy on a computer, controls the audit policy,
        - `drsuapi` >> perform replication-related tasks across Domain Controllers in a multi-DC environment.

    - **Simply:**
        - Domain-joined computers initiate communication using Netlogon and
        - sometimes indirectly through LSARPC to `authenticate and request` information `from DCs`.
        - Administrative tools running on domain-joined computers (or elsewhere) initiate SAMR to `instruct DCs` to `make changes` to directory objects.
        - DCs initiate DRS to `replicate changes` `amongst themselves`.

# NTLM Authentication
- LM >> LAN Manager >> Hashing Protocol
    - weak one
    - used until Windows Vista/Server 2008
    - password: maximum 14 chars

- NTLM >> NT LM
    - used on modern windows systems
    - `challenge-response` authentication protocol
        - uses three messages: `NEGOTIATE` / `CHALLENGE` / `AUTHENTICATE`
    - **pass-the-hash** attacks are possible with NTLM Hashes
        - `crackmapexec smb 10.129.41.19 -u rachel -H e46b9e548fa0d122de7f59fb6d48eaa2`

# User Accounts
- `SYSTEM` >> local account in Windows
    - used by OS
    - the highest permission level
- `User Naming Attributes`
    - `UserPrincipalName` >> primary logon name for the user
    - `ObjectGUID` >> unique identifier of the user, never changes, removes even after the user del
    - `SAMAccountName` >> logon name to support the previous versions of windows clients
    - `objectSID` >> security identifier
    - `sIDHistory` >> when user is migrated from another domain, previous SID is written in history

# AD Groups
- `Group Types:`
    - **Security Groups**      >> used to `assign permissions & rights` for a users
    - **Distribution Groups**  >> used by email applications to `distribute messages` to group members

- `Group Scope:`
    - **Domain Local Group** >> to manage to domain resources `in the domain where it was created`
    - **Global Group** >> to grant access to resources in `another domain`
        - only contain accounts from the domain where it was created.
        - can be added to both other global groups and local groups.
    - **Universal Group** >> manage resources distributed `across multiple domains`
        - can be given permissions to `any object within` the `same forest`
        - is stored at GC (Global Catalog)
        - *adding or removing objects* from a universal group `triggers forest-wide replication`.

    - **Advice:**
        - **recommended to create other groups (Global Groups) as members of Universal Groups**
        - Why? because replication only happens in the `individual domain level` **not globally** when a user is
            - removed from a global group
        - But, if `individual users or groups` are maintained in `universal groups`
            - it will trigger **forest-wide replication** `each time a change is made`.

# AD Rights & Privileges
- `Rihts` >> to *access the objects*: file etc
- `Privileges` >> to *perform an action*: run program, shut down system

- **Some Nice Privileges:**
    - `SeRemoteInteractiveLogonRight`
    - `SeBackupPrivilege` >> could be used to obtain `SAM` and `SYSTEM Registry hives` and the `NTDS.dit`
    - `SeDebugPrivilege` >>  to debug and adjust the memory of a process.
        - `Mimikatz` to read the memory space of the `Local System Authority (LSASS)` process
        - To obtain any credentials `stored in memory`.
    - `SeImpersonatePrivilege` >> allows us to impersonate a token of a privileged account such as NT AUTHORITY\SYSTEM.
        - With tools:  JuicyPotato, RogueWinRM, PrintSpoofer, etc., to escalate privileges on a target system.
    - `SeTakeOwnershipPrivilege` >> allows a process to take ownership of an object.
        - we could use this privilege to `gain access to a file share` or a `file on a share` that was otherwise `not accessible to us`

    - **whoami /priv** >> to see the user privileges

# AD Hardening
- `LAPS` >> Local Administrator Password Solution
    - used to **randomize and rotate** `local administrator passwords` on Win hosts,
    - prevent lateral movevement
    - on specific intervals (12 hour; 24 hour)
    - Local Admin Accounts >> for administrative tasks in individual hosts of the Domain
- `Audit > Policy Settings`
- `Group Policy Security Settings`
    - software restrictions
    - local policies
    - account policies
    - application control policies: `AppLocker`
- **Update Management:**
    - **WSUS** >> Windows Server Update Service >> to apply patches automatically
    - *SCCM* >> System Center Configuration Manager >> together with `WSUS` works better
- Security Groups >> Built-in Ones

- **Restricted Groups:** >> help you `define and enforce exactly` who should (or shouldn't) `be members of important groups`
    - For example, for `local "Administrators" group` in every host, we want only `local
        administrator` and `Domain Groups` are members but `Not others`
        - if we specify this in restricted groups >> others will be removed and only what we have
            - shown are left in *Administrators*

- `Limit Local Admin & RDP Rights` >> Domain Users do not need `local admin rights` & `RDP`.
    - If local admin rights is enabled for all Domain users, Users can access to `ANY` computer host
        as local admin >> obtain sensitive info from memory if someone is already logged in.



