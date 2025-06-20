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




















