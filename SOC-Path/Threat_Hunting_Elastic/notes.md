# Threat Hunting
- Start
    - active / human-led / often hypothesis-driven practice
    - identify the critical assets
    - analyze TTPs >> tactics >> techniques >> procedures

    - cognitive empathy with the attacker
    - offensive & proactive strategy

- **When You should HUNT?**
    - `When New Information on an Adversary or Vulnerability Comes to Light`
    - When New Indicators are Associated with a Known Adversary
    - When Multiple Network Anomalies are Detected
    - `During an Incident Response Activity`

# Hunting Process:
1. `Setting the Stage:`
    - planning / prep / threat landscape / business assets
2. `Formulating Hypotheses:`
    - making educated predictions through:
        - recent threat intelligence
        - industry updates
        - alerts from security tools
        - or even our professional intuition
3. `Designing the Hunt:`
    - follow the hypothesis
    - recognize the specific data sources
    - look for the indicators of compromise (IoCs) or patterns
4. `Data Gathering and Examination:`
    -  active threat hunt occurs
    -  collecting necessary data >> log files >> network traffic data >> endpoint data
5. `Evaluating Findings and Testing Hypotheses:`
    - Need to interpret the results.
    - Identify affected systems
6. `Mitigating Threats:`
    - Isolate affected systems
    - Eliminate malware
    - Patch vulnerabilities
    - Modify configurations
7. `After the Hunt:`
    - Document findings
    - Share with stakeholders

# Glossary Hunting:
- `Tactics` >> explain "why"
    - `Techniques` >> explain "how"
    - `Procedures` >> explain "recipe"

- **Pyramid of Pain:**
    - presents a hierarchy of indicators
    - helps to detect `adversaries`
    - the impact is for the `adversaries`
    - Here it is:   *Indicators*               *Impact*
        - `TTPs`                   >> Tough
        - `Tools`                  >> Challenging
        - `Network/Host Artifacts` >> Annoying
        - `Domain Names`           >> Simple
        - `IP Addresses`           >> Easy
        - `Hash Values`            >> Trivial
- **Domain Names:**
    - `domain generation algorithms (DGAs)`: to produce a large number of `pseudo-random domain names` to **evade detection**.

- **Diamond Model:**
    -  a more structured approach to `understand`, `analyze` and respond to cyber threats.
    -  Adversary >> Capability >> Infrastructure >> Victim
    - *Infrastructure vs Capability*
        - Capability     >> TTPs >> malware >> exploits >> other malicious tools
        - Infrastructure >> the `physical and virtual resources`  >>
            - **servers, domain names, IP addresses**
            - other network resources used to **deliver malware, control compromised systems, or exfiltrate data**


- Voila:
    **The Diamond Model provides a complementary perspective to the Cyber Kill Chain, offering a
    different lens through which to understand and respond to cyber threats.**

# Cyber Threat Intelligence >> CTI
- `Key Points` >> Relevance >> Timeliness >> Actionability >>> Accuracy
    - **Threat Intelligence vs Threat Hunting**
        - **Predictive vs (Reactive & Proactive)**

    - *Intelligence Types:*
        - Strategic >> Operational >> Tactical

- **How To Go Through A Tactical Threat Intelligence Report?:**
    - `Comprehending the Report's Scope and Narrative`            >> specifically to whom all this info?
    - Spotting and Classifying the IOCs                         >> what IoCs they have ?
    - `Comprehending the Attack's Lifecycle`                      >> how the attack functions?
    - Analysis and Validation of IOCs                           >> these IoCs can happen in your env?
    - `Incorporating the IOCs into our Security Infrastructure`   >> apply IoCs to your company?
    - Proactive Threat Hunting                                  >> hunt before the adversary?

# Practical Challenge: Stuxbot
- **Report is given:**
    - Possible Victim Platforms >> Microsoft Windows
    - Users                     >> Windows Users
    - Potential Impact          >> Complete takeover victim's machine
    - Risk Level                >> Critical

- **Attack Scenario:**
    - Phishing Email >> OneNote File >> Batch File >> Powershell script (in memory) >> RAT

- **IOCs:**
    - OneNote File: `https://transfer.sh/get/kNxU7/invoice.one` or
        `https://mega.io/dl9o1Dz/invoice.one`
    - Powershell Script: `https://pastebin.com/raw/AvHtdKb2` or `https://pastebin.com/raw/gj58DKz`
    - C2 Nodes: 91.90.213.14:443 >> 103.248.70.64:443
    - Cryptographic Hashes of Involved Files (SHA256):
        - `226A723FFB4A91D9950A8B266167C5B354AB0DB1DC225578494917FE53867EF2`
        - `018D37CBD3878258C29DB3BC3F2988B6AE688843801B9ABC28E6151141AB66D4`

- **Hunting For Stuxbot With The Elastic Stack:**
    - Available Data:
            1. `windows*` >> includes powershell logs >> Sysmon logs >> Windows audit logs
            2. `zeek*` >> includes >> zeek logs >>  a network security monitoring tool

    - Hunting:
            1. Sysmon ID 15 >> (FileCreateStreamHash) >>  a browser file download event: `event.code:15`
            2. Search filename: `file.name:*invoice.one`
            3. Sysmon ID 11 >> (File Create) (browsers aren't involved in the file download process): `event.code:11`
            4. `file.name:invoice.one*`
    - Through this, we found the `file downloaded actions` & associated Host : now we analyse which host did
        this to get its IP address:
        - KQL >> `event.code:3 AND host.hostname:WS001` >> for this switch logs `zeek*`
        - IP is found: Now need to check DNS queries:
        - `source.ip:192.168.28.130 AND dns.question.name:*`
        - `March 26th 2023 @ 22:05:00 to March 26th 2023 @ 22:05:48.`
        - We found some artifacts mentioned in the report: IP address of C2 possible,
                        dig deeper:
        - `34.197.10.85, 3.213.216.16`
        - We found that `Bob`, successfully downloaded the file "invoice.one" from the hosting provider "file.io".
        - `event.code:1 AND process.command_line:*invoice.one*`
        - `process.pid:"9944" and process.name:"powershell.exe"`
        -
        - `process.hash.sha256` field for default.exe
        - `process.hash.sha256:018d37cbd3878258c29db3bc3f2988b6ae688843801b9abc28e6151141ab66d4`
        - Exact Match is found
        - `(event.code:4624 OR event.code:4625) AND winlog.event_data.LogonType:3 AND source.ip:192.168.28.130`

## Practical Challenges:
1. Navigate to http://[Target IP]:5601 and follow along as we hunt for Stuxbot. In the part where default.exe is under investigation, a VBS file is mentioned. Enter its full name as your answer, including the extension.

    **Solved:**
    - I followed the steps to identify any malicious actions by filtering `process.name:default.exe`
    - I found the .vbs file is downloaded and I found its associated name

2. Stuxbot uploaded and executed mimikatz. Provide the process arguments (what is after .\mimikatz.exe, ...) as your answer.

    **Solved:**
    - In Elastic Stack >> I searched for logs with KQL >> `mimikatz.exe`
    - Then I added as a column `process.args`
    - Then it was easier to find the necessary info

3. Some PowerShell code has been loaded into memory that scans/targets network shares. Leverage the available PowerShell logs to identify from which popular hacking tool this code derives.

    **Solved:**
    - I have applied the filter any scripts with KQL >> `powershell.script_block_text:*`
    - Among them, I tried to find the any suscipicous files associated with
    - I got one with extension `.ps1` starting with `D` Letter then I googled what it is
    - I found that it is a tool `for reconnaissance in Windows domains`
    - a part of the `PowerSploit Collection`

# Skills Assessment: Challenges >> Hunting For Stuxbot (Round 2)

## The Tasks:
1. Create a KQL query to hunt for "Lateral Tool Transfer" to C:\Users\Public. Enter the content of the user.name field in the document that is rel           ated to a transferred tool that starts with "r" as your answer.
        .
    **Solved:**
    - I identified that for the lateral movement process >> sysmon file create 11 ID may be
        associated
    - I searched for the KQL >> `file.directory:C:\Users\Public`
    - Then I added columns with fields >> `user.name` and `process.name`
    - Voila >> J'ai fini la tache avec succes
    
2.  Create a KQL query to hunt for "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder". Enter the content of the registry.valu            e field in the document that is related to the first registry-based persistence action as your answer.
        
    **Solved:**
    - This went challenging for me
    - I created KQL with `HKU` key and filtered the logs with `sysmon ID 13` to know when
        `registry key set` events occured
        - KQL >> `event.code:13` and `HKU*`
    - I added a column with the field `registry.value`
    - I also filtered the `file.directory` and `message:*Common Startup*` to find the keys
        specifically associated with Startup Folder
    - Voila, c'est fini, j'ai trouve le drapeau
    -
3.  Create a KQL query to hunt for "PowerShell Remoting for Lateral Movement". Enter the
            content of the winlog.user.name field in the document that is related to PowerShell
            remoting-based lateral movement towards DC1.
        
    **Solved:**
    - Based on my work wit **MITRE ATT&CK** Framework, I found those clues:
    - need to put the filter: 
        - `process.name:powershell.exe` then I applied `powershell.command_line.block_text:*` >> to see the suspicious powershell remote
        connections
    - I found out the remote tool script with .ps1 and correlate this to the right time when the
        attack time happened
    - I added a column to Elastic Stack board with `win1log.user.name` field.
    - Voila, J'ai trouve le drapeau >> La vie est belle!

