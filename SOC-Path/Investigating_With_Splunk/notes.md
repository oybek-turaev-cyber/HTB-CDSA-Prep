# Splunk
    - versatile, scalable data analytics software tool
    - ingest / index / analyze / visualize

    - **Splunk Architecture:**
        - `Forwarders:` >> responsible for data collection / forward to data indexers
            - `Universal Forwarders:` >> lightweight agent without any preprocessing
            - `Heavy Forwarders:` >> agents with parsing data before forwarding
        -
        - `Indexers:` >> receive data from `forwarders` >> organize it / store it **in indexes**
        - `Search Heads:` >>  Search heads coordinate search jobs, dispatching them to the indexers and merging the results
            - GUI interface for Users in Splunk
        - `Deployment Server:` >> manages configurations for `forwarders`, distributing apps &
            updates
        - `Cluster Master:` >> coordinates activities of `indexers`

    - **Splunk Key Components:**
        - `Splunk Web Interface`
        - `Search Processing Language` **SPL**
        - `Apps` and `Add-ons`
        - `Knowledge Objects` >> include fields, tags, event types, lookups, macros, data models, and alerts that enhance the data in Splunk

## Splunk as SIEM
    - **Basic Searching:**
        - `search index="main" "UNKNOWN"`
        - `index="main" EventCode!=8`

    - **Commands:**
        - `Comparison:` >> `=, !=, <, >, <=, >=`
        -
        - **fields** >> to exclude or include certain fields >> `index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 | fields - User`
        - **table**  >> to show in tabular format >> `index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 | table _time, host, Image`
        - **rename** >> rename fields in search >> `index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 | rename Image as Process`
        - **dedup**  >> removes duplicate events >> `index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 | dedup Image`
        - **sort**   >> `index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 | sort - _time`
        - **stats**  >> to perform statistical operations >> `index="main" sourcetype="WinEventLog:Sysmon" EventCode=3 | stats count by _time, Image`
        - **chart**  >>  creates a data visualization based on statistical operations
            - `index="main" sourcetype="WinEventLog:Sysmon" EventCode=3 | chart count by _time, Image`
        - **eval**   >> creates or redefines fields >> `index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 | eval Process_Path=lower(Image)`
        - **rex**    >> extracts new fields from existing ones using regular expressions
            - `index="main" EventCode=4662 | rex max_match=0 "[^%](?<guid>{.*})" | table guid`
            - whatever finds in the regex is called **guid**
        - **lookup** >> enriches data with external sources >>
            - `index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 | rex field=Image "(?P<filename>[^\\\]+)$" | eval filename=lower(filename)
            - | lookup malware_lookup.csv filename OUTPUTNEW is_malware | table filename, is_malware`
        -
        - `index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 | eval filename=mvdedup(split(Image, "\\")) | eval filename=mvindex(filename, -1) | ev          al filename=lower(filename) | lookup malware_lookup.csv filename OUTPUTNEW is_malware | table filename, is_malware | dedup filename, is_malware`
        - this also removes duplicates from the source file: malware_lookup.csv
        -
        - **inputlookup** >> retrieves data from a lookup file without joining it to the search results
            - `| inputlookup malware_lookup.csv`
        - **earliest, latest** >> time fields >> `index="main" earliest=-7d EventCode!=1`
        -
        - **transaction** >> group events that share common characteristics into transactions
            - `index="main" sourcetype="WinEventLog:Sysmon" (EventCode=1 OR EventCode=3) | transaction Image startswith=eval(EventCode=1) endswith=eval(Ev               entCode=3) maxspan=1m | table Image |  dedup Image`
        -  the transaction starts with an event where EventCode is 1 and ends with an event where EventCode is 3
        -  `maxspan=1m` clause limits the transaction to events occurring within a 1-minute window.
        -
        **Subsearches:**
            -  a search that is nested inside another search
            -  `index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 NOT [ search index="main" sourcetype="WinEventLog:Sysmon" EventCode=1
               | top limit=100 Image | fields Image ] | table _time, Image, CommandLine, User, ComputerName`
            - NOT []: The square brackets contain the subsearch.

## How to Identify Available Data
    - **eventcount** >> `| eventcount summarize=false index=* | table index`
    - **metadata** >> `| metadata type=sourcetypes` >> `| metadata type=sourcetypes index=* | table sourcetype`
                 `| metadata type=sources index=* | table source`
    - To see all fields available >> `sourcetype="WinEventLog:Security" | table *`
    - `sourcetype="WinEventLog:Security" | fields Account_Name, EventCode | table Account_Name, EventCode`
    -
    - **fieldsummary** >> a  list of field names only >> `sourcetype="WinEventLog:Security" | fieldsummary`
    -
    - **bucket** >> bucket command is used to group the events based on the _time field into 1-day buckets._
    - `index=* sourcetype=* | bucket _time span=1d | stats count by _time, index, sourcetype | sort - _time`_
    - **rare** >> identify uncommon event types >> `index="main" | rare limit=20 useother=f ParentImage`
    - **dc >> distinct count** >> `index=* sourcetype=* | fieldsummary | where count < 100 | table field, count, distinct_count`
    - **sistats** >> `index=* | sistats count by index, sourcetype, source, host`
    -
    - **rare** >> `index=* sourcetype=* | rare limit=10 field1, field2, field3`
    -

## Helpful:
    - **Pivots:** >> Pivots are an extremely powerful feature in Splunk that allows us to create complex reports and visualizations
      without writing SPL queries.

## Practical Exercises:
    1. Find through an SPL search against all data the account name with the highest amount of Kerberos authentication ticket requests. Enter it as your answer.

    **Solved:**
    - I found the Event IDs associated with Kerberos Authentication: Event ID >> 4768, 4773
    - SPL >> `index="main" EventCode=4768 | table Account_Name, User`
    - Voila >> this query gives the correct results!

    2. Find through an SPL search against all 4624 events the count of distinct computers accessed by the account name SYSTEM. Enter it as your answer.

    **Solved:**
    - I used the hint given by offering "distinct_count" function
    - I used the given search filters: 4624, SYSTEM, sorted with descending order
    - SPL >> `index="main" EventCode=4624 Account_Name="SYSTEM" | dc(ComputerName)`
    - Voila >> j'ai trouve le drapeau

    3. Find through an SPL search against all 4624 events the account name that made the most login attempts within a span of 10 minutes. Enter it as your answer.

    **Solved:**
    - It went a bit challenging since the question meant different meaning:
    - Need to find the account name which made the most login attempts during his login time of 10
        mins window
    - My approach: I found the first login time and last login time, I found the difference and
        searched for login_duration for less than 10 minutes = 600 seconds
        Then, using table command, I printed Account_Names sorted by login duration
    - SPL:
    - `Code=4624 | stats earliest(_time) as first_login latest(_time) as last_login by Account_Name | eval login_duration = last_login - first_login
    | where login_duration <= 600 | convert ctime(first_login) ctime(last_login) | table Account_Name first_login last_login login_duration
    | sort - login_duration`
    - Voici, I got the flag!

# Splunk Apps
    - Different Apps to be integrated into Splunk SIEM

    - **Sysmon App** by Mike Haag

## Practical Challenges:
    1. Access the Sysmon App for Splunk and go to the "Reports" tab. Fix the search associated with the "Net - net view" report and provide the complete e       xecuted command as your answer.

    **Solved:**
    - I see that the SPL Query is not well-built:
    - It was such: `sysmon` | table Computer, Command
    - I fixed in a such way: `index="main" sourcetype="WinEventLog:Sysmon EventCode=1 | table ComputerName, CommandLine`
    - Voila, c'est fini!

    2. Access the Sysmon App for Splunk, go to the "Network Activity" tab, and choose "Network Connections". Fix the search and provide the number of conn       ections that SharpHound.exe has initiated as your answer.

    **Solved:**
    - My fixed SPL Query:
    - `index="main" sourcetype="WinEventLog:Sysmon" EventCode=3 Image="$imgsel$" Protocol="$protosel$" DestinationPort="$portsel$"
        DestinationHostname="$destinations$" | eval DestinationHostname=coalesce(DestinationHostname,DestinationIp) | stats count,
        values(DestinationHostname) AS "Destinations", values(DestinationPort) AS "Ports",
        values(Protocol) AS "Protocols" by Image | fields Image Destinations Ports Protocols count`
    - C'est le query correct et tu peux trouver le drapeau!
    - Voila, c'est fini!

# Intrusion Detection With Splunk (Real-World Scenario)
    - ` I will be working with over 500,000 events.`
    - Need to know what we have                  >> `index="main" | stats count by sourcetype`
    - Then I will choose the specific sourcetype >> `index="main" sourcetype="WinEventLog:Sysmon"`
    - Then do some general queries to warm-up hands

## Embrac ing The Mindset Of Analysts, Threat Hunters, & Detection Engineers
    - Start with what Sysmon EventCodes are on the trend >> `index="main" sourcetype="WinEventLog:Sysmon" | stats count by EventCode`
    - I decide to detect on suspicious \ unusual **parent-child** processes >> using Sysmon ID 1 (ProcessCreate)
        - `index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 | stats count by ParentImage, Image`
    - Then to be more specific with `cmd.exe` or `powershell.exe`:
        - `index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 (Image="*cmd.exe" OR Image="*powershell.exe") | stats count by ParentImage, Image`
    - It takes an attention: when `notepad.exe` is connected with `powershell.exe`
        - `index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 (Image="*cmd.exe" OR Image="*powershell.exe") ParentImage="C:\\Windows\\System32\\not            epad.exe"`
    - Something interesting comes up with downloading files from another machine: `CommandLine`, with `10.0.0.229`
        - `index="main" 10.0.0.229 | stats count by sourcetype`
        - `index="main" 10.0.0.229 sourcetype="linux:syslog"`
    - I want to take a look on used `CommandLine`:
        - `index="main" 10.0.0.229 sourcetype="WinEventLog:sysmon" | stats count by CommandLine`
        - `index="main" 10.0.0.229 sourcetype="WinEventLog:sysmon" | stats count by CommandLine, host`
    - From the output, visible, that DCSync PowerShell script was executed on the second host
        - `index="main" EventCode=4662 Access_Mask=0x100 Account_Name!=*$`
        - Event Code 4662 is triggered when an Active Directory (AD) object is accessed
        - Access Mask 0x100 specifically requests Control Access typically needed for DCSync's high-level permissions
        - as DCSync should only be performed legitimately by machine accounts or SYSTEM, not users
        - Then, we look at the Properties Part: two intriguing GUIDs >> Google Search >>
            - **DS-Replication-Get-Changes-All** >> **allows the replication of secret domain data**
            - successfully executed by the Waldo user on the UNIWALDO domain
            -
    - Time to see any memory dumps >> Sysmon ID 10 (ProcessAccess)
        - `index="main" EventCode=10 lsass | stats count by SourceImage`
        - `index="main" EventCode=10 lsass SourceImage="C:\\Windows\\System32\\notepad.exe"`

    - Call Trace Info:
        - CallStack >> callstack refers to an **UNKNOWN segment into ntdll**
        - any form of shellcode will be located in what's termed an unbacked memory region
        - Key Moment >> **ANY API calls from this shellcode don't originate from any identifiable
            file on disk, but from arbitrary, or UNKNOWN, regions in memory that don't map to disk
            at all.**
        - But we need to be careful with **JIT processes** >> false positives
        -

## Creating Meaningful Alerts
    - It's important now to create a useful alerts
        - `index="main" CallTrace="*UNKNOWN*" | stats count by EventCode` >> Sysmon ID 10
        - `index="main" CallTrace="*UNKNOWN*" | stats count by SourceImage`
        - **false positives we mentioned, and they're all JITs as well! .Net is a JIT, and Squirrel
            utilities are tied to electron, which is a chromium browser and also contains a JIT**
    - Now, exclude when source and target are the pareil
        - `index="main" CallTrace="*UNKNOWN*" | where SourceImage!=TargetImage | stats count by SourceImage`
    - Exclude anything C Sharp related due to its JIT. >> Microsoft.Net folders and anything that has ni.dll in its call trace or clr.dll.
        - `index="main" CallTrace="*UNKNOWN*" SourceImage!="*Microsoft.NET*" CallTrace!=*ni.dll* CallTrace!=*clr.dll* | where SourceImage!=TargetImage
          | stats count by SourceImage`
    - Eradicate anything related to WOW64 within its call stack
        - `to the above query: CallTrace!=*wow64*`
    - Exclude >> Explorer.exe as well
        - `SourceImage!="C:\\Windows\\Explorer.EXE"`
    - Final Query >> Alert >>
    - `index="main" CallTrace="*UNKNOWN*" SourceImage!="*Microsoft.NET*" CallTrace!=*ni.dll* CallTrace!=*clr.dll* CallTrace!=*wow64* SourceImage!="C:\\Win       dows\\Explorer.EXE" | where SourceImage!=TargetImage | stats count by SourceImage, TargetImage, CallTrace`


## Practical Challenges:
    1. Find through an SPL search against all data the other process that dumped lsass. Enter its name as your answer.

    **Solved:**
    - I see that the investigation is associated with access to lsass
    - That's why I use Sysmon ID 10 (ProcessAccess)
    - My SPL >> `index="main" sourcetype="WinEventLog:Sysmon" EventCode=10 lsass | stats count by Image | sort - count`
    - Voila >> it gives the correct direction

    2. Find through SPL searches against all data the method through which the other process dumped lsass. Enter the misused DLL's name as your answer.

    **Solved:**
    - Based on the investigation from `powershell.exe` associated unusual activities
    - I see some connection to the another machine and downloading of dll into the victim's machine
    - Using other processes activities >> `Call Trace` I found out the suspicious dll:
    - Also I used Sysmon 7 ID >> DLL Image loading
    - My SPL >> `index="main" sourcetype="WinEventLog:Sysmon" EventCode=7 Image=*answer_from_the_previous_question" | stats count by ImageLoaded, CommandL                 ine`
    - Voila >> it gives the correct direction


    3. Find through an SPL search against all data any suspicious loads of clr.dll that could indicate a C# injection/execute-assembly attack. Then, again       through SPL searches, find if any of the suspicious processes that were returned in the first place were used to temporarily execute code. Enter it       s name as your answer.

    **Solved:**
    - To understand the scenario >> I created a map of the attack >> that any usage of clr.dll
        except normal programs, and calling from system32, I will consider as suspicious and dig
        deeper
    - I found a couple of the programs loaded clr.dll from the unusual locations
    - Then I used this SPL
    - `index="main" sourcetype="WinEventLog:Sysmon" Image="suspicious.exe" | stats count by CallTrace`
    - Investigating further this data >> I found out that the benevolent process is called to
        execute the code
    - Voila >> c'est fini

    4. Find through SPL searches against all data the two IP addresses of the C2 callback server. Answer format: 10.0.0.1XX and 10.0.0.XX

    **Solved:**
    - Starting from the beginning I know that there is a suspicious IP address `10.0.0.229`
    - SPL >> `index="main" sourcetype="WinEventLog:Sysmon" DestinationIp=10.0.0.229 | stats by host, SourceIp, DestinationIp`
    - This was kinda starting to find the poisoned hosts >> through this I identified the host associated with this IP
    - Then I changed the SPL Query to target this specific host: "DESKTOP.....$"
    - I made sure that it's one victim one and searched on the DestinationIp and SourceIp associated
        with this host:
    - My SPL >> `index="main" sourcetype="WinEventLog:Sysmon" host="DESKTOP......$" | stats count by SourceIp, DestinationIp | sort - count`
    - Voila, J'ai trouve le drapeau!!!

    5. Find through SPL searches against all data the port that one of the two C2 callback server IPs used to connect to one of the compromised machines.        Enter it as your answer.

    **Solved:**
    - Continuing with #4 Challenge >> I just added to my query: Actually I found two mostly used
        ports >> one is correct!
    - `|stats count by SourceIp, DestinationIp, DestinationPort`
    - `index="main" sourcetype="WinEventLog:Sysmon" host="DESKTOP......$" | stats count by SourceIp, DestinationIp, DestinationPort | sort - count`
    - Voila, c'est fini!!!


