# Intro
- Definition
    - `IDS or IPS` >> a device or an application
    - monitors >> network or system activities for malicious activities
    - monitors >> policy violations
    - produces reports

- IDS
    - signature-based >> based on known signatures, patterns
    - anomaly-based >> based on normal baseline >> reports anything deviating from this
    - common location: **after the firewall, closer to internal net**
    - only detection

- IPS
    - **sits directly behind the firewall**
    - signature-based / anomaly-based
    - detection + protection

# Suricata
- **Usage:**
    - IDS >> IPS >> NSM (Network Security Monitoring)
    - Talents: detailed set of rules >> efficiency
    - Modes: IDS >> IPS >>
        - IDPS (Intrustion Detection Prevention System): does IDS stuff also, as IPS sends `RST` packets to abnormal activities
        - NSM >> `Dedicated Logging Mechanism`

    - Input: Offline >> `LibPCAP` format
        - Live Input >> `LibPCAP` >> some limitations
        - `NFQ`, `AF_PACKET` >> better for inline operations
        -
        - `NFQ` >> Linux-specific IPS mode >> collaborates with IPTables to take packets from kernel space
        - `AF_PACKET` >> *performance improvement over LibPCAP* >> *multi-threading*

    - Output:
        - `EVE` >> *JSON formatted log*: `alerts, HTTP, DNS, TLS metadata, drop, SMTP metadata, flow, netflow, etc`

- **Details:**
    - configuration file >> `/etc/suricata/suricata.yaml`
    - rules located at >> `/etc/suricata/rules/`

    - **Rules:**
        - `$HOME_NET` -> examines IP addresses from this going to `$EXTERNAL_NET`
        - Variables are configured at `suricata.yaml`
        - Possible to add custom rules: `rule-files` in `suricata.yaml`

- **Practice With Suricata Inputs:**
    - **Offline:**
        - `suricata -r /home/suspicious.pcap`
        - `suricata -r /home/htb-student/pcaps/suspicious.pcap -k none -l .`
            - `-r` >> to read & analyse
            - `-k none` >> Disables checksum verification
            - `-l .` >>  Sets the output log directory to the current folder `.`

    - **Live Input:**
        - specify the network interface: `sudo suricata --pcap=ens160 -vv`

    - **Suricata in Inline (NFQ) mode:**
        1. `sudo iptables -I FORWARD -j NFQUEUE`
        2. `sudo suricata -q 0`
            - `-q` >> specifies the `interface` or `queue` to listen on which is `0` now

    - **Suricata in IDS mode with AF_PACKET input**
        - `sudo suricata -i ens160`
        - `sudo suricata --af-packet=ens160`

- **Practice With Suricata Outputs:**
    - Files >> `eve.json`, `fast.log`, `stats.log`

    - Commands:
        - Filter only *alert* events:
            - `cat /var/log/suricata/old_eve.json | jq -c 'select(.event_type == "alert")'`
                - `jq` >> JSON command-line processor
        - Filter the first *DNS* events:
            - `log/suricata/old_eve.json | jq -c 'select(.event_type == "dns")' | head -1 | jq .`
                - `jq .` >> *Pretty-prints that single DNS event in a readable, indented JSON format.*
                - not one-line form
    - Fields:
        - `flow_id` >> unique identifier assigned by Suricata to each network flow
            - `flow` >> set of IP packets between a specific pair of source & destination endpoints
        - `pcap_cnt` >> a counter that Suricata increments for each packet it processes from the network traffic or from a PCAP file

- **File Extraction:**
    - file extraction >> Suricata can automatically save files (like PDFs, executables etc) over different protocols
    - `suricata.yaml` >> find the section:`file-store` >> This is where we tell Suricata how to handle the files it extracts.
        - set `version` to `2` and `enabled` to `yes`, and `force-filestore` to `yes`
        - then `dir: filestore` >> you specify the directory to store the files

    - `alert http any any -> any any (msg:"FILE store all"; filestore; sid:2; rev:1;)`
        - This rule tells Suricata to store all files seen in HTTP traffic.

    - Goal >> **look for files in traffic and save them**

    - `cd filestore` >> `find . -type f` >> check out stored files
    - This directory: logs its files with `SHA256` >>
    - Naming Style: if the SHA256 hex string of an extracted file starts with f9bc6d... the file we be placed in the directory filestore/f9.
    - Example: `/21/21742fc621f83041db2e47b0899f5aea6caa00a4b67dbff0aae823e6817c5433` file inside `filestore` dir.
    - **xxd** tool can be used to inspect: `xxd ./21/21742fc621f83041db2e47b0899f5aea6caa00a4b67dbff0aae823e6817c5433 | head`

- **Live Rule Reloading Feature & Updating Suricata Rulesets:**
    - in configuration file find `detect-engine` and set `reload` to `true`
        - `sudo kill -usr2 $(pidof suricata)`
        - tells Suricata to check for changes in the ruleset periodically and apply them without needing to restart the service.

    - `suricata-update` tool >> Updating Suricata's ruleset
    - `sudo suricata-update enable-source et/open` >> to retrieve and enable the et/open rulesets


    - ` sudo suricata -T -c /etc/suricata/suricata.yaml`
        - `-T` >> test mode >> check it's valid or not
        - `-c` >> tells to use `this specific configuration file.`

- **Suricata Key Features:**
    - `Lua scripting`
    - `Geographic IP identification (GeoIP)`
    - `IP reputation`
    - `File extraction`

- **Practical Challenges:**
    1. Filter out only HTTP events from /var/log/suricata/old_eve.json using the the jq command-line JSON processor.
       Enter the flow_id that you will come across as your answer.

    **Solved:**
    - J'ai utilise cette commande:
        - `log/suricata/old_eve.json | jq -c 'select(.event_type == "http")' | head | jq .`
    - Voila, j'ai obtenu le drapeau

    2. Enable the http-log output in suricata.yaml and run Suricata against /home/htb-student/pcaps/suspicious.pcap.
       Enter the requested PHP page as your answer.

    **Solved:**
    - D'abbord, j'ai modifie `suricata.yaml` avec htt-log a `yes`
    - Apres, j'ai utilise cette commande:
        - `sudo suricata -r /home/htb-student/pcaps/suspicious.pcap`
        - `cat http.log` et la j'ai trouve le drapeau
    - Voila, c'est fini!

# Suricata Rule Development: #1
- **Rule BreakDown:**
    - `action protocol from_ip port -> to_ip port (msg:"Known malicious behavior, possible X malware infection";
      content:"some thing"; content:"some other thing"; sid:10000001; rev:1;)`

    - `action` >> alert >> log >> pass >> drop >> reject
    - `protocol` >> tcp, udp, icmp, ip, http, tls, smb, or dns.
    - `rule host variables` for **traffic directionality**: $HOME_NET, $EXTERNAL_NET
        - Outbound: `$HOME_NET any -> $EXTERNAL_NET 9090`
        - Inbound: `$EXTERNAL_NET any -> $HOME_NET 8443`
        - Bidirectional: `$EXTERNAL_NET any <> $HOME_NET any`
    - `rule ports:`
        - `alert tcp $HOME_NET any -> $EXTERNAL_NET $UNCOMMON_PORTS`
        - `alert tcp $HOME_NET any -> $EXTERNAL_NET [8443,8080,7001:7002,!8443]`
        - `alert tcp $HOME_NET any -> $EXTERNAL_NET 9443`

    - `flow` >> identifies the originator and responder.
        - `(msg:"Potential HTTP-based attack"; flow:established,to_server; sid:1003;)`
        - `alert udp 10.0.0.0/24 any -> any 53 (msg:"DNS query"; flow:from_client; sid:1002;)`
        - `alert tcp any any -> 192.168.1.0/24 22 (msg:"SSH connection attempt"; flow:to_server; sid:1001;)`

    - `dsize` >> matches using the payload size of the packet
        - `alert http any any -> any any (msg:"Large HTTP response"; dsize:>10000; content:"HTTP/1.1 200 OK"; sid:2003;)`

    - `RULE content:` >> help identify specific network traffic or activities, unique values
        - `content:"User-Agent|3a 20|Go-http-client/1.1|0d 0a|Accept-Encoding|3a 20|gzip";`
            - `|3a 20|` >> *hexadecimal representation of the characters ":"*

    - `nocase` >> avoid case changes

    - `offset` >> specifies where to start the search for bytes
        - `alert tcp any any -> any any (msg:"Detect specific protocol command"; content:"|01 02 03|"; offset:0; depth:5; sid:3003;)`
        - here searches the bytes in payload starting from the `0th` byte
    - `depth` >> specifies a length of certain bytes to be considered for matching.
        - `depth:5` >> look for 5 bytes after offset

    - `content:"/admin"; offset:4; depth:10; distance:20; within:50;`
        - detects the string `/admin` in the TCP payload
        - skips first 4bytes and starts at 5th byte : `offset:4`
        - considers length only 10 bytes `depth:10`
        - `distance:20` >> specifies that subsequent matches of /admin *should not occur* within the next 20 bytes
        - `within:50` >> ensures that the content match occurs within the next 50 bytes *after a previous match.*

- **Example:**
    - `alert http any any -> $HOME_NET any (msg: "ATTACK [PTsecurity] Apache Continuum <= v1.4.2 CMD Injection";
      content: "POST";
      http_method;
      content: "/continuum/saveInstallation.action";
      offset: 0;
      depth: 34;
      http_uri;
      content: "installation.varValue=";
      nocase; http_client_body; pcre: !"/^\$?[\sa-z\\_0-9.-]*(\&|$)/iRP";
      flow: to_server, established;
      sid: 10000048;
      rev: 1;)`

      - Here, a specific rule to detect an attack with its unique patterns
      - **pcre >> Perl Compatible Regular Expressions.**
        -  `pcre: !"/^\$?[\sa-z\\_0-9.-]*(\&|$)/iRP";`
        -  `^` >> marks the start of the line
        -  `\$?` >> checks for an optional dollar sign at the start
        -  `[\sa-z\\_0-9.-]*` >> checks > space,letters a-z, underscore, 0-9 numbers, dot, hyphen,
            - matches zero or more (*) of the characters  in the set
        - `(\&|$)` >> either an ampersand or the end of the line
        - `/iRP` >> inverted match (meaning the rule triggers when the match does not occur)
            -  case insensitive `(i)`, and relative to the buffer position `(RP)`. \

- **How to Create Rules:**
    1. need to identify the *unique elements* in the network traffic >> related to malware
    2. such as: `simple patterns in packet payloads` >> `specific command` `distinctive string`
    3. need to identify *specific behaviours* >> beaconing interval >> certain HTTP response size within a threashold
    4. need to monitor *stateful protocol analysis* >>

## Detection Example #1: Detecting PowerShell Empire
- Powershell Empire >> C2 framework
- Rule:
    - `alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET MALWARE Possible PowerShell Empire Activity Outbound";
      flow:established,to_server; >> looking for established connections where data is flowing to the server.
      content:"GET";
      http_method;
      content:"/";
      http_uri;
      depth:1;
      pcre:"/^(?:login\/process|admin\/get|news)\.php$/RU"; >> looking for URIs that end with login/process.php, admin/get.php, or news.php
      content:"session=";  >> looking for the string "session=" in HTTP Cookie
      http_cookie;
      pcre:"/^(?:[A-Z0-9+/]{4})*(?:[A-Z0-9+/]{2}==|[A-Z0-9+/]{3}=|[A-Z0-9+/]{4})$/CRi";
      content:"Mozilla|2f|5.0|20 28|Windows|20|NT|20|6.1";
      http_user_agent; http_start; content:".php|20|HTTP|2f|1.1|0d 0a|Cookie|3a 20|session=";
      fast_pattern;
      http_header_names;
      content:!"Referer";
      content:!"Cache";
      content:!"Accept";
      sid:2027512;
      rev:1;)`

## Detecting Example #2: Detecting Covenant
- Covenant >> C2 framework
- Rule:
    - `alert tcp any any -> $HOME_NET any (msg:"detected by body";
      content:"<title>Hello World!</title>";
      detection_filter: track by_src, count 4 , seconds 10;
      priority:1;
      sid:3000011;)`

    - `detection_filter: track by_src, count 4, seconds 10`
        - track the source IP address `(by_src)`
        - only trigger an alert if this same detection happens at least 4 times `(count 4)`
        - within a 10-second window `(seconds 10).`

## Detecting Example #3: Detecting Covenant (Using Analytics)
- Rule
    - `alert tcp $HOME_NET any -> any any (msg:"detected by size and counter";
      dsize:312;
      detection_filter: track by_src, count 3 , seconds 10;
      priority:1;
      sid:3000001;)`

## Detecting Example 4: Detecting Sliver:
- Sliver >> C2 framework
- Rule
    - `alert tcp any any -> any any (msg:"Sliver C2 Implant Detected";
      content:"POST";
      pcre:"/\/(php|api|upload|actions|rest|v1|oauth2callback|authenticate|oauth2|oauth|auth|database|db|namespaces)
            (.*?)((login|signin|api|samples|rpc|index|admin|register|sign-up)\.php)\?[a-z_]{1,2}=[a-z0-9]{1,10}/i";
      sid:1000007;
      rev:1;)`

      - PCRE >> identify specific URI patterns

- Rule #2
    - `alert tcp any any -> any any (msg:"Sliver C2 Implant Detected - Cookie";
      content:"Set-Cookie";
      pcre:"/(PHPSESSID|SID|SSID|APISID|csrf-state|AWSALBCORS)\=[a-z0-9]{32}\;/";
      sid:1000003;
      rev:1;)`

## Practical Challenge:
1. In the /home/htb-student directory of this section's target, there is a file called local.rules.
       Within this file, there is a rule with sid 2024217, which is associated with the MS17-010 exploit.
       Additionally, there is a PCAP file named eternalblue.pcap in the /home/htb-student/pcaps directory,
       which contains network traffic related to MS17-010. What is the minimum offset value that can be set to trigger an alert?

    **Solved:**
    - J'ai inspecte ce fichier avec Wireshark
    - J'ai compris que pour trouver l'attaque avec cette regle >> je dois regarder aux premieres
        bytes de TCP Payload >> `5,4,6` >> Le drapeau est l'un d'eux

# Suricata Rule Development: #2 (Encrypted Traffic)
- **Way to inspect Encrypted traffic:**
    - `attention to the elements within SSL/TLS certificates and the JA3 fingerprint.`
    - details >> *the issuer, the issue date, the expiry date, and the subject
                 (containing information about who the certificate is for and the domain name)*

    - `Goal` >> **Suspicious or malicious domains might utilize SSL/TLS certificates with anomalous or unique characteristics**
    - `JA3 Hash` >>  a fingerprinting method that provides a unique representation for each SSL/TLS client.

## Suricata Example 5: Detecting Dridex (TLS Encrypted)
- Dridex >> trojan
- Rule:
    - `alert tls $EXTERNAL_NET any -> $HOME_NET any (msg:"ET MALWARE ABUSE.CH SSL Blacklist Malicious SSL certificate detected (Dridex)";
      flow:established,from_server;
      content:"|16|";
      content:"|0b|";
      within:8;
      byte_test:3,<,1200,0,relative;
      content:"|03 02 01 02 02 09 00|";
      fast_pattern;
      content:"|30 09 06 03 55 04 06 13 02|";
      distance:0; pcre:"/^[A-Z]{2}/R";
      content:"|55 04 07|";
      distance:0;
      content:"|55 04 0a|";
      distance:0;
      pcre:"/^.{2}[A-Z][a-z]{3,}\s(?:[A-Z][a-z]{3,}\s)?(?:[A-Z](?:[A-Za-z]{0,4}?[A-Z]|
           (?:\.[A-Za-z]){1,3})|[A-Z]?[a-z]+|[a-z](?:\.[A-Za-z]){1,3})\.?[01]/Rs";
      content:"|55 04 03|";
      distance:0;
      byte_test:1,>,13,1,relative;
      content:!"www.";
      distance:2;
      within:4;
      pcre:"/^.{2}(?P<CN>(?:(?:\d?[A-Z]?|[A-Z]?\d?)(?:[a-z]{3,20}|[a-z]{3,6}[0-9_][a-z]{3,6})\.){0,2}?(?:\d?[A-Z]?|
            [A-Z]?\d?)[a-z]{3,}(?:[0-9_-][a-z]{3,})?\.(?!com|org|net|tv)[a-z]{2,9})[01].*?(?P=CN)[01]/Rs";
      content:!"|2a 86 48 86 f7 0d 01 09 01|";
      content:!"GoDaddy";
      sid:2023476;
      rev:5;)`

    - *BreakDown:*
        - `content:"|16|"; content:"|0b|"; within:8;` >> hex values 16 and 0b within the first 8 bytes of the payload
            - represent the `handshake message (0x16)` and the `certificate type (0x0b)` in the TLS record.
            -
        - `content:"|03 02 01 02 02 09 00|"; fast_pattern;` >> this specific pattern of bytes in the packet
            -
        - `content:"|30 09 06 03 55 04 06 13 02|"; distance:0; pcre:"/^[A-Z]{2}/R";`
            - checks for the 'countryName' field in the certificate's subject
            - PCRE checks that the value for 'countryName' begins with two uppercase letter
            -
        - `content:"|55 04 07|"; distance:0;`
            - >> checks for the 'localityName' field in the certificate's subject (OID 2.5.4.7).
            -
        - `content:"|55 04 0a|"; distance:0;`
            - checks for the `organizationName` field in the certificate's subject (OID 2.5.4.10).
            -
        - `content:"|55 04 03|"; distance:0; byte_test:1,>,13,1,relative;`
            - checks for the `commonName` field in the certificate's subject (OID 2.5.4.3)
            - byte_test checks that the length of the commonName field is more than 13.

## Suricata Example 6: Detecting Sliver (TLS Encrypted)
- Rule:
     - `alert tls any any -> any any (msg:"Sliver C2 SSL";
       ja3.hash;
       content:"473cd7cb9faa642487833865d516e578";
       sid:1002;
       rev:1;)`

- **JA3 Hash calculation:**
    - `ja3 -a --json /home/htb-student/pcaps/sliverenc.pcap`

## Practical Challenges:
1.  There is a file named trickbot.pcap in the /home/htb-student/pcaps directory,
        which contains network traffic related to a certain variation of the Trickbot malware.
        Enter the precise string that should be specified in the content keyword of the rule
        with sid 100299 within the local.rules file so that an alert is triggered as your answer.

    **Solved:**
    - J'ai d'abbord utilise cette commande pour prendre JA3 hash de ce fichier:
        - `ja3 -a --json /home/htb-student/pcaps/trickbot.pcap`
    - Apres, j'ai teste le `local.rules` et j'ai trouve que `ja3.hash;` et content
    - Pour content, j'ai donne le hash de la premiere commande avec JA3
    - Voila, j'ai obtenu le drapeau












