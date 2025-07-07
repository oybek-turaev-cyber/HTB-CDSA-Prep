# Snort Funs
- **Usage:**
    - IDS >> IPS

    - Modes:
        - Inline IDS/IPS
        - Passive IDS
        - Network-Based IDS
        - Host-Based IDS
    - Key components:
        - `Preprocessor, Detection Engine, Logging and Alerting System`

    - Configuration file >> `snort.lua`
        - `sudo more /root/snorty/etc/snort/snort.lua`

    - `snort -c /root/snorty/etc/snort/snort.lua --daq-dir /usr/local/lib/daq`
        - `-c` specifies config file
        - `--daq-dir /usr/local/lib/daq` >> where Snort can find necessary libraries of DAQ
        - DAQ >> Data Acquisition Library >>
            - its job: *at a high-level, it's an abstraction layer used by modules to communicate with both hardware and software network data sources.*


- **Snort Inputs:**
    - Offline:
        - `sudo snort -c /root/snorty/etc/snort/snort.lua --daq-dir /usr/local/lib/daq -r /home/htb-student/pcaps/icmp.pcap`

    - Live:
        - `sudo snort -c /root/snorty/etc/snort/snort.lua --daq-dir /usr/local/lib/daq -i ens160`

- **Snort Rules:**
    - *It's possible to place rules (for example, local.rules residing at /home/htb-student) directly
     within the snort.lua configuration file using the ips module as follows.*

     `ips =
     {
        -- use this to enable decoder and inspector alerts
        --enable_builtin_rules = true,

        -- use include for rules files; be sure to set your path
        -- note that rules files can include other rules files
        -- (see also related path vars at the top of snort_defaults.lua)

        { variables = default_variables, include = '/home/htb-student/local.rules' }
     }`

    - **Then, the "included" rules will be automatically loaded.**
    - For a single rules file, we can use the `-R` option followed by the path to the rules file.
    - To include an entire directory of rules files, we can use the `--rule-path` option followed by the path to the rules directory

- **Snort Outputs:**
    - It gives different statistics info
    - When rules are configured >> **enable alerting (using the -A option)**

    - `-A cmg` >> This option combines `-A fast -d -e` and displays alert information along with packet headers and payload.
    - `-A u2` >> equivalent to `-A unified2` and logs events and triggering packets *in a binary file*

    - Commands:
        - `sudo snort -c /root/snorty/etc/snort/snort.lua --daq-dir /usr/local/lib/daq -r /home/htb-student/pcaps/icmp.pcap -A cmg`
        -
        - `sudo snort -c /root/snorty/etc/snort/snort.lua --daq-dir /usr/local/lib/daq -r /home/htb-student/pcaps/icmp.pcap
          -R /home/htb-student/local.rules -A cmg`
            - config file is specified

- **Practical Challenges:**
    1. There is a file named wannamine.pcap in the /home/htb-student/pcaps directory.
       Run Snort on this PCAP file and enter how many times the rule with sid 1000001 was triggered as your answer.

    - **Solved:**
        - J'ai utilise cette commande de Snort:
            - `sudo snort -c /root/snorty/etc/snort/snort.lua --daq-dir /usr/local/lib/daq -r /home/htb-student/pcaps/wannamine.pcap -A cmg`
        - Apres, j'ai cherche le truc dans le fichier local.rules: precisement >> avec le sid: 1000001
        - J'ai compris que j'ai eu besoin le nombre des packets de icmp
        - Voila, j'ai obtenu le drapeau


# Snort Rule Development
## Snort Example 1: Detecting Ursnif (Inefficiently)
- Rule
    - `alert tcp any any -> any any (msg:"Possible Ursnif C2 Activity";
      flow:established,to_server;
      content:"/images/", depth 12;
      content:"_2F";  >> string specifique
      content:"_2B";  >> string specifique
      content:"User-Agent|3a 20|Mozilla/4.0 (compatible|3b| MSIE 8.0|3b| Windows NT";
      content:!"Accept";
      content:!"Cookie|3a|";
      content:!"Referer|3a|";
      sid:1000002;
      rev:1;)`

    - *The |3a 20| and |3b| in the rule are hexadecimal representations of the : and ; characters respectively.*

## Snort Example 2: Detecting Cerber
- Rule
    - `alert udp $HOME_NET any -> $EXTERNAL_NET any (msg:"Possible Cerber Check-in";
      dsize:9;
      content:"hi", depth 2, fast_pattern;
      pcre:"/^[af0-9]{7}$/R";
      detection_filter:track by_src, count 1, seconds 60;
      sid:2816763;
      rev:4;)`

    - `content:"hi", depth 2, fast_pattern;` >> checks the payload's first 2 bytes for the string `hi`.
    - The `fast_pattern` modifier makes the pattern matcher search for **this pattern before any others in the rule**,
      optimizing the rule's performance.

## Snort Example 3: Detecting Patchwork
- Rule
    - `alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"OISF TROJAN Targeted AutoIt FileStealer/Downloader CnC Beacon";
      flow:established,to_server;
      http_method; content:"POST";
      http_uri; content:".php?profile=";
      http_client_body;
      content:"ddager=", depth 7;
      http_client_body;
      content:"&r1=", distance 0;
      http_header;
      content:!"Accept";
      http_header;
      content:!"Referer|3a|";
      sid:10000006;
      rev:1;)`

    - `content:"ddager=", depth 7;` >> looking for the string ddager= within the first 7 bytes of the body.

## Snort Example 4: Detecting Patchwork (SSL)
- Rule
    - `alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"Patchwork SSL Cert Detected";
      flow:established,from_server;
      content:"|55 04 03|";
      content:"|08|toigetgf", distance 1, within 9;
      classtype:trojan-activity;
      sid:10000008;
      rev:1;)`

    - `content:"|55 04 03|"` >> These hex values represent the ASN.1 (Abstract Syntax Notation One) tag
      for the `"common name"` field in an `X.509 certificate`

## Practical Challenges:
     1.  There is a file named log4shell.pcap in the /home/htb-student/pcaps directory,
         which contains network traffic related to log4shell exploitation attempts,
        where the payload is embedded within the user agent.
        Enter the keyword that should be specified right before the content keyword
        of the rule with sid 10000098 within the local.rules file so that an alert is triggered as your answer.

    **Solved:**
    - J'ai utilise mon cerveau >> j'ai analyse local.rules avec sid donne et
    - Apres, j'ai compris que j'ai eu besoin de `keyword` connecte avec `http`
    - Voila, j'ai obtenu le drapeau connecte avec header















































