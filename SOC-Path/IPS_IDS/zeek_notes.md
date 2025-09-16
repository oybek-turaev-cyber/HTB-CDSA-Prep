# Zeek Funs
- **Usage:**
    - open-source network traffic analyzer
    - tool for troubleshooting network issues
    - highly capable scripting language

    - Modes:
        - Fully passive traffic analysis
        - libpcap interface for packet capture
        - Real-time and offline (e.g., PCAP-based) analysis

    - Key Components:
        - `event engine` >> `script interpreter`
        - **Most of Zeek's events are defined in .bif files located in the  /scripts/base/bif/plugins/ directory**

    - Zeek Logs:
        - conn.log >> dns.log >> http.log >> ftp.log >> smtp.log

    - Compressed Archieve
        - applies `gzip` compression to log files every hour.
        - `gzcat` for printing logs or `zgrep` for searching within logs

## Zeek VS Snort VS Suricata
- Snort/Suricata = rule-based, need config and rule files.
-
- Zeek = script-based, starts analyzing traffic automatically with default behaviors — no rules needed to get started.

## Zeek Example 1: Detecting Beaconing Malware
- Command:
    - `/usr/local/zeek/bin/zeek -C -r /home/htb-student/pcaps/psempire.pcap`
        - `-C` >> ignore checksums

## Intrusion Detection With Zeek Example 2: Detecting DNS Exfiltration
- Command:
    - `/usr/local/zeek/bin/zeek -C -r /home/htb-student/pcaps/dnsexfil.pcapng`
    - check dns.log
    -
- zeek-cut
    - `cat dns.log | /usr/local/zeek/bin/zeek-cut query | cut -d . -f1-7`
    - output clearing

## Intrusion Detection With Zeek Example 3: Detecting TLS Exfiltration
- Command:
    - `/usr/local/zeek/bin/zeek -C -r /home/htb-student/pcaps/tlsexfil.pcap`
    - check >> conn.log
 - narrow things down by using `zeek-cut`
    - `cat conn.log | /usr/local/zeek/bin/zeek-cut id.orig_h id.resp_h orig_bytes | sort | grep -v -e '^$' | grep -v '-' | datamash -g 1,2 sum 3
      | sort -k 3 -rn | head -10`

    - extracting the `id.orig_h` (originating host), `id.resp_h` (responding host),
      `orig_bytes` (number of bytes sent by the originating host) fields.
    - `grep -v -e '^$'` >> filters out any empty lines `(-v)` inverts the selection
      `-e` option for regex '^$'

    - `grep -v '-'`: This command filters out lines containing a `dash -`
    - `datamash -g 1,2 sum 3` >>
        - **datamash** >> datamash is a command-line tool that performs basic numeric, textual, and statistical operations
        - `-g 1,2` option groups the output by the first two fields
        - `sum 3` computes the sum of the third field
    - `sort -k 3 -rn` >>  sorts the output of the previous command in descending order `(-r)`
      based on the numerical value `(-n)` of the `third field (-k 3)` >> orig_bytes

    - `head -n 10` == `head -10`
## Intrusion Detection With Zeek Example 4: Detecting PsExec
- PsExec >> used when they carry out remote code execution attacks.

- Attack Scenario:
    - *an attacker transfers the binary file PSEXESVC.exe to a target machine using the ADMIN$ share,
       a special shared folder used in Windows networks, via the SMB (Server Message Block) protocol.*
    -
    - *Following this, the attacker remotely launches this file as a temporary service by utilizing
        the IPC$ share, another special shared resource that enables Inter-Process Communication.*

    - **dentify SMB transfers and the typical use of PsExec using Zeek's:
      smb_files.log, dce_rpc.log, and smb_mapping.log as follows.**

- Command:
    - ` /usr/local/zeek/bin/zeek -C -r /home/htb-student/pcaps/psexec_add_user.pcap`
    - check `smb_files.log`, `dce_rpc.log`, `smb_mapping.log`
    -

## Practical Challenges:
1. There is a file named printnightmare.pcap in the /home/htb-student/pcaps directory, which contains network traffic related
       to the PrintNightmare (https://labs.jumpsec.com/printnightmare-network-analysis/) vulnerability.
       Enter the zeek log that can help us identify the suspicious spooler functions as your answer

    **Solved:**
    - J'ai utilise cette commande: ` /usr/local/zeek/bin/zeek -C -r /home/htb-student/pcaps/printnightmare.pcap`
    - Apres, j'ai cherche les informations pour trouver `spooler` et voila
    - J'ai obtenu le drapeau

2. There is a file named revilkaseya.pcap in the /home/htb-student/pcaps directory, which contains network traffic related
       to the REvil ransomware Kaseya supply chain attack.
       Enter the total number of bytes that the victim has transmitted to the IP address 178.23.155.240 as your answer.

    **Solved:**
    - J'ai utilise cette commande: `/usr/local/zeek/bin/zeek -C -r /home/htb-student/pcaps/revilkaseya.pcap`
    - Apres, pour trouver les informations necessaires, j'ai utilise cette commande:
        - `cat conn.log | /usr/local/zeek/bin/zeek-cut id.orig_h id.resp_h orig_bytes | sort | grep -v -e '^$' | grep -v '-'
          | datamash -g 1,2 sum 3 | sort -k 3 -rn | head -10`
    - C'est une commande geniale pour trouver `bytes`
    - Voila, j'ai obetenu le drapeau












