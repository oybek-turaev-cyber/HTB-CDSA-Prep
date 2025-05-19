# Host Discovery
- `sudo nmap 10.129.29.39/24 -sn -oA tnet | grep for | cut -d" " -f5`
    - `-sn` >> disable ports scanning
    - `-oA` >> output the results in the three formats: `normal`, `XML`, `grepable` with *name* now `tnet`
    - grepping the line with for
    - delimeter by whitespaces and extracting fifth element

# IP Scan
- `nmap -sn -oA my_file -iL hosts.lst | grep for | cut -d" " -f5`
    - `-iL` to specify the file which consists of the hosts

- `nmap 10.23.239.15-20` >> c'est pour range
- `nmap 10.20.239.15 -sn -oA host -PE --packet-trace`
    - `-PE` pour envoyer ICMP request aussi
    - `--packet-trace` pour voir toutes packets
    - `--reason` aussi == peut montre le reason pour un objet specific

# Host & Port Scanning
- Some useful Flags:
    - `-Pn` >> to skip host discovery >> to disable ICMP echo requests
    - `-F` >> fast scan for 100 ports
    - `--top-ports=10` >> top tcp ports
    - `-sT` >> Connect Scan >> full tcp-handshake
    - `-n` >> to disable DNS resolution
    - `--disable-arp-ping`


# Saving Results
- `-oA` >> three outputs:
    - `-oN` >> normal output
    - `-oG` >> greppable output
    - `-oX` >> xml based
- `Convert to HTML from xml`
    - **xsltproc:**  >> `xsltproc host.xml -o target.html`


# Service Enum
- `-sV` >> for service
- `--stats-every=5s` >> montre les resultes par chaque 5 seconds
- `-v` >> verbose mode

- **Banner Grabbing**
    - Nmap primarily looks at the banners of the scanned ports >> prints them
    - *Parfois, Nmap ne peut montre les complete info du Banner*
    - Donc, on utilise `tcpdump` ou `nc` pour montre info que Nmap ne peut pas prendre
        - `nc -nv 10.129.2.48 139` >> il montre des info du Banner `pour le port 139`
        - `sudo tcpdump -i eth0 host 10.29.34.23 and 10.23.32.24`
            - listens on `eth0` and searchers for packets associated with two hosts given

# Nmap Scripting
- `-sC` >> pour default scripts
- `-A` >> pour aggressive mode: OS, service, traceroute, defualt scripts

- Some Script categroies:
    - `auth /  brute   /  dos /  exploit  / vuln / safe / fuzzer / external / malware`
    - `nmap <target> --script vuln` >> par exemple

- `nmap 10.129.2.49 -p 139 --script brute` >> pour le port specifique

# Flags Found
- **First Lab >> Easy:**
    - First, tried with multiple script files for web server: `nmap 10.129.2.49 -p 80 --script vuln`
    - Then, with `vuln` script >> found that >> `/robots.txt` exist as shown vulnerability
    - Thirdly execute: `curl -O 10.129.2.49:80/robots.txt` >> inside the file >> `Evrika: flag`

- **Second Lab >> Medium:**
    - First, I got the clue that UDP port is required for VPN connection
    - Then, I remembered that DNS functions at both ports at `TCP 53 & UDP 53`
    - I see, that `tcp` is filtered by `IPS/IDS`
    - But, when I tried for the `scan UDP 53` port >> I found the `flag`
    - `nmap 10.129.2.47 -sS -sU -p 53 -Pn -n --disable-arp-ping`

- **Third Lab >> Hard:**
    - First, I tried all the options: scripts, -sT, -sA, specific ports
    - But, the ports both TCP 53 and UDP 53 are filtered by the IPS/IDS
    - Then, based on the hint, "new service added", I checked out `tcp 50000` port
    - It was from the Module knowledge: Enumeration Services & Host
    - Then, interestingly this port was filtered by the normal Nmap request
    - I used the trick >> `--source-port 53` >> to request info about `tcp 50000`
    - Voila, it worked >> IPS/IDS allow to access to `50000 port` through `port 53`
    - However, `-sV` banner info from Nmap was cut off, I guess and did not give  much knowledge
    - Then, I used `sudo ncat -nv --source-port 53 10.129.2.49 50000` to get direct access
    - Again, even with `ncat` I used `--source-port 53` without this no access
        - **Some Thoughts:**
            - For `ncat` to use `privileged ports: 0-1024` need **sudo** privileges
            - Ports: 0-1024 >> `privileged ports` >> Linux OS requires special attention on them
            - Without `sudo`, you see error messages
    - Finally, after this connection, I get the `flag` through `ncat`

