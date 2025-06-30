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












