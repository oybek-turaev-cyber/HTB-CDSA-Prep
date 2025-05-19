# Networking

# Network Types
- `WAN`  >> Wide Area Network   >> Internet
- `LAN`  >> Local Area Network  >> Internal Network (Home, Office)
- `WLAN` >> Wireless LAN        >> Internal Network accessible over Wi-Fi
- `VPN`  >> Virtual Private Net >> Connects multiple network sites to one `LAN`

- **LAN / WLAN**
    - IP Addresses assigned: `RFC 1918, 10.0.0.0/8; 172.16.0.0/12; 192.168.0.0/16`
    - `How LAN is built`:
        1. Desktops >> Computers: `Connect Cables` (Ethernet)
        2. Bring all the cables from the desktops to the `Central Room`
        3. Connect those desktop cables to `Switch`
        4. Create `Ip Scheme`: e.g: `192.168.1.0/24` >> `Subnet`: `
            - 3 octets(24 bits)` were reserved for the network, 1 octet`(8 bit)` for the network devices:
            - Number of devices: `2^8 = 256;` 256-2(reserved addresses) = `254` devices can be created
            - *Reserved Addresses*:
                - The `network address`(`192.168.1.0`): to identify the network itself and cannot be assigned to a device.
                - The `broadcast address`(`192.168.1.255`): to send messages to all devices within the subnet.
        5. `Subnet Mask`: `255.255.255.0` >> here `3 octets` identify `the network` part >>
            - 1 octet to `identify the device` in the network
            - the devices `in the same network` can `talk to each other`
        6. `Router`: Gateway to reach to the `Internet` >> Switch connects to it
            - It has a IP address within the subnet `Default Gateway`: `192.168.1.1` (*Internet Access*)
            - It will be known to each desktops in the subnet network
        7.

- **VPN**
    - Goal: to make a user feel that he is plugged in different network
    - `Site-To-Site VPN` >> Both client and server are *Network Devices*: `Routers` or `Firewalls` >>
        share entire network ranges
        - To connect company networks over the internet: multiple locations to communicate over the
            internet as if they were local
    - `Remote Access VPN` >> client's computer creates a virtual interface >> that interface behaves
        as if it's on client's network
        - For example, `OpenVPN` >> makes TUN Adapter
        - `Split-Tunnel VPN` >> it's directed to a specific network; is triggered when there is a
            request for this network: 10.10.10.0/24 for example
            - the rest of the internet connection (browsing, watching) goes through normal way not
            with VPN
    - `SSL VPN`:
        - Works in browser >>
        - Provides a connection to `remote applications` or `entire system` through the web page
        - Streams applications or desktops >> like streaming video
        - Uses SSL/TLS technology >> HTTPS for connections
        - For example: HTB Pwnbox >> Linux Machine >> I use through web browser >> mouse, keyboard
            integrated
- **WAN**
    - To connect two offices (two `LANs`):
        - ISP provides:
            - `Leased Lines`: A dedicated, private connection that offers guaranteed bandwidth.
            - `MPLS` (Multiprotocol Label Switching): A more sophisticated technology that creates virtual private circuits between sites.
            - `Site-To-Site VPN`: Using the public internet as the underlying transport but creating
                an encrypted tunnel between the two office routers.
        - `Routers`: Routers in each office will be configured to connect to another office

- **Firewall VS ACL**
    - `ACL` >> for `traffic filtering` on `network devices`: routers & switches
        - `Stateless` >> checks the packets without considering the context of previous packets in a
            connection
        - `Focus` >> basis Permit and Deny actions
        - Basic Logging
        - Lower overhead
    - `Firewall` >> Designed for `network security`
        - `Security barrier`: e,g: between Internet & Internal Network
        - `Statefull`: considers the previous packets in a connections >> tracks the established
            connections
            - remember initial handshake >> only allow return traffic that belongs to established,
                legitimate session.
            - kinda better filters inbound traffic
        - Provides: NAT >> Network Address Translation
        - Stateful Packet Inspection
        - IPS / VPN capabilities / content filtering
        - Comprehensive Logging
        - Higher overhead

- **Router**
    - gateway between Internal Network and Internet
    - NAT capability >> private IPs to a single public IP
        - for private IPs to connect to the Internet >> it assigns ports and creates NAT Table to
            track them >> to redirect the return traffic coming from the internet
    - Assign private addresses
    - Handles: Internet Connection >> Routing to the Internet

- **Firewall VS Router**
    - `Router` >> *connectivity* >> routing the traffic & routing tables
    - `Firewall` >> *security* >> check the traffic incoming & outgoing
        - `NGFW` >> these come with Router capabilities >> provide routing traffic
    - `Home Wi-Fi Router` >> `Combined Device`
        - *Router* >> directs the traffic between internet and internal network
        - `Firewall` >> filters incoming and outgoing traffic
        - *Wireless access point* >> allow devices to connect wirelessly
        - `DHCP server` >> assigns private IPs to devices in internal network
        - *NAT device* >> enable multiple devices to share a single Public IP

- **PAN / WPAN**
    - `Wireless Personal Area Network`
        - shorter distance
        - Bluetooth or Wireless USB devices
        - WPAN via Bluetooth is called *Piconet*
        - IoT devices use this commonly
            - `Protocols`: Z-Wave; Insteon; ZigBee >> for smart homes & home automation

# Proxy
- `Middleman`:
    - The request to the internet goes through it
    - It can see the data
    - It may modify the data
    - It sends to the Internet >> also receives
    - Returns to you
    - It may send you gifts: scripts, see your data
- `Purpose`:
    - It filters the content: blocks some websites/ content filtering
    - It can check malicious content as well
    - Best to control what website / content is allowed for the company people
- `Examples`:
    - HTTPS Proxy
        - only for web traffic
        - enables HTTPS, secure tunnel for this traffic
- *HTTPS Inspection in Proxy*:
    1. `User Browser` reaches out to the `Proxy` with the destination website info
    2. Proxy reaches out to the `destination website` with its own IP address
    3. Proxy establishes a `secure connection` with Client Browser
        - It `generates a certificate` (using dynamic or pre-generated certificates)
        - It *signs* this newly-generated certificate with *Root CA*.
        - This Root CA is listed in Client's Browser as a `trusted source`
        - It encrypts the data with this certificate to send to the Client Browser
        - The client sees that the certificate is signed by Root CA as shown in his list as trusted
        - With Client, connection is established
    4. Now, when Client Browser communicates with Proxy, uses `Proxy's certificate` so that proxy can
       read the data and Proxy can send the data to Client using its private key
    5. Now, Proxy can reach out to the destination website on behalf of the user and plays in the
       middle, decrypts it and sends to the client
    6. This process is handled like this.


# TCP/IP VS OSI Model
- TCP/IP Model:
    - Communication protocol >> allows hosts to connect to the internet
    - Practical-approach based Model >> In use in real world
    - When you sends an email >> TCP/IP model is used >>
    - using protocols within the TCP/IP suite (like HTTP, SMTP, TCP, IP, etc.) to handle the communication,
    - Not the seven distinct layers of the OSI model

- OSI Model:
    - Newer version
    - Theoretical
    - Easier To Understand & To Troubleshoot
    - Very Detailed Model
    -
-

# OSI Model
- How Layers Work:
    - Each layer completes its assigned job.
    - `Sender`: starts from the Application till `Physical`
    - `Receiver`: starts from the Physical till `Application`
    - **PDU**: `Protocol Data Unit` >> In each layer data is exchanged in different format
    - Each Layer adds: `header` to `PDU` from the upper layer, to control and identify the packets
        - This process is **Encapsulation**
        - Header & Data form PDU for the next layer
        - The process continues till Physical Layer or Network Layer, where data is transmitted to
            the receiver

- Layers:            *Protocols*                  *PDU*
    7. Application:  FTP, HTTP              >> Data                   >> Write a letter
    6. Presentation: JPG, PNG, SSL, TSL     >> Data                   >> Translate it
    5. Session:      NetBios                >> Data                   >> Format it nicely
    4. Transport:    TCP, UDP               >> Segment/Datagram       >> Establish a connection
    3. Network:      Router, L3 Switch      >> Packet                 >> Find the best route
    2. Data-Link:    Switch, Bridge         >> Frame                  >> Make sure data arrives
    1. Physical:     Network Card           >> Bit                    >> Send the electrical signal

# TCP/IP Model (Internet Protocol Suite)
- Layered reference model >> TCP/IP >> a generic term for many network protocols
- Responsible for `switching` and `transport of data packets` on the internet
- The internet is entirely based on `TCP/IP` protocol family: ICMP, UDP are also part of this family

- Layers:
    4. Application
    3. Transport
    2. Internet
    1. Link

# IP Addresses
-`IPv4` or `IPv6` >> made up of *network address* & *host address*
    - Router assigns        `host address`
    - Network Admin assigns `network address`

- **IPv4**
    - 4 bytes >> 32-bits >> 8-bit groups (octets) >> 0-255
    - 0111 1111.0000 0000.0000 0000.0000 0001 == 127.0.0.1

- **Network Classes**
    - A Class == CIDR /8

`Class`| `Network Add` | `1st Add` |    `Last Add`   | `SubnetMask` | `CIDR` | `Subnets` | `IPs`
- *A*    1.0.0.0      1.0.0.1   127.255.255.255  255.0.0.0     \8     127      16,777,214 + 2

- *B*    128.0.0.0    128.0.0.1 191.255.255.255  255.255.0.0   \16   16,384    65,534 + 2

- *C*    192.0.0.0    192.0.0.1 192.255.255.255  255.255.255.0  \24  2,097,152  254 + 2

- *D*    224.0.0.0    224.0.0.1 239.255.255.255  Multicast     Multicast     Multicast

- *E*    240.0.0.0    240.0.0.1 255.255.255.255  reserved      reserved       reserved

- **Broadcast Address**
    - Broadcast is to communicate with all hosts in the network `without knowing their individual`
        IPv4 address
    - Sends the packets to all hosts
    - DHCP uses this address to communicate with hosts
    - The last IPv4 address in the network

- **Network Address**
    - Network address help to routine the data packet to what network
    - If network address is same, data packet stays in this network and be routed
    - If network address is different from the current one, data packet is routed to another subnet
    - It happens via `Default Gateway` >> it routes to another subnet network

- **Binary Representation**
    - `192.0.1.2` >> 192(1st Octet) >> 0(2nd Octet) >> 1 (3rd Octet) >> 2(4th Octet)
        - 192 == 1100  0001
            -   128 + 64 + 0 + 0 + 0 + 0 + 0 + 0 = 192
        - 0 == 0000 0000
        - 1 == 0000 0001
        - 2 == 0000 0010

- **CIDR (Classless Inter-Domain Routing)**
    - CIDR Suffix `\24, \16, \8`  >> shows how many bits for network part


# Subnetting

- Given: CIDR `10.200.20.0/27`
    - **Find its SubnetMask**:
        - Okay, 27 bits are given for network: 1111 1111.1111 1111.1111 1111.1110 0000 =
            255.255.255.224(128+64+32)
        - Then, 32 bits - 27 = 5 bits for hosts = 2^5 = 32 hosts
        - What is left for hosts: .1110 0000 = 16+8+4+2+1 = 31 (the last host: broadcast)
        - `10.200.20.0` >> Network address >> `10.200.20.31` Broadcast address
        - `10.200.20.1-30` *included usable IPv4 addresses for devices in this subnet*
    - **Divide into 4 smaller subnets**
        - 4: 2^2 = the power is 2 = that's why 2 bits we add for subnet
        - 27 + 2 = `29` bits for networking
        - Then, to create 4 individual subnets: we first calculate the devices:
        - `1111 1111.1111 1111.1111 1111.1111 1`000 = 3 bits for hosts >> 2^3 = 8 devices
        -
        - we know that `8 devices` would be for each subnets, we add `8` for `Network address`
        -
        1. `1st Subnet`: `10.200.20.0`(Net IP)  >> `10.200.20.1-6` (usable IPs) >> `10.200.20.7` (Broad IP)
        2. `2nd Subnet`: `10.200.20.8`(Net IP)  >> `10.200.20.9-14` (usable IPs) >> `10.200.20.15` (Broad IP)
        3. `3rd Subnet`: `10.200.20.16`(Net IP) >> `10.200.20.17-22` (usable IPs) >> `10.200.20.23` (Broad IP)
        4. `4th Subnet`: `10.200.20.24`(Net IP) >> `10.200.20.25-30` (usable IPs) >> `10.200.20.31` (Broad IP)

# MAC Addreses
- ARP >> used by devices when they are on `the same local network` LAN
    - If device is in the different network, then ARP is used only to find the `default gateway MAC`
    - Then, default gateway (router) handles where to send

# TCP vs UDP
- All communications are built upon using `TCP` or `UDP`

- **TCP:**
    - connection-oriented >> establishes the virtual connection before transmitting the data
- **UDP:**
    - connectionless >> does not establish a virtual connection before transmitting the data
    - video streaming >> YouTube >> Phone Calls >> using UDP

- **ICMP:**
    - To report the `errors` and to show the `status information`
    - Using `Time-To-Live` >> each time an ICMP packets passes through the `router`, the router
        decrements the `TTL` value by 1.
    - The goal of `TTL` is to `prevent the packet` from `circulating indefinitely` on the network in
        case of routing loops
    - TTL >> limits the packet's lifetime as it travels through the network.
    - `By knowing TTL` >> can `guess OS`: `TTL 128` >> Windows; `TTL 64` is MacOS/Linux; `TTL 255` is Solaris
    - These can be changed by the user so the chance is 50/50 :) hahahah

# Wireless Networks
- Uses `RF (Radio Frequency)` to transmit data between devices
-
- Encryption Protocols:
    - WPA >> Wi-Fi Protected Access
        - uses 128-bit AES
        - authentication servers (TACACS+ or Radius)

- Authentication Protocols
    - LEAP & PEAP (over TLS)
    - Both are based on the EAP >> Extensible Authentication Protocol
    - `LEAP` >> uses the `the same key` for both `authentication and encryption`
    - `PEAP` >> uses TLS (digital certificate) and also encrypted tunnel to protect the authen proc

- In a wireless network, WAP(wireless access point) sends an authentication request to TACACS+server
- `Entire request packet will be encrypted`
- **TACACS+**:
    - protocol used to authenticate & authorize users
    - to access network devices: routers / switches
    - TACACS uses >> TLS or IPSec for encrypting the authentication request

- `Disassociation Attack` >> to disconnect the users from WAP

- **Wireless Hardening:**
    - Disable Broadcasting
    - Wi-Fi Protected Access WPA
    - MAC Filtering
    - Deploy EAP-TLS

# VPN
- `IPSec` >> network security protocol
    - uses two protocols:
        - `AH` (Authentication Header) >> integrity & authenticity
        - `ESP` (Encapsulating Security Payload) >> confidentiality (encryption) & optional authen
    - *two modes*:
        - `Transport Mode` >> encrypts and authenticate the `data payload` but `not IP header`
        - `Tunnel Mode` >> encrypts and authenticates `entire IP packet`
            - This used to create a VPN Tunnel between two networks

    - To build IPsec VPN traffic, we need these protocols:
        - `IP` >> `Port: UDP/50,51` >> primary protocol to provide foundation for all internet commu
        - `IKE` (Internet Key Exchange) >> `UDP/500`
            - establish & maintain secure communication between VPN client and VPN server
            - key exchange algorithm based on Diffie-Hellman
            - create shared secret keys >> to encrypt & decrypt the VPN traffic
        - `ESP`>> `UDP/4500`

- `PPTP` >> Point-To-Point Tunnelling Protocol
    - creates a VPN tunnel between VPN client & VPN Server
    - Is Not Secure:
        - Due to the  Authentication method: `MSCHAPv2` >> employs the outdated `DES encryption`

# VLAN
- Is built on network adapter `VLAN Tagging`
- On top of `eth0` >> we can create different `VLAN with ID`
    - Marketing >> VLAN ID 10 >> 192.168.1.0/24
    - Services  >> VLAN ID 20 >> 192.168.2.0/24
    - Finance   >> VLAN ID 30 >> 192.168.3.0/24

# Authentication Protocols
- For `Wireless Clients`        >>     to authenticate >> `PEAP` / `EAP-TLS` can be used
- For `Physical Connections`    >>     to authenticate >> `SSH` / `HTTPS`

# TCP / UDP
- `TCP` >> for important data >> web pages & emails
- `UDP` >> real-time data >> streaming & online gaming

- `IP Packet` >> data to send from one comp to another
    - `Packet`: Header & Payload Data

- **ping** >> `ping -c 1 -R 10.200.20.2`
    - `-R` >> *Record-route* field to see the IP addresses of devices the packet goes through
