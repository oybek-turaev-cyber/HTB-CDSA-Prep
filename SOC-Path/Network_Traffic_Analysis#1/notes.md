# Network Traffic Analysis
- **Key Functions**
    - Collecting real-time traffic
    - Setting a baseline
    - Identifying and Analyzing traffic
    - Detecting malware on wire

- **Common Tools**
    - `Tshark` >> command-line variant of Wireshark
    - `NGrep` >> pattern-matching tool >> works with network packets
    - `tcpick` >> command-line packet sniffer >> specialized in tracking and reassembling TCP Streams\
    - `Network Taps` >> Taps **Gigamon, Niagra-taps** >> devices >> capable of taking copies of network traffic
        and sending them to another place for analysis
    - `Networking Span Ports` >> Span Ports >> way to copy frames from Layer 2 or 3 Networking
        devices >> then send them to a collection point. Often >> a port is mirrored

- **BPF Syntax**
    -  Berkeley Packet Filter >> syntax used often for the tools in NTA
    -  BPF is a technology that enables `a raw interface to read and write` from the `Data-Link layer`
    -  we care for BPF because of the filtering and decoding abilities

- **Network Traffic Analysis LifeCycle**
    1. Ingest Traffic
    2. Reduce Noise by Filtering
    3. Analyze and Explore
    4. Detect and Alert
    5. Fix & Monitor

# Networking Primer >> Layers 1-4
- **OSI VS TCP/IP**
    - 7 layers VS 4 layers
    - (Application + Presentation + Session) == Application

- **NetBIOS**
    - *enables communication between computers and devices within a local area network (LAN).
    - It provides services related to the session layer of the OSI model.
    - allows applications on separate computers to communicate over a LAN.*

- **PDU** >> Protocol Data Units
    - Each Layer in OSI or TCP/IP Model >> has specific PDU type

-     **OSI                         >>     TCP/IP        >>       PDU**
7. Application  (FTP, HTTP)       >>
6. Presentation (JPG,PNG,TLS)     >>    4. Application >>       Data
5. Session      (NetBIOS)         >>
4. Transport    (TCP, UDP)        >>    3. Transport   >>       Segment/Datagram
3. Network      (Router,L3Switch) >>    2. Internet    >>       Packet
2. Data-Link    (Switch, Bridge)  >>                   >>       Frame
1. Physical     (Network Card)    >>    1. Link        >>       Bit


- **TCP VS UDP**
    - Connection-Oriented VS Connectionles (Fire, Forget)
    - UDP does not care the destination is listening
    - **Data Delivery** >> stream-based conversations VS packet by packet

- **UDP**
    - **The worst thing that happens if a DNS request is dropped is that it is reissued. No harm, no foul.**
    - since another packet will be resissued >> UDP >> packet by packet
    - **UDP >> it is a single packet, with no response or acknowledgment**

- **TCP**
    - Three-Hand-Shake Start >> Client (SYN) > Server (ACK, SYN) > Client (ACK)
    - Finish                 >> Client (FIN, ACK) > Server (FIN, ACK) > Client (ACK)

# Networking Primer >> Layers 5-7
- **HTTP**
    - stateless Application Layer protocol since 1990
    - HTTP enables the transfer of data in clear text between a client and server over TCP
    - The client send HTTP request to server asking for a resource
    - A session is established, and the server responds with the requested media (HTML, images, hyperlinks, video).
    - HTTP utilizes ports 80 or 8000 over TCP

    **To perform operations such as fetching webpages, requesting items for download, or posting updates**
    **We need METHODS**
    - `HEAD`   >> *required* >> requests a response from the server similar to a `Get request` except that the message body is not included.
       It is a great way to acquire more information about the server and its operational status.
    - `GET`    >> *required* >> requests information and content from the server.
    - `POST`   >> *optional* >>  POST will create child entities at the provided URI
            submitting a message to a Facebook post or website forum is a POST action
    - `PUT`    >> *optional* >> PUT will create or update an object at the URI supplied
    - `CONNECT` >> *optional* >> Connect is reserved for use with` Proxies` or other security devices like `firewalls`
                Connect allows for tunneling over HTTP. (SSL tunnels)

    *As a requirement by the standard, GET and HEAD must always work and exist with standard HTTP implementations*

- **HTTPS**
    - HTTP over TLS >> 443 or 8443

- **FTP**
    - Application Layer protocol  >> enables quick data transfer between computing devices
    - command-line >> web-browser >> GUI version >> **FileZilla**
    - `Port 20` is used for `data transfer`, while `port 21` is utilized for `issuing commands controlling the FTP session`
    - active VS passive modes
        - Active is the default >> the server listens for a control command `PORT` from the client >> **stating what port to use for data transfer**
        - Passive enables us to access FTP servers `located behind firewalls` or a `NAT-enabled link` that **makes direct TCP connections impossible**
    *the client would send the PASV command and wait for a response from the server informing the client what IP and port to utilize for the data transfer       channel connection.*

    - FTP Commands >> **USER,PASS,PORT,PASV,LIST,CWD,QUIT,RETR,SIZE,PWD**

- **SMB**
    - enables `sharing resources` between `hosts over common networking architectures`
    - SMB is a `connection-oriented protocol` that requires user authentication from the host to the resource
    - In the past, SMB utilized NetBIOS as its transport mechanism over UDP ports 137 and 138
    - SMB now supports direct `TCP transport over port 445`, `NetBIOS over TCP port 139`
    - **SMB provides us easy and convenient access to resources like printers, shared drives, authentication servers, and more**
    - As it uses TCP transport mechanism >> it uses functions like three-hand-shake


# Analysis Process
- **Key Practices**
    - keep an eye on malicious traffic such as unauthorized remote communications from the internet over RDP, SSH, or Telnet
    - We need to **set a baseline**
    - Traffic Capture >> Active vs Passive

- **Mirrored Port**
     - *A switch or router network interface configured to copy data from other sources to that specific interface,
       along with the capability to place your NIC into promiscuous mode*

# Analysis in Practice

- **Prescriptive Analysis**

    1. What is the issue?
        - Suspected breach? Networking issue?

    2. Define our scope and the goal. (what are we looking for? which time period?)
        - Target: multiple hosts potentially downloading a malicious file from bad.example.com
        - When: within the last 48 hours + 2 hours from now.
        - Supporting info: filenames/types 'superbad.exe' 'new-crypto-miner.exe'

    3. Define our target(s) (net / host(s) / protocol)

    4. Capture network traffic
        - plug into a link with access to the 192.168.100.0/24 network to capture live traffic to try and grab one of the executables in transfer.

    5. Identification of required network traffic components (filtering)
        - filter out any traffic not needed for this investigation to include
        - any traffic that matches our common baseline and keep anything relevant to the scope
        - **HTTP and FTP from the subnet, anything transferring or containing a GET request for the suspected executable files**

    6. An understanding of captured network traffic
        - time to dig for our targets—filter on things like `ftp-data` to find any files transferred
        - filter on `http.request.method == "GET"`

    7. Note-taking and mind mapping of the found results.
        - Annotating everything we do, see, or find throughout the investigation is crucial. Ensure we are taking ample notes,
        - Timeframes we captured traffic during.
        - Suspicious hosts within the network

    8. Summary of the analysis (what did we find?)
        - Finally, summarize what has been found, explaining the relevant details so that superiors can make an informed decision
          to quarantine the affected hosts

## Key Components of an Effective Analysis
1. Know your Environment >> baselines >> what's normal and what's not
2. Placement is Key >> the placement of our host for capturing traffic at right place is a critical thing
3. Persistence >> keep an eye >> Attacker is smart & patient

## Analysis Approach >> Super-Duper Guidelines
- **Start with standard protocols first**
- Most attacks will come from the internet, so it has to access the internal net somehow
- **HTTP/S, FTP, E-mail, and basic TCP and UDP traffic will be the most common things seen coming from the world**
- `Start at these and clear out anything that is not necessary to the investigation`
- After these, check standard protocols that allow for communications between networks, such as **SSH, RDP, or Telnet**
    - Question Yourself: Does our organization's security plan and implementations allow for RDP sessions?
    - that are initiated outside the enterprise?
    - What about the use of Telnet?

- *Look for patterns.*
    - specific host or set of hosts checking in with something on the internet at the same time daily?
    - a typical Command and Control profile setup that can easily be spotted by looking for patterns
- Check anything **host to host** within our network
    - In standard setup, user's hosts will rarely talk to each other
    - So be suspicious of any traffic that appears like this

- *Look for unique events.*
    - a host who usually visits a specific site ten times a day
    - A random port only being bound once or twice on a host is also of note.
    - like C2 callbacks, someone opening a port to do something non-standard, or an application showing abnormal behavior

- **Don't be afraid to ask for help**
    - Having a second set of eyes on the data can be a huge help in spotting stuff that may get glossed over.


# TCPDump
- available in all Unix-like systems
- **Commands:**
    - `which tcpdump` >> pour verifier si il est la

    **Switches:**
    - `D` >> to display available interfaces
    - `i` >> to specify the interface
    - `n` >> to disable naming resolution
    - `e` >> to grab ethernet header along with upper-layer data
    - `X` >> to show packet content in HEX and ASCII
    - `XX` >> equal to ==`Xe` >>
    - `v, vv, vvv` >> to show verbosity
    - `c` >> to grab the specific number of packets then quit
    - `s` >> to define how much of a packet to grab
    - `S` >> to change relative sequence numbers to absolute sequence numbers
    - `q` >> to print the less protocol info
    - `r file.pcap` >> to read from the file
    - `w file.pcap` >> to write to the file

    **Absolute Sequence Numbers VS Relative**
    - Absolute >> exact position of a byte in the data stream assigned by TCP to bytes
    - Relative >> adjusted to start from zero for easier readability >>

- **Run**
    - `sudo tcpdump -i eth0`
    - `sudo tcpdump -D`
    - `sudo tcpdump -nvXe`

    - `sudo tcpdump -w /tmp/file.pcap`
    - `sudo tcpdump -r /tmp/file.pcap`

- **TCPDump Shell Breakdown**
    1. Timestamp
    2. Protocol
    3. Source & Destination: IP.Port
    4. Flags
    5. Sequence & ACK Numbers
    6. Protocol Options >> *any negotiated TCP values established between the client and server,
         such as window size, selective acknowledgments, window scale factors*
    7. Notes & Header Information

## Practical Challenges
1. Utilizing the output shown in question-1.png, who is the server in this communication? (IP Address)

    **Solved:**
    - I locate the info with TCP connection >>
    - Random Port Numbers for usually Hosts & Known ports for Servers
    - Public IP addresses vs Private IP address
    - Voila, j'ai obtenu le drapeau

2. Were absolute or relative sequence numbers used during the capture? (see question-1.zip to answer)

    **Solved:**
    - I see the relative numbers since they are modified for better understanding
    - Je sais que absolute numbers sont des chiffres original par TCP
    - Voila, c'est fini!

3. If I wish to start a capture without hostname resolution, verbose output, showing contents in ASCII and hex, and grab the first 100 packets;
       what are the switches used? please answer in the order the switches are asked for in the question.

    **Solved:**
    - Without HostName resolution >> -n
    - Verbose >> -v
    - Content in HEX or ASCII >> -X
    - Grab specific number packets >> -c 100
    - All together >> -nvXc 100
    - Voila!

4. Given the capture file at /tmp/capture.pcap, what tcpdump command will enable you to read from the capture and
       show the output contents in Hex and ASCII? (Please use best practices when using switches)

    **Solved:**
    - Je saie que je doit utiliser `sudo`
    - `sudo tcpdump -Xr /tmp/capture.pcap`
    - C'est dans le style de "best practices using switches"


# Fundamentals Lab
- **Practical Challenges:**
1. What TCPDump switch will allow us to pipe the contents of a pcap file out to another function such as 'grep'?

    **Solved:**
    - Il y a un switch appelle `-l` >> avec ca, c'est possible de faire `piping` quand on utilise
        tcpdump en paralel
    - `sudo tcpdump -i eth0 -l | grep -i "dns"`

2.  If we wished to filter out ICMP traffic from our capture, what filter could we use? ( word only, not symbol please.)

    **Solved:**
    - `not ICMP`

# Packet Filtering Avec TCPDump
- **Some Filters:**
    - `host` >>  filter traffic to show anything involving the designated host. **Bi-directional**
        - `sudo tcpdump -i eth0 host 172.16.18.8`

    - `src/dest` >>  designate a source or destination host or port.
        -  `sudo tcpdump -i eth0 src host 172.16.146.2`
        -  `sudo tcpdump -i eth0 tcp src port 80`

    - `net` >>  any traffic sourcing from or destined to the **network designated** >> **uses / notation.**
        - `sudo tcpdump -i eth0 dest net 172.16.146.0/24`

    - `proto` >> filter for a specific protocol, tcp[6], udp[17], or icmp[1]
        - `sudo tcpdump -i eth0 udp`
        - `sudo tcpdump -i eth0 proto 17`


    - `port` >> port is bi-directional >> src et dest aussi
        - `sudo tcpdump -i eth0 tcp port 443`

    - `portrange` >> specify a range of ports. (0-1024)
        - `sudo tcpdump -i eth0 portrange 0-1024`

    - `less / greater` >> used to look for a packet or protocol option of a specific size.
        - `sudo tcpdump -i eth0 less 64` >> to show packets less than 64 bytes
        - `sudo tcpdump -i eth0 greater 500`

    - `and / &&` >> concatenate two different filters together. for example, src host AND port.
        - `sudo tcpdump -i eth0 host 192.168.0.1 and port 23`

    - `or, not` >> either of two conditions, >>  saying anything but not x. For example, not UDP.
        - `sudo tcpdump -r sus.pcap icmp or host 172.16.146.1`
        - `sudo tcpdump not host 192.168.1.10`

- **Tips:**
    - `The -v, -X, and -e switches can help you increase the amount of data captured`
    - **-c, -n, -s, -S, and -q switches can help reduce and modify the amount of data**
    - `-A` switch >> show *only the ASCII* text after the packet line, instead of both ASCII and Hex
    - `-l` >> allows us to send the output directly to another tool such as **grep using a pipe |**
    - `sudo tcpdump -Ar http.cap -l | grep 'mailto:*'`

- **Looking for TCP Protocol Flags:**
    -  **standard TCP header layout:** >> *the first 20 bytes are structured as follows:*
    Offset(Byte)	Field	              Size (bytes)

      0–1	       Source Port	            2
      2–3	       Destination Port	        2
      4–7	       Sequence Number	        4
      8–11	       Acknowledgment Number	4
      12	       Reserved bits	        1
      *13	       Flags (Control Bits)	    1*
      14–15	       Window Size	            2
      16–17	       Checksum	                2
      18–19	       Urgent Pointer	        2

    - **byte 13 is where all TCP flags like SYN, ACK, FIN, RST, etc. are stored**

    - Point: We want to filter TCP SYN Flag where hunting TCP packets where the SYN flag is set.
    - `sudo tcpdump -i eth0 'tcp[13] & 2 != 0'`
        - `tcp[13]` >> refers to byte 13 of the TCP header
        - "Flags" byte, where control flags like SYN, ACK, FIN, etc. are stored as bits.
                Flag	Bit value	Position

                CWR	    128	        Bit 7
                ECE	    64	        Bit 6
                URG	    32	        Bit 5
                ACK	    16	        Bit 4
                PSH	    8	        Bit 3
                RST	    4	        Bit 2
                SYN	    2	        Bit 1
                FIN	    1	        Bit 0
    - Suppose we have this flag byte in binary: `00000010`
        - `the SYN bit (Bit 1) is set`. The value of this is: 2 in decimal >> 0x02 in hex
        - So, to check if that bit is set, we use: `tcp[13] & 2 != 0`
        - You’re checking `bit values`: 1 (FIN), 2 (SYN), 4 (RST), etc. >> These are powers of 2:
        -
        - **Bitwise AND: tcp[13] & 2**
            - so in this case, the 13th byte as whole corresponds to one specific value of these flags
            - my goal is to find whether this flag setting is only equal to the value of "SYN" flag
            - For this, I know in advance that "SYN" has 2 value >> then
            - I do *AND Bitwise* >> calculation with 0s and 1s >> if 0 0 = 0 or 1 1 = 1 >> otherwise 0
            - How math is working: if SYN is set then 13th byte is by default = 2 in binary = `00000010`
            - Okay then I am checking >> `00000010` & `00000010` = `00000010` (of course, the result will be 2)
            - Then I know that this packet is what I look for >> with **SYN flag set, can be in combination with other flags also**
            -
            - Another example >> let's say when `ACK` Flag is set >> then we know `its value is 16`
            - It means that now I should look for values when `13th byte` of TCP Header is equal to 16
            - tcp[13] & 16 >> in binary >> `00010000`& `00010000` = `00010000` 16 >> here we go
            - Now, if I find any packet with different Flag set >> let's say >> tcp[13] = 18
            - tcp[13] = 18 >> I know that it's then **SYN+ACK** (2+16) = 18
            - if we do bitwise AND between tcp[13] & 2 >> it gives me 0 >> says that
            - Hey it's not only SYN set but SYN+ACK >> that's why get the fu*k out of here
            - In binary >> 18= `00010010` & `00000010` == `00000010` >> equal to 2
            - **Actually, here tcp[13] & 2 != 0 >> says that find me all packets which is associated
                with "SYN" flag from 13th byte >> it could be "SYN" flag, also "SYN+ACK" since as
                you see it's 18 >> but when we do "bitwise &" >> I got 2 >> making it positive to
                find"**
            - Now, if we want to look for packets with only SYN Flag set >> then
            - **tcp[13] = 2** >> this will give me only packets with only "SYN" set not any others
            - **tcp[13] = 18** >> only "SYN+ACK" cases


    - Hunting For a SYN Flag
        - `sudo tcpdump -i eth0 'tcp[13] &2 != 0'`
## Practical Challenges
1. What filter will allow me to see traffic coming from or destined to the host with an ip of 10.10.20.1?

    **Solved:**
    - I know that we need something bi-directional >> avec `host`
    - Voila >> c'est fini

# Lab
- **Task #1**
    - Read a capture from a file without filters implemented.
    - `sudo tcpdump -r TCPDump.pcap`

- **Task #2**
    - Identify the type of traffic seen.
    - `sudo tcpdump -nr TCPDump-lab-2.pcap -tttt 'tcp[13] & 18 != 0'`
    - Through this >> I am look for >> **SYN+ACK** connections for full TCP Handshake
    - `-tttt` >> for full timestamp

- **Task #3**
    - Identify HTTP Methods:
    - `sudo tcpdump -A -s 0 port 80 | grep -iE "OPTIONS|GET|PUT|POST|DELETE|HEAD"`
    - `-s 0` >> when capturing HTTP, DNS >> to set >> snaplen >> snapshot length to the maximum is important
        - this puts it to the max >> it captures the **entire packet**

## Practical Challenges
1.  What are the client and server port numbers used in first full TCP three-way handshake? (low number first then high number)

    **Solved:**
    - `sudo tcpdump -nr TCPDump-lab-2.pcap -tttt 'tcp[13] & 18 != 0' `
    - this command is the one which gives the info:
    - also, need to check the flow >> SYN >> SYN+ACK >> ACK
    - the last ACK (from the client) is what you need
    - Voila, c'est fini

2. Based on the traffic seen in the pcap file, who is the DNS server in this network segment? (ip address)

    **Solved:**
    - it went easier since I know that the servers use the known ports while hosts use random ports
    - there are not much traffic after applying the correct filters;
    - `sudo tcpdump -nr TCPDump-lab-2.pcap tcp port 53 or udp port 53`
    - Voila, J'ai obtenu le drapeau


# Wireshark
- **Key Points:**
    - Decryption capabilities for IPsec, ISAKMP, Kerberos, SNMPv3, SSL/TLS, WEP, and WPA/WPA2
    - GUI >> Packet List >> Packet Details >> Packet Bytes
    - **There already defined: capture filters and displayed filters which we can use**

- **TShark**
    - Terminal Version of Wireshark
    **Switches:**
    - `D` >> tos how available interfaces
    - `L` >> Will list the Link-layer mediums you can capture from and then exit out.
    - `i` >> choose the interface
        - `sudo tshark -i eth0 -W /tmp/hello.pcap`

    - `f` >> allows us to apply filters
        - `sudo tshark -i eth0 -f "host 172.16.18.3"`

    - `c` >> Grab a specific number of packets, then quit
    - `a` >> Defines an `autostop` condition. Can be after a duration, specific file size, or after a certain number of packets.
    - `r file.pcap` >> `W file.pcap`
    - `P` >> Will print the packet summary while writing into a file (-W)
    - `x` >> HEX & ASCII

- **TermShark**
    - Text-based User Interface (TUI) application
    - **provides the user with a Wireshark-like interface right in your terminal window.**


# Wireshark Advanced Usage
- **Plugins:**
    - `Analyze` & `Statistics` >> gives a bunch of plugins to run against the capture

- **TCP Streams:**
    - TCP Stream >> one full conversation >> consists of all packets associated with this one conversation between two hosts
    - `Wireshark` >> can collect TCP packets back together to recreate the entire stream in a readable format

    - **Follow TCP Stream**
        - this feature is available for every TCP packets
        - This ability also allows us to `pull data` (`images, files, etc.`) **out of the capture.**
        - **This works for almost any protocol that utilizes TCP as a transport mechanism.**
        - **Alternatively**
        - `tcp.stream eq #` to find and track specific conversations captured in the pcap file.

    - **Extracting Data and Files From a Capture**
        - Select the File radial → Export → , then select the protocol format to extract from.

- **FTP Filters**
    - `ftp`
    - `ftp.request.command`  >> port 21
    - `ftp-data` >> port 20

# Practical Challenges
- **Part #1**
    1. How many conversations can be seen?
        **Solved:**
            - TCP >> 5 conversations
            - IPv4 >> 6 conversations

    2. Can we determine who the clients and servers are?
        **Solved:**
            - 172.16.10.2 >> client >> 41524
            - 172.16.10.20 >> server >> 80 >> FTP Server also
            - 643 packets between them

    3. Do FTP Analysis
        **Solved:**
            - Server >> 172.16.10.20
            - Client >> 172.16.10.2
            - User >> Anonymous

    4. What protocols are being utilized?
        **Solved:**
            - TCP >> HTTP >> ICMP

- **Part #2**
    1. what is the issue?
        **Solved:**
        - suspicious traffic from the host 10.129.43.4

    2. what we are looking for ?
        *I am looking for any files associated with, hosts which communicated with it
        Started: 2021-05-10 22:32:13 until 22:33*

    3. Analyze the NTA
        *I see that following TCP Streams >> commands are visible >> plaintext protocols are used
        random high port numbers >> ephemeral >>*

    4. Find the executed commands:
        *TCP Stream >> shows all the info >> I got the honey*
        - `net user hacker Passw0rd1 /add`
        - `net localgroup administrators hacker /add`
        -
        - **Known port 4444 >> Meterpeter's port is used >> remote shell in-memory**

- **Part #3 >> RDP**
    1. Who is communicating with whom?
        - Two hosts >> Started the conversation >> 10.129.43.27.50675 >> 10.129.43.29.3389

    2. The account used >> DESKTOP-8BSUEVL/bucky >> Found through the ASCII Cookies part
        Also findable through `Packet Details` >> rabbit holing you need to do.

    3. Voila, Avec Wireshark, c'est fini pour ce Module! Bonne Chance!

# Decrypting RDP Connections
- **Scenario:**
    - When run the filter `rdp` >> ce ne peut donner plus d'information car il utilise TLS
    - Need to do: `tcp.port == 3389`
    - To see more >> **Provide the RDP-key to Wireshark so it can decrypt the traffic.**
    -
    - `go to Edit → Preferences → Protocols → TLS` >> then >> `Import An RDP Key`
    - Voila, apres, >> maintenant plus d'information tu peux voir
















