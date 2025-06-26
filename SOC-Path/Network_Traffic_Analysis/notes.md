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









