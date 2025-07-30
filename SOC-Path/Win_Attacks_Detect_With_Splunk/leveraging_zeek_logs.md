# Detecting RDP Brute Force Attacks
- Goal
    - Brute force for RDP

- How Traffic looks like:
    - Authentication: `3389 >> [ACK]`
    - Certificates Exchange: `Client Hello`

- Detection:
    - Command:
        ```code
            index="rdp_bruteforce" sourcetype="bro:rdp:json"
            | bin _time span=5m
            | stats count values(cookie) by _time, id.orig_h, id.resp_h
            | where count>30
        ```
        - Idea >> with specific index & sourcetype for `RDP connection`
        - Group events in `5-minute buckets` intervals
        - `stats count values(cookie) by _time, id.orig_h, id.resp_h`
            - Here, for the combination of events with `_time, source IP, dest IP` >>
            - `stats` does counting of events `count` , and also:
            - It takes unique cookies for each event
        - At the end, if total count of events > 30 during this `5-min` interval, it shows

- Practical Challenge:
1. Construct a Splunk query targeting the "ssh_bruteforce" index and the "bro:ssh:json" sourcetype.
   The resulting output should display the time bucket, source IP, destination IP, client, and server,
   together with the cumulative count of authentication attempts where the total number of attempts
   surpasses 30 within a 5-minute time window.
   Enter the IP of the client that performed the SSH brute attack as your answer.

   **Solved:**
    - Pour creer ce query, j'ai utilise la logique de le dernier query:
    - Ma SPL commande:
        ```code
            index="ssh_bruteforce" sourcetype="bro:ssh:json"
            | bin _time span=5m
            | stats sum(auth_attempts) as total_attempts by _time, id.orig_h, id.resp_h, client, server
            | where total_attempts > 30
        ```
    - D'abbord, pour trouver combine de fois `auth_attempts` ont passe >> j'ai trouve que
    - Il y a un `field` `auth_attempts` >> par le commande: `table *`
    - Pour faire de la calculation de sum >> j'ai utilise la fonction `sum()`
    - Pendent `5-min fenetre` il compte `auth_attempts` et en fin, il donne `total_attempts`
    - Voila, apres, il me montre seulement quand `total_attempts` est grand que le chiffre 30
    - Voila, ca y est, c'est fini! J'ai trouve le drapeau!

# Detecting Beaconing Malware
- Goal
    - C2 communication with the victim
    - protocols: `HTTP/HTTPS, DNS, ICMP`

- Example:
    - `C2 Framework` >> *Cobalt Strike*

- Detecting Beaconing Malware With Splunk & Zeek Logs:
    - Command:
        ```code
                index="cobaltstrike_beacon" sourcetype="bro:http:json"
                | sort 0 _time
                | streamstats current=f last(_time) as prevtime by src, dest, dest_port
                | eval timedelta = _time - prevtime
                | eventstats avg(timedelta) as avg, count as total by src, dest, dest_port
                | eval upper=avg*1.1
                | eval lower=avg*0.9
                | where timedelta > lower AND timedelta < upper
                | stats count, values(avg) as TimeInterval by src, dest, dest_port, total
                | eval prcnt = (count/total)*100
                | where prcnt > 90 AND total > 10
        ```

    - Here, `sort 0 _time` >> shows unlimited time outputs `0` no restrict
    - `| streamstats current=f last(_time) as prevtime by src, dest, dest_port`
        - For the combination src, dest, dest_port, for each event, it calculates previous time
    - `eval timedelta = _time - prevtime` >> computes time difference between current and previous events' timestamps
    - after this, with `eventstats` >> *Calculates the average time difference (avg) and
    - the total number of events (total) for each combination of src, dest, and dest_port.*
    - Then it creates boundries >> lower >> upper
    - filters events based on these boundries
    - After this filter, it counts the number of elements again for each combination:
        - `src, dest, dest_port, and total.`
    - Then, it calculates what percentage the filtered events out of total events
    - if the filtered events > 90 while total events > 10 >> it shows only those

- Practical Challenge:
1. Use the "cobaltstrike_beacon" index and the "bro:http:json" sourcetype.
   What is the most straightforward Splunk command to pinpoint beaconing from the 10.0.10.20 source to the 192.168.151.181 destination?
   Answer format: One word

   **Solved:**
    - J'ai utilise la logique que je dois chercher le google pour Splunk Commandes pour ca
    - Et apres, j'ai trouve que `t***c****` est une bonne option pour obtenir les meilleurs resultats
    - Ma commande:
        ```code
            index="cobaltstrike_beacon" sourcetype="bro:http:json"
            | search src=10.0.10.20 dest=192.168.151.181
            | t***c**** span=30m count
        ```
    - Cela fonctionne bien! Voila, j'ai obtenu le drapeau!

# Detecting Nmap Port Scanning
- Goal
    - Nmap scans multiple ports
    - Packet Nmap sends to the target is equal to `0` bytes

- Detecting Nmap Port Scanning With Splunk & Zeek Logs:
    - Command:
        ```code
            index="cobaltstrike_beacon" sourcetype="bro:conn:json" orig_bytes=0 dest_ip IN (192.168.0.0/16, 172.16.0.0/12, 10.0.0.0/8)
            | bin span=5m _time
            | stats dc(dest_port) as num_dest_port by _time, src_ip, dest_ip
            | where num_dest_port >= 3
        ```
    - Here, In Zeek Logs: `id.orig_h` >> source IP  >> initiator >> `id.resp_h` >> dest IP >> the target
    - But here, src_ip shows us the attacker IP and dest IP is victim or target
    - The victim IP is in internal range of IPs
    - Window for 5 minutes
    - For each combination group of events by `_time, src_ip, dest_ip` > `dc` counts distinct number of dest_ports accessed for each combination
    - if num_dest_port is greater 3 >> meaning that at least nmap should try 3-4 different ports scan

- Practical Challenge:
1.  Use the "cobaltstrike_beacon" index and the "bro:conn:json" sourcetype. Did the attacker scan port 505? Answer format: Yes, No

    **Solved:**
    - Pour reponder efficacement, j'ai decide que je dois utiliser cette commande:
        ```code
            index="cobaltstrike_beacon" sourcetype="bro:conn:json"
            | where dest_port = "505"
            | bin _time span=5m
            | stats count by _time, src_ip, dest_ip, dest_port
        ```
    - Avec ca, d'abbord, j'ai obtenu tous les evenements avec `505`
    - Apres, j'ai cree la fenetre de 5 minutes
    - Et je compte combien d'evenements pendent la fenetre pour chaque combination: `_time, src_ip, dest_ip, dest_port`
    - Voila, ca y est, c'est fini! J'ai trouve le drapeau!

# Detecting Kerberos Brute Force Attacks
- Goal:
    - To enumerate KDC to know what usernames are valid in the system
    - Attacker sends `AS-REQ` request >> Response from KDC reveals more stuff
    - If the `AS-REP` == `KRB5KDC_ERR_PREAUTH_REQUIRED` >> the username **exists** but needs authentication
    - If the `AS-REP` == `KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN` >> no valid username

- Detecting Kerberos Brute Force Attacks With Splunk & Zeek Logs:
    - Command:
        ```code
            index="kerberos_bruteforce" sourcetype="bro:kerberos:json"
            error_msg!=KDC_ERR_PREAUTH_REQUIRED
            success="false" request_type=AS
            | bin _time span=5m
            | stats count dc(client) as "Unique users" values(error_msg) as "Error messages" by _time, id.orig_h, id.resp_h
            | where count>30
        ```
    - This detection query >> filters out `KDC_ERR_PREAUTH_REQUIRED` based events >> since
    - Because we are only interested in `KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN`
    - It counts the events based on each group combination of `_time, id.orig_h, id.resp_h`
    - dc(client) makes sure that distinct clients

- Practical Challenge:
    1.  Use the "kerberos_bruteforce" index and the "bro:kerberos:json" sourcetype.
        Was the "accrescent/windomain.local" account part of the Kerberos user enumeration attack? Answer format:

    **Solved:**
    - J'ai utilise cette commande:
        ```index
            index="kerberos_bruteforce" sourcetype="bro:kerberos:json"
            error_msg!=KDC_ERR_PREAUTH_REQUIRED
            success="false" request_type=AS
            client=accrescent/windomain.local
            stats count by _time, id.orig_h, id.resp_h
        ```
    - Voila, j'ai ajoute just cette partie >> `client=accrescent/windomain.local`
    - Voici, ca y est, c'est fini!

# Detecting Kerberoasting
- Goal:
    - When attacker compromises one account & its password, it can ask `SPN`
    - It can request `Service Principal Names` from AD >> domain-joined anyone can do that
    - Then, it sends `AS-TGS` request to the Kerberos with found `SPN`
    - When Kerberos replies with `REP-TGS` >> here Kerberos does some key thing:
    - **Kerberos sends `TGS-REP` with the hash of service account password**
    - Attacker then tries to offline brute force the password >> since it usually use `RC4` for **ticket encryption**
    - If the attacker finds the matching hash >> it means that it finds the password of `service account`

- Detecting Kerberoasting With Splunk & Zeek Logs:
    - Command:
        ```code
            index="sharphound" sourcetype="bro:kerberos:json"
            request_type=TGS cipher="rc4-hmac"
            forwardable="true" renewable="true"
            | table _time, id.orig_h, id.resp_h, request_type, cipher, forwardable, renewable, client, service
        ```
        - `cipher="rc4-hmac` >> it's key point here
        - also request type >>
        - `forwardable` >> permet to forwared the `TGS` to other machine or service
        - `renewable` >> Permet au ticket d’être renouvelé sans redemander un mot de passe.
        **Dans Kerberoasting, ces deux attributs sont souvent activés**

- Practical Challenge:
    1. What port does the attacker use for communication during the Kerberoasting attack?

    **Resolu:**
    - J'ai utilise la commande ci-dessus mais j'ai ajoute aussi cette partie: `id.resp_p` et `id.orig_p`
    - Voila, j'ai trouve le port necessaire!

# Detecting Golden Tickets
- Goal:
    - The case is that attacker bypasses the usual Kerberos Authentication
    - Since it has already forged `TGT` using `krbtgt hash` that's why `AS-REQ` and `AS-RESP` are not initiated / seen
    - `In-Pass-The-Ticket` also >> attacker steals a valid `TGT`

- Detection:
    - Pay attention to `TGS-REQ` and `TGS-REP` requests

- Command:
    ```code
        index="golden_ticket_attack" sourcetype="bro:kerberos:json"
        | where client!="-"
        | bin _time span=1m
        | stats values(client), values(request_type) as request_types, dc(request_type) as unique_request_types by _time, id.orig_h, id.resp_h
        | where request_types=="TGS" AND unique_request_types==1
    ```
    - It removes `clients` with empty info

- Practical Challenge:
    1. What port does the attacker use for communication during the Golden Ticket attack?

    **Resolu:**
    - J'ai ajoute just cette partie: `id.orig_p` et `id.resp_p`
    - Voila, c'est fini!

# Detecting Cobalt Strike's PSExec
- Goal:
    - `PSExec` >> *lightweight telnet-replacement that lets you execute processes on other systems.*
    - Cobalt Strike uses this tool
    - `PSExec` works over `445` >> **SMB**

- How it works:
    1. `Service Creation` >> It creates a `new service` on a target system >> this service later `execute the payload`
        - usually comes with random_name
    2. `File Transfer` >> payload transfer occurs to the target system >> often to `ADMIN$` share by `SMB` protocol
    3. `Service Execution` >> newly created service is started >> executed payload (shellcode, executable, or any file type)
    4. `Service Removal` >> after the payload is executed, the service is deleted from the system >> no traces
    5. `Communication` >> if it's a becon connection

- Detecting Cobalt Strike's PSExec With Splunk & Zeek Logs:
    - Command:
        ```code
            index="cobalt_strike_psexec"
            sourcetype="bro:smb_files:json"
            action="SMB::FILE_OPEN"
            name IN ("*.exe", "*.dll", "*.bat")
            path IN ("*\\c$", "*\\ADMIN$")
            size>0
        ```

    - Garde un oeil sur le `SMB` et ses actions: `FILE_OPEN`

- Practical Challenge:
    1. Use the "change_service_config" index and the "bro:dce_rpc:json" sourcetype to create a Splunk search
       that will detect SharpNoPSExec (https://gist.github.com/defensivedepth/ae3f882efa47e20990bc562a8b052984).
       Enter the IP included in the "id.orig_h" field as your answer.

    - J'ai trouve que je doit chercher `svcctl` et
    - Apres, j'ai ajoute `id.orig_h` et `id.resp_h` pour montrer les resultats
    - Et voila, ca y est, c'est fini!

# Detecting Zerologon
- Goal:
    - This attack is related to the vulnerability of `Netlogon Remote Protocol`
    - More it's cryptographically related issue
    - Vulnerability enables that **attacker can impersonate any user even DC, and execute remote procedure calls on their behalf**

- Vulnerability in `Netlogon Remote Protocol`
    - This protocol is used **authenticates users and machines in a Windows domain**
    - When a user  wants to `authenticate against the domain controller`, it uses a protocol called `MS-NRPC`, a `part of Netlogon`
    - They establish secure channel
        - *The client and the server generate a session key, which is computed from the machine account's password.*
        - *This key is then used to derive an initialization vector (IV) for the AES-CFB8 encryption mode*
        - *Ideally, the IV should be unique and random for each encryption operation*
        - **However, due to the flawed implementation in the Netlogon protocol, the IV is set to a fixed value of all zeros.**

    **Surprise:**
    - The attacker can exploit this flaw by authenticate against the DC using of **session key consisting of all zeros**
    - Now, attacker authenticates itself without knowing machine account's password

    - Later attacker uses `NetrServerPasswordSet2` function to **change the computer account's password to any value**
    - **This gives the attacker full control over the DC**

- Detecting Zerologon With Splunk & Zeek Logs:
    - Command:
        ```code
            index="zerologon" endpoint="netlogon" sourcetype="bro:dce_rpc:json"
            | bin _time span=1m
            | where operation == "NetrServerReqChallenge" OR operation == "NetrServerAuthenticate3" OR operation == "NetrServerPasswordSet2"
            | stats count values(operation) as operation_values dc(operation) as unique_operations by _time, id.orig_h, id.resp_h
            | where unique_operations >= 2 AND count>100
        ```

    - Keep an eye on key operations:
        - `NetrServerReqChallenge`, `NetrServerAuthenticate3`, `NetrServerPasswordSet2`
        - This is the flaw of connections when **domain-joined user tries to do Zerologon attack to DC**

- Practical Challenge:
    1. In a Zerologon attack, the primary port of communication for the attacker is port 88. Answer format: True, False.

    **Resolu:**
    - J'ai utilise `id.orig_p` et `id.resp_p` pour voir les port
    - Et j'ai compris que No, l'attaquant n'ai utilise le port `88`

#




















