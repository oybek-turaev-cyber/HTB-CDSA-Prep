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

#








































